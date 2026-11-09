package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/store"
)

// setupState 首次初始化状态：一次性初始化令牌（启动日志中打印）与待完成的 MFA 绑定。
type setupState struct {
	mu      sync.Mutex
	token   string
	pending map[string]*enrollment
}

type enrollment struct {
	acc, name, hash, secret string
	exp                     time.Time
}

func newSetupState() *setupState { return &setupState{pending: map[string]*enrollment{}} }

// SetupToken 返回（必要时生成）首次初始化令牌；preset 非空时使用指定值。
func (s *Server) SetupToken(preset string) string {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	if s.setup.token == "" {
		s.setup.token = preset
		if s.setup.token == "" {
			s.setup.token = auth.RandomToken(12)
		}
	}
	return s.setup.token
}

func (s *Server) setupRequired() bool {
	req := false
	s.St.Read(func(d *store.Data) { req = d.SetupRequired() })
	return req
}

// POST /api/v1/setup/begin {token, account, name, password} —— 校验初始化令牌与口令，返回 MFA 绑定信息。
func (s *Server) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	if !s.limiter.allow("setup:" + s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	if !s.setupRequired() {
		writeErr(w, http.StatusConflict, "系统已完成初始化")
		return
	}
	var req struct{ Token, Account, Name, Password string }
	if !readJSON(w, r, &req) {
		return
	}
	s.setup.mu.Lock()
	tokOK := s.setup.token != "" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.Token)), []byte(s.setup.token)) == 1
	s.setup.mu.Unlock()
	switch {
	case !tokOK:
		writeErr(w, http.StatusUnauthorized, "初始化令牌错误（见服务启动日志）")
		return
	case !accRe.MatchString(strings.TrimSpace(req.Account)):
		writeErr(w, http.StatusUnprocessableEntity, "账号需以小写字母开头，3-24 位小写字母、数字或下划线")
		return
	case strings.TrimSpace(req.Name) == "" || len([]rune(req.Name)) > 20:
		writeErr(w, http.StatusUnprocessableEntity, "请填写姓名（不超过 20 字）")
		return
	}
	if err := auth.CheckComplexity(req.Password); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "口令处理失败")
		return
	}
	en := &enrollment{acc: strings.TrimSpace(req.Account), name: strings.TrimSpace(req.Name), hash: hash, secret: auth.NewTOTPSecret(), exp: time.Now().Add(10 * time.Minute)}
	id := auth.RandomToken(18)
	s.setup.mu.Lock()
	for k, e := range s.setup.pending {
		if time.Now().After(e.exp) {
			delete(s.setup.pending, k)
		}
	}
	s.setup.pending[id] = en
	s.setup.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"enrollment": id, "secret": en.secret, "otpauth": auth.OTPAuthURI("OpenDLP", en.acc, en.secret)})
}

// POST /api/v1/setup/complete {enrollment, code} —— 校验动态码后创建超级管理员并登录。
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	if !s.limiter.allow("setup:" + s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	var req struct{ Enrollment, Code string }
	if !readJSON(w, r, &req) {
		return
	}
	s.setup.mu.Lock()
	en := s.setup.pending[req.Enrollment]
	s.setup.mu.Unlock()
	if en == nil || time.Now().After(en.exp) {
		writeErr(w, http.StatusUnauthorized, "初始化会话已过期，请重新开始")
		return
	}
	if _, ok := auth.VerifyTOTP(en.secret, req.Code, time.Now()); !ok {
		writeErr(w, http.StatusUnauthorized, "动态码错误，请确认身份验证器时间准确后重试")
		return
	}
	ip := s.clientIP(r)
	created := false
	s.St.Write(func(d *store.Data) {
		if !d.SetupRequired() { // 防止并发重复初始化
			return
		}
		now := time.Now().UnixMilli()
		d.Admins = append(d.Admins, &store.Admin{Acc: en.acc, Name: en.name, Role: "super", MFA: true, IP: ip, Status: "active", Created: now, Last: now, PwdHash: en.hash, TOTPSecret: en.secret, PwdChanged: now})
		created = true
	})
	if !created {
		writeErr(w, http.StatusConflict, "系统已完成初始化")
		return
	}
	s.setup.mu.Lock()
	s.setup.pending, s.setup.token = map[string]*enrollment{}, ""
	s.setup.mu.Unlock()
	_ = s.St.Save(r.Context())
	_ = s.St.AppendAudit(context.Background(), store.AuditEntry{Op: en.acc, Role: "超级管理员", Type: "权限变更", Detail: "完成系统初始化，创建超级管理员 " + en.acc + "（已绑定 MFA）", IP: ip, OK: true})
	tok, err := s.Sess.Create(en.acc, "super", ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	s.setSessionCookie(w, tok, 0)
	writeJSON(w, http.StatusOK, map[string]any{"name": en.name})
}
