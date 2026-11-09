// Package api 实现 OpenDLP 管理控制台的 REST API、SSE 实时推送与静态资源服务。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/store"
)

type Config struct {
	Dev          bool   // 开发模式：动态码打印到日志、允许模拟 SSO / 扫码、允许超级管理员切换角色
	Demo         bool   // 演示模式：写入演示数据并运行检测模拟器
	Version      string // 平台版本（构建时注入）
	Static       string // 前端目录，为空则不提供静态资源
	SecureCookie bool   // 通过 HTTPS 提供服务时开启
	AgentToken   string // 终端 / 网关上报检测数据所用令牌，为空则关闭上报接口
	TrustProxy   bool   // 信任 X-Forwarded-For（部署在反向代理之后时开启）
	DataDir      string
}

type Server struct {
	St      *store.Store
	Sess    *auth.Manager
	Hub     *Hub
	Jobs    *Jobs
	Metrics *Metrics
	Cfg     Config
	mux     *http.ServeMux
	limiter *limiter
	setup   *setupState
	Alerts  *Alerts
	aiLimit *limiter     // AI 调用频率限制（每账号）
	aiHTTP  *http.Client // 测试时替换模型服务的 HTTP 客户端
}

// Actor 当前请求的操作者。
type Actor struct {
	Acc      string
	Name     string
	Role     string
	BaseRole string
	Perms    store.Matrix
	Token    string
	IP       string
	// PwdChange 非空表示须先修改口令（值为原因），此时只允许访问修改口令等少数接口
	PwdChange string
}

func New(st *store.Store, cfg Config) *Server {
	s := &Server{
		St:      st,
		Sess:    auth.NewManager(st.Sessions(), 30*time.Minute, 12*time.Hour),
		Hub:     NewHub(),
		Jobs:    NewJobs(),
		Metrics: NewMetrics(20),
		Cfg:     cfg,
		mux:     http.NewServeMux(),
		limiter: newLimiter(10, 5*time.Minute),
		setup:   newSetupState(),
	}
	s.Alerts = newAlerts(s)
	s.aiLimit = newLimiter(30, 10*time.Minute)
	st.OnAudit = s.Alerts.Audit
	s.normalizeSchedules()
	s.routes()
	if cfg.Static != "" {
		s.mux.Handle("GET /", staticHandler(cfg.Static))
	}
	return s
}

// Handler 返回带全部中间件的 http.Handler。
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.logger(s.secureHeaders(s.mux)))
}

/* ---------- 路由注册 ---------- */

type handlerFn func(w http.ResponseWriter, r *http.Request, a *Actor)

// route 注册需要登录的接口；module/op 为空表示仅需登录。
func (s *Server) route(pattern, module, op string, h handlerFn) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.actor(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "登录已失效，请重新登录")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.csrfOK(r) {
			writeErr(w, http.StatusForbidden, "请求来源校验失败")
			return
		}
		if a.PwdChange != "" && !pwdChangeAllowed[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": a.PwdChange, "code": "pwd_change"})
			return
		}
		if module != "" && !allowed(a.Perms, module, op) {
			if r.Method != http.MethodGet {
				s.audit(a, "越权访问", fmt.Sprintf("%s %s", r.Method, r.URL.Path), false, "权限不足")
			}
			writeErr(w, http.StatusForbidden, "当前角色无权执行该操作")
			return
		}
		h(w, r, a)
	})
}

func allowed(m store.Matrix, module, op string) bool {
	o, ok := m[module]
	if !ok {
		return false
	}
	switch op {
	case "", "view":
		return o.View
	case "op":
		return o.Op
	case "cfg":
		return o.Cfg
	case "exp":
		return o.Exp
	}
	return false
}

const cookieName = "odlp_session"

func (s *Server) actor(r *http.Request) (*Actor, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, false
	}
	sess, ok := s.Sess.Get(c.Value)
	if !ok {
		return nil, false
	}
	a := &Actor{Acc: sess.Acc, Role: sess.Role, Token: c.Value, IP: s.clientIP(r)}
	valid := false
	s.St.Read(func(d *store.Data) {
		ad := d.Admin(sess.Acc)
		if ad == nil || ad.Status != "active" || !ipAllowed(ad.Allow, a.IP) {
			return
		}
		valid = true
		a.PwdChange = pwdChangeReason(d, ad, time.Now())
		a.Name, a.BaseRole = ad.Name, ad.Role
		if d.Role(a.Role) == nil { // 角色被删除时回退到账号自身角色
			a.Role = ad.Role
		}
		a.Perms = clonePerms(d.Perms[a.Role])
	})
	if !valid {
		s.Sess.Delete(c.Value)
		return nil, false
	}
	return a, true
}

func clonePerms(m store.Matrix) store.Matrix {
	out := store.Matrix{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// csrfOK 写操作必须携带自定义头（跨站表单无法设置），且 Origin 若存在须与 Host 一致。
func (s *Server) csrfOK(r *http.Request) bool {
	if r.Header.Get("X-OpenDLP-Request") != "1" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		o = strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
		if o != r.Host {
			return false
		}
	}
	return true
}

func (s *Server) clientIP(r *http.Request) string {
	if s.Cfg.TrustProxy {
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) setSessionCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.Cfg.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

// audit 记录一条审计日志（写入数据库哈希链）。
func (s *Server) audit(a *Actor, typ, detail string, ok bool, reason string) {
	var role string
	s.St.Read(func(d *store.Data) { role = d.RoleName(a.Role) })
	_ = s.St.AppendAudit(context.Background(), store.AuditEntry{Op: a.Acc, Role: role, Type: typ, Detail: detail, IP: a.IP, OK: ok, Reason: reason})
}

// auditIn 在已持有配置锁时记录审计日志（审计写入不依赖配置锁，可安全调用）。
func (s *Server) auditIn(d *store.Data, a *Actor, typ, detail string, ok bool, reason string) {
	_ = s.St.AppendAudit(context.Background(), store.AuditEntry{Op: a.Acc, Role: d.RoleName(a.Role), Type: typ, Detail: detail, IP: a.IP, OK: ok, Reason: reason})
}

/* ---------- JSON 工具 ---------- */

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

// respond 在读锁内构造并序列化响应，避免序列化期间数据被并发修改。
func (s *Server) respond(w http.ResponseWriter, build func(d *store.Data) any) {
	var b []byte
	var err error
	s.St.Read(func(d *store.Data) { b, err = json.Marshal(build(d)) })
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "序列化失败")
		return
	}
	writeRaw(w, http.StatusOK, b)
}

// mutate 在写锁内执行修改并序列化返回值；fn 返回 (状态码, 响应体)。
func (s *Server) mutate(w http.ResponseWriter, fn func(d *store.Data) (int, any)) {
	var b []byte
	var code int
	s.St.Write(func(d *store.Data) {
		var v any
		code, v = fn(d)
		b, _ = json.Marshal(v)
	})
	writeRaw(w, code, b)
}

// fail 构造错误响应体，供 mutate 使用。
func fail(msg string) map[string]string { return map[string]string{"error": msg} }

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var errBody = errors.New("请求体格式错误")

// readJSON 解析请求体（限制 1 MB，拒绝未知字段之外的格式错误）。
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, errBody.Error())
		return false
	}
	return true
}

/* ---------- 中间件 ---------- */

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if s.Cfg.SecureCookie {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int)           { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/v1/stream" {
			slog.Info("api", "method", r.Method, "path", r.URL.Path, "status", sw.code, "ms", time.Since(t).Milliseconds())
		}
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				slog.Error("panic", "err", v, "path", r.URL.Path)
				writeErr(w, http.StatusInternalServerError, "服务器内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// staticHandler 提供前端静态资源，禁止目录列表与隐藏文件。
func staticHandler(dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") {
			writeErr(w, http.StatusNotFound, "接口不存在")
			return
		}
		if p != "/" {
			for _, seg := range strings.Split(p, "/") {
				if strings.HasPrefix(seg, ".") {
					http.NotFound(w, r)
					return
				}
			}
			fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p)))
			if err != nil || fi.IsDir() {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		fs.ServeHTTP(w, r)
	})
}

/* ---------- 登录限流 ---------- */

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			h = append(h, t)
		}
	}
	if len(h) >= l.max {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, now)
	return true
}
