package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/store"
)

const (
	maxFailed   = 5
	lockMinutes = 15
)

type loginReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

// POST /api/v1/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.csrfOK(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	if !s.limiter.allow("login:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "登录尝试过于频繁，请 5 分钟后再试")
		return
	}
	var req loginReq
	if !readJSON(w, r, &req) {
		return
	}
	req.Account = strings.TrimSpace(req.Account)
	if req.Account == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "请输入账号和口令")
		return
	}
	now := time.Now()
	var (
		status    int
		msg       string
		mfa       bool
		name      string
		role      string
		secret    string
		lastIP    string
		lastAt    int64
		success   bool
		pwdChange string
	)
	// 先在读锁外取出哈希以避免在写锁内执行耗时的 PBKDF2
	var hash string
	var found bool
	s.St.Read(func(d *store.Data) {
		if a := d.Admin(req.Account); a != nil {
			found, hash = true, a.PwdHash
		}
	})
	pwOK := found && auth.CheckPassword(hash, req.Password)
	if !found {
		auth.CheckPassword("pbkdf2-sha256$210000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", req.Password) // 平衡耗时，防止账号枚举
	}
	s.St.Write(func(d *store.Data) {
		a := d.Admin(req.Account)
		entry := store.AuditEntry{Op: req.Account, Type: "登录", Detail: "口令登录管理控制台", IP: ip}
		defer func() {
			entry.OK = success
			if a != nil {
				entry.Role = d.RoleName(a.Role)
			}
			_ = s.St.AppendAudit(context.Background(), entry)
		}()
		if a == nil {
			status, msg, entry.Reason = http.StatusUnauthorized, "账号或口令错误", "账号不存在"
			return
		}
		if a.LockedUntil > now.UnixMilli() {
			left := (a.LockedUntil - now.UnixMilli()) / 60000
			status, msg, entry.Reason = http.StatusLocked, fmt.Sprintf("登录失败次数过多，账号已锁定，请 %d 分钟后再试", left+1), "账号锁定中"
			return
		}
		if !pwOK {
			a.Failed++
			entry.Reason = "口令错误"
			if a.Failed >= maxFailed {
				a.Failed, a.LockedUntil = 0, now.Add(lockMinutes*time.Minute).UnixMilli()
				status, msg = http.StatusLocked, fmt.Sprintf("连续 %d 次口令错误，账号已锁定 %d 分钟", maxFailed, lockMinutes)
				return
			}
			status, msg = http.StatusUnauthorized, fmt.Sprintf("账号或口令错误（再失败 %d 次将锁定 %d 分钟）", maxFailed-a.Failed, lockMinutes)
			return
		}
		if a.Status != "active" {
			status, msg, entry.Reason = http.StatusForbidden, "该账号已被禁用，请联系系统管理员", "账号已禁用"
			return
		}
		if !ipAllowed(a.Allow, ip) {
			status, msg, entry.Reason = http.StatusForbidden, "当前网络位置不允许登录该账号，请联系系统管理员", "来源 IP 不在允许范围"
			return
		}
		a.Failed = 0
		success = true
		mfa, name, role, secret, lastIP, lastAt = a.MFA, a.Name, a.Role, a.TOTPSecret, a.IP, a.Last
		pwdChange = pwdChangeReason(d, a, now)
		if mfa {
			entry.Detail = "口令校验通过，等待双因素认证"
		} else {
			a.Last, a.IP = now.UnixMilli(), ip
		}
	})
	if !success {
		writeErr(w, status, msg)
		return
	}
	if mfa {
		ch := s.Sess.NewChallenge(req.Account)
		if s.Cfg.Dev {
			code, _ := auth.TOTPCode(secret, time.Now())
			slog.Warn("[开发模式] 双因素动态码", "account", req.Account, "code", code, "otpauth", auth.OTPAuthURI("OpenDLP", req.Account, secret))
		}
		writeJSON(w, http.StatusOK, map[string]any{"mfa": true, "challenge": ch, "account": req.Account, "name": name})
		return
	}
	tok, err := s.Sess.Create(req.Account, role, ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	s.setSessionCookie(w, tok, 0)
	writeJSON(w, http.StatusOK, map[string]any{"mfa": false, "name": name, "last": lastAt, "lastIp": lastIP, "pwdChange": pwdChange, "warn": "该账号未开启双因素认证，建议尽快启用"})
}

// POST /api/v1/auth/mfa
func (s *Server) handleMFA(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.csrfOK(r) {
		writeErr(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	if !s.limiter.allow("mfa:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
		return
	}
	var req struct{ Challenge, Code string }
	if !readJSON(w, r, &req) {
		return
	}
	ch, ok := s.Sess.UseChallenge(req.Challenge)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "验证已过期，请重新登录")
		return
	}
	var secret string
	s.St.Read(func(d *store.Data) {
		if a := d.Admin(ch.Acc); a != nil {
			secret = a.TOTPSecret
		}
	})
	counter, valid := auth.VerifyTOTP(secret, req.Code, time.Now())
	if valid && !s.Sess.MarkOTPUsed(ch.Acc, counter) {
		valid = false
	}
	var role, name, lastIP, pwdChange string
	var lastAt int64
	s.St.Write(func(d *store.Data) {
		a := d.Admin(ch.Acc)
		e := store.AuditEntry{Op: ch.Acc, Type: "登录", Detail: "登录管理控制台（口令 + TOTP）", IP: ip, OK: valid && a != nil && a.Status == "active"}
		if a != nil {
			e.Role = d.RoleName(a.Role)
		}
		if !e.OK {
			e.Reason = "动态码错误"
		} else if !ipAllowed(a.Allow, ip) {
			e.OK, e.Reason = false, "来源 IP 不在允许范围"
		}
		_ = s.St.AppendAudit(context.Background(), e)
		if e.OK {
			role, name, lastIP, lastAt = a.Role, a.Name, a.IP, a.Last
			pwdChange = pwdChangeReason(d, a, time.Now())
			a.Last, a.IP = time.Now().UnixMilli(), ip
		}
	})
	if role == "" {
		writeErr(w, http.StatusUnauthorized, "动态码错误或已使用，请重新输入")
		return
	}
	s.Sess.DropChallenge(req.Challenge)
	tok, err := s.Sess.Create(ch.Acc, role, ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	s.setSessionCookie(w, tok, 0)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "last": lastAt, "lastIp": lastIP, "pwdChange": pwdChange})
}

// GET /api/v1/auth/config —— 登录页所需的公开配置。
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	setup := false
	s.St.Read(func(d *store.Data) { setup = d.SetupRequired() })
	writeJSON(w, http.StatusOK, map[string]any{"dev": s.Cfg.Dev, "demo": s.Cfg.Demo, "setup": setup, "version": s.Cfg.Version})
}

func (s *Server) meJSON(a *Actor) map[string]any {
	var roleName string
	var mfa bool
	s.St.Read(func(d *store.Data) {
		roleName = d.RoleName(a.Role)
		if ad := d.Admin(a.Acc); ad != nil {
			mfa = ad.MFA
		}
	})
	return map[string]any{"acc": a.Acc, "name": a.Name, "role": a.Role, "roleName": roleName, "baseRole": a.BaseRole, "perms": a.Perms, "mfa": mfa, "ip": a.IP,
		"canSwitch": s.Cfg.Dev && a.BaseRole == "super", "dev": s.Cfg.Dev, "pwdChange": a.PwdChange}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, a *Actor) {
	writeJSON(w, http.StatusOK, s.meJSON(a))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, a *Actor) {
	s.Sess.Delete(a.Token)
	s.audit(a, "登录", "退出管理控制台", true, "")
	s.setSessionCookie(w, "", -1)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/v1/auth/role —— 开发模式下超级管理员切换角色视角（演示三员分立）。
func (s *Server) handleSwitchRole(w http.ResponseWriter, r *http.Request, a *Actor) {
	if !s.Cfg.Dev || a.BaseRole != "super" {
		writeErr(w, http.StatusForbidden, "仅开发模式下的超级管理员可切换角色视角")
		return
	}
	var req struct{ Role string }
	if !readJSON(w, r, &req) {
		return
	}
	exists := false
	s.St.Read(func(d *store.Data) { exists = d.Role(req.Role) != nil })
	if !exists {
		writeErr(w, http.StatusBadRequest, "角色不存在")
		return
	}
	if err := s.Sess.SetRole(a.Token, req.Role); err != nil {
		writeErr(w, http.StatusInternalServerError, "切换失败")
		return
	}
	s.audit(a, "权限变更", "切换角色视角为「"+req.Role+"」（开发模式）", true, "")
	na, _ := s.actor(r)
	writeJSON(w, http.StatusOK, s.meJSON(na))
}
