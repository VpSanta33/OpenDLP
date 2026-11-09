package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/store"
)

/* ---------- 管理员登录来源限制 ---------- */

// parseAllow 校验并规范化允许登录的来源（IP 或 CIDR，最多 20 项）。
func parseAllow(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(v); err == nil {
			v = n.String()
		} else if ip := net.ParseIP(v); ip != nil {
			v = ip.String()
		} else {
			return nil, fmt.Errorf("「%s」不是有效的 IP 或 CIDR 网段", clip(v, 40))
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) > 20 {
		return nil, fmt.Errorf("最多配置 20 个来源")
	}
	return out, nil
}

// ipAllowed 来源 IP 是否在允许列表内；列表为空表示不限制。
func ipAllowed(allow []string, ip string) bool {
	if len(allow) == 0 {
		return true
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, a := range allow {
		if _, n, err := net.ParseCIDR(a); err == nil {
			if n.Contains(addr) {
				return true
			}
		} else if x := net.ParseIP(a); x != nil && x.Equal(addr) {
			return true
		}
	}
	return false
}

/* ---------- 口令有效期 ---------- */

// pwdMaxAge 「系统设置 → 管理员口令有效期」，0 表示不过期。
func pwdMaxAge(d *store.Data) time.Duration {
	days := 90
	if v, ok := d.Settings["pwdMaxAge"].(float64); ok {
		days = int(v)
	}
	return time.Duration(days) * 24 * time.Hour
}

// pwdChangeReason 账号是否必须先修改口令；返回原因（空表示无需修改）。
func pwdChangeReason(d *store.Data, ad *store.Admin, now time.Time) string {
	if ad.MustChange {
		return "首次登录或口令被重置，请先设置新口令"
	}
	if age := pwdMaxAge(d); age > 0 && ad.PwdChanged > 0 && now.Sub(time.UnixMilli(ad.PwdChanged)) > age {
		return fmt.Sprintf("口令已超过 %d 天未修改，请设置新口令", int(age.Hours()/24))
	}
	return ""
}

// 口令待修改时仍允许访问的接口。
var pwdChangeAllowed = map[string]bool{"/api/v1/auth/password": true, "/api/v1/auth/logout": true, "/api/v1/auth/me": true}

/* ---------- 修改口令 ---------- */

// POST /api/v1/auth/password {old, new} —— 修改本人口令；成功后吊销该账号其他会话。
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, a *Actor) {
	if !s.limiter.allow("pwd:" + a.Acc) {
		writeErr(w, http.StatusTooManyRequests, "尝试过于频繁，请 5 分钟后再试")
		return
	}
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Old == "" || req.New == "" {
		writeErr(w, http.StatusBadRequest, "请输入当前口令与新口令")
		return
	}
	if err := auth.CheckComplexity(req.New); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if req.New == req.Old {
		writeErr(w, http.StatusUnprocessableEntity, "新口令不能与当前口令相同")
		return
	}
	if strings.Contains(strings.ToLower(req.New), strings.ToLower(a.Acc)) {
		writeErr(w, http.StatusUnprocessableEntity, "口令不能包含账号名")
		return
	}
	var hash string
	s.St.Read(func(d *store.Data) {
		if ad := d.Admin(a.Acc); ad != nil {
			hash = ad.PwdHash
		}
	})
	if !auth.CheckPassword(hash, req.Old) {
		s.audit(a, "登录", "修改本人口令", false, "当前口令错误")
		writeErr(w, http.StatusUnprocessableEntity, "当前口令错误")
		return
	}
	nh, err := auth.HashPassword(req.New)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "口令处理失败")
		return
	}
	ok := false
	s.St.Write(func(d *store.Data) {
		if ad := d.Admin(a.Acc); ad != nil && ad.PwdHash == hash {
			ad.PwdHash, ad.PwdChanged, ad.MustChange, ok = nh, time.Now().UnixMilli(), false, true
			s.auditIn(d, a, "登录", "修改本人口令", true, "")
		}
	})
	if !ok {
		writeErr(w, http.StatusConflict, "口令已被修改，请重新登录")
		return
	}
	if err := s.St.Save(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败")
		return
	}
	// 吊销该账号全部会话（含其他设备），为当前浏览器签发新会话
	s.Sess.RevokeAccount(a.Acc)
	tok, err := s.Sess.Create(a.Acc, a.Role, a.IP)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	s.setSessionCookie(w, tok, 0)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

/* ---------- 管理员：重置口令、登录来源限制 ---------- */

// POST /api/v1/admins/{acc}/reset-password —— 生成新的随机初始口令，下次登录须修改。
func (s *Server) adminResetPassword(d *store.Data, a *Actor, ad *store.Admin, res map[string]any) error {
	pw := genPassword()
	h, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	ad.PwdHash, ad.MustChange, ad.PwdChanged = h, true, time.Now().UnixMilli()
	ad.Failed, ad.LockedUntil = 0, 0
	res["initialPassword"] = pw
	s.auditIn(d, a, "权限变更", "重置管理员 "+ad.Acc+" 的登录口令", true, "")
	return nil
}

// PATCH /api/v1/admins/{acc} {allow: []} —— 设置允许登录的来源 IP / 网段。
func (s *Server) handleAdminPatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Allow *[]string `json:"allow"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Allow == nil {
		writeErr(w, http.StatusBadRequest, "缺少 allow 字段")
		return
	}
	allow, err := parseAllow(*req.Allow)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	acc := r.PathValue("acc")
	if acc == a.Acc && len(allow) > 0 && !ipAllowed(allow, a.IP) {
		writeErr(w, http.StatusUnprocessableEntity, "当前来源 "+a.IP+" 不在列表中，保存后将无法登录本账号")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		ad := d.Admin(acc)
		if ad == nil {
			return http.StatusNotFound, fail("管理员不存在")
		}
		ad.Allow = allow
		desc := "不限制"
		if len(allow) > 0 {
			desc = strings.Join(allow, "、")
		}
		s.auditIn(d, a, "权限变更", fmt.Sprintf("设置管理员 %s 的登录来源限制：%s", acc, desc), true, "")
		return http.StatusOK, ad.View()
	})
}
