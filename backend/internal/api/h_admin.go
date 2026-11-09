package api

import (
	"context"
	"encoding/csv"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/llm"
	"opendlp/internal/notify"
	"opendlp/internal/store"
)

/* ---------- 组织与权限 ---------- */

// POST /api/v1/iam/ad-sync —— LDAP 同步连接器尚未内置，返回明确提示（组织数据请使用 CSV 导入）。
func (s *Server) handleADSync(w http.ResponseWriter, r *http.Request, a *Actor) {
	writeErr(w, http.StatusNotImplemented, "当前版本未内置 LDAP 同步连接器，请使用「导入 CSV」维护组织架构")
}

// POST /api/v1/iam/employees/import {csv, mode} —— 导入组织架构。
// CSV 列：工号,姓名,部门,职位,邮箱,状态(在职/离职中/已离职),是否部门负责人(是/否)。mode=replace 时整体替换，否则按工号合并。
func (s *Server) handleEmployeeImport(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ CSV, Mode string }
	if !readJSON(w, r, &req) {
		return
	}
	cr := csv.NewReader(strings.NewReader(strings.TrimPrefix(req.CSV, "\uFEFF")))
	cr.FieldsPerRecord = -1 // 允许省略末尾可选列
	cr.TrimLeadingSpace = true
	recs, err := cr.ReadAll()
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "CSV 格式错误："+err.Error())
		return
	}
	if len(recs) > 0 && strings.Contains(recs[0][0], "工号") {
		recs = recs[1:]
	}
	if len(recs) == 0 || len(recs) > 50000 {
		writeErr(w, http.StatusUnprocessableEntity, "请导入 1-50,000 名员工")
		return
	}
	status := map[string]string{"": "active", "在职": "active", "离职中": "leaving", "已离职": "left", "active": "active", "leaving": "leaving", "left": "left"}
	var list []*store.Employee
	leaders := map[string]string{}
	for n, rec := range recs {
		if len(rec) < 3 {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("第 %d 行至少需要 工号、姓名、部门 三列", n+2))
			return
		}
		col := func(i int) string {
			if i < len(rec) {
				return clip(rec[i], 80)
			}
			return ""
		}
		st, ok := status[col(5)]
		if !ok || col(0) == "" || col(1) == "" || col(2) == "" {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("第 %d 行数据不完整或状态无效", n+2))
			return
		}
		list = append(list, &store.Employee{ID: col(0), Name: col(1), Dept: col(2), Title: col(3), Email: col(4), Status: st, Joined: time.Now().UnixMilli()})
		if col(6) == "是" {
			leaders[col(2)] = col(1)
		}
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		idx := map[string]*store.Employee{}
		if req.Mode != "replace" {
			for _, e := range d.Employees {
				idx[e.ID] = e
			}
		}
		added, updated := 0, 0
		for _, e := range list {
			if old, ok := idx[e.ID]; ok {
				e.Host, e.IP, e.Joined, e.Core = old.Host, old.IP, old.Joined, old.Core
				*old = *e
				updated++
			} else {
				idx[e.ID] = e
				added++
			}
		}
		d.Employees = d.Employees[:0]
		depts := map[string]bool{}
		for _, e := range idx {
			d.Employees = append(d.Employees, e)
			depts[e.Dept] = true
		}
		sort.Slice(d.Employees, func(i, j int) bool { return d.Employees[i].ID < d.Employees[j].ID })
		d.Depts = d.Depts[:0]
		for k := range depts {
			d.Depts = append(d.Depts, k)
		}
		sort.Strings(d.Depts)
		if d.DeptLeaders == nil {
			d.DeptLeaders = map[string]string{}
		}
		for k, v := range leaders {
			d.DeptLeaders[k] = v
		}
		s.auditIn(d, a, "配置变更", fmt.Sprintf("导入组织架构：新增 %d 人、更新 %d 人，共 %d 个部门", added, updated, len(d.Depts)), true, "")
		return http.StatusOK, map[string]any{"added": added, "updated": updated, "employees": d.Employees, "depts": d.Depts, "deptLeaders": d.DeptLeaders}
	})
}

// sodConflict 三员分立冲突检测：同一角色不得同时拥有系统 / 安全配置权限与审计权限。
func sodConflict(m store.Matrix) []string {
	var out []string
	aud := m["audit"].View
	sys, sec := false, false
	for _, k := range []string{"iam", "ops", "settings"} {
		sys = sys || m[k].Cfg
	}
	for _, k := range []string{"incidents", "ueba", "policies", "rules", "discovery", "approvals"} {
		sec = sec || m[k].Cfg
	}
	if sys && aud {
		out = append(out, "系统配置权限与审计权限")
	}
	if sec && aud {
		out = append(out, "安全策略配置权限与审计权限")
	}
	return out
}

func (s *Server) handleRoleCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ Name, From string }
	if !readJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len([]rune(req.Name)) > 20 {
		writeErr(w, http.StatusUnprocessableEntity, "角色名称须为 1-20 个字符")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		for _, ro := range d.Roles {
			if ro.Name == req.Name {
				return http.StatusConflict, fail("角色名称已存在")
			}
		}
		src := d.Perms["analyst"]
		desc := "自定义角色"
		if f := d.Role(req.From); f != nil {
			src, desc = d.Perms[f.Key], "复制自「"+f.Name+"」"
		}
		key := fmt.Sprintf("c%d", store.NextSeq(d, "role"))
		ro := &store.Role{Key: key, Name: req.Name, Desc: desc, Color: "info"}
		d.Roles = append(d.Roles, ro)
		d.Perms[key] = clonePerms(src)
		s.auditIn(d, a, "权限变更", "新建角色「"+ro.Name+"」", true, "")
		return http.StatusCreated, map[string]any{"role": ro, "perms": d.Perms[key]}
	})
}

func (s *Server) handleRolePerms(w http.ResponseWriter, r *http.Request, a *Actor) {
	var m store.Matrix
	if !readJSON(w, r, &m) {
		return
	}
	key := r.PathValue("key")
	clean := store.Matrix{}
	for _, mod := range store.Modules {
		o := m[mod]
		if !o.View { // 无查看权限时其他权限一律无效
			o = store.Ops{}
		}
		clean[mod] = o
	}
	if c := sodConflict(clean); len(c) > 0 {
		writeErr(w, http.StatusUnprocessableEntity, "违反三员分立原则：同一角色不应同时拥有"+strings.Join(c, "、"))
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		ro := d.Role(key)
		if ro == nil {
			return http.StatusNotFound, fail("角色不存在")
		}
		if ro.Builtin {
			return http.StatusForbidden, fail("内置角色权限不可修改")
		}
		d.Perms[key] = clean
		n := 0
		for _, ad := range d.Admins {
			if ad.Role == key {
				n++
			}
		}
		s.auditIn(d, a, "权限变更", fmt.Sprintf("修改角色「%s」的权限矩阵（影响 %d 名管理员）", ro.Name, n), true, "")
		return http.StatusOK, map[string]any{"perms": clean, "affected": n}
	})
}

var accRe = regexp.MustCompile(`^[a-z][a-z0-9_]{2,23}$`)

// genPassword 生成满足复杂度要求的随机初始口令。
func genPassword() string {
	const (
		up  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lo  = "abcdefghijkmnpqrstuvwxyz"
		dig = "23456789"
		sym = "!@#$%^&*-_"
	)
	for {
		tok := auth.RandomToken(12)
		p := string(up[rand.IntN(len(up))]) + tok + string(dig[rand.IntN(len(dig))]) + string(sym[rand.IntN(len(sym))]) + string(lo[rand.IntN(len(lo))])
		if auth.CheckComplexity(p) == nil {
			return p
		}
	}
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Acc, Name, Role, IP string
		Allow               []string
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.IP != "" { // 兼容旧版单个 IP 字段
		req.Allow = append(req.Allow, req.IP)
	}
	allow, aerr := parseAllow(req.Allow)
	if aerr != nil {
		writeErr(w, http.StatusUnprocessableEntity, "登录来源限制："+aerr.Error())
		return
	}
	req.Acc, req.Name = strings.TrimSpace(req.Acc), strings.TrimSpace(req.Name)
	if !accRe.MatchString(req.Acc) {
		writeErr(w, http.StatusUnprocessableEntity, "账号需以小写字母开头，3-24 位小写字母、数字或下划线")
		return
	}
	if req.Name == "" || len([]rune(req.Name)) > 20 {
		writeErr(w, http.StatusUnprocessableEntity, "请填写姓名（不超过 20 字）")
		return
	}
	if req.Role == "super" {
		writeErr(w, http.StatusForbidden, "不允许创建超级管理员")
		return
	}
	pw := genPassword()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成口令失败")
		return
	}
	secret := auth.NewTOTPSecret()
	s.mutate(w, func(d *store.Data) (int, any) {
		if d.Role(req.Role) == nil {
			return http.StatusUnprocessableEntity, fail("角色不存在")
		}
		if d.Admin(req.Acc) != nil {
			return http.StatusConflict, fail("该账号已存在")
		}
		now := time.Now().UnixMilli()
		ad := &store.Admin{Acc: req.Acc, Name: req.Name, Role: req.Role, MFA: true, Allow: allow, Status: "active", Created: now, PwdHash: hash, TOTPSecret: secret, PwdChanged: now, MustChange: true}
		d.Admins = append(d.Admins, ad)
		s.auditIn(d, a, "权限变更", fmt.Sprintf("新建管理员 %s（%s，角色 %s）", ad.Acc, ad.Name, d.RoleName(ad.Role)), true, "")
		// 初始口令与 MFA 绑定信息仅在此响应中返回一次，服务端只保存哈希
		return http.StatusCreated, map[string]any{"admin": ad.View(), "initialPassword": pw, "otpauth": auth.OTPAuthURI("OpenDLP", ad.Acc, secret)}
	})
}

// POST /api/v1/admins/{acc}/unlock|disable|reset-mfa|force-mfa
func (s *Server) handleAdminAction(w http.ResponseWriter, r *http.Request, a *Actor) {
	acc, act := r.PathValue("acc"), r.PathValue("action")
	if acc == a.Acc && (act == "disable" || act == "reset-mfa" || act == "reset-password") {
		writeErr(w, http.StatusForbidden, "不能对当前登录账号执行此操作")
		return
	}
	revoke := false
	s.mutate(w, func(d *store.Data) (int, any) {
		ad := d.Admin(acc)
		if ad == nil {
			return http.StatusNotFound, fail("管理员不存在")
		}
		res := map[string]any{}
		switch act {
		case "unlock":
			ad.Status, ad.Failed, ad.LockedUntil = "active", 0, 0
			s.auditIn(d, a, "权限变更", "解锁管理员账号 "+acc, true, "")
		case "disable":
			if ad.Role == "super" {
				return http.StatusForbidden, fail("不能禁用超级管理员")
			}
			ad.Status, revoke = "disabled", true
			s.auditIn(d, a, "权限变更", "禁用管理员账号 "+acc, true, "")
		case "reset-password":
			if ad.Role == "super" && a.BaseRole != "super" {
				return http.StatusForbidden, fail("只有超级管理员可以重置超级管理员口令")
			}
			if err := s.adminResetPassword(d, a, ad, res); err != nil {
				return http.StatusInternalServerError, fail("生成口令失败")
			}
			revoke = true
		case "reset-mfa", "force-mfa":
			ad.MFA, ad.TOTPSecret, revoke = true, auth.NewTOTPSecret(), true
			res["otpauth"] = auth.OTPAuthURI("OpenDLP", ad.Acc, ad.TOTPSecret)
			s.auditIn(d, a, "权限变更", map[string]string{"reset-mfa": "重置", "force-mfa": "强制启用"}[act]+"管理员 "+acc+" 的双因素认证", true, "")
		default:
			return http.StatusBadRequest, fail("不支持的操作")
		}
		res["admin"] = ad.View()
		return http.StatusOK, res
	})
	if revoke {
		s.Sess.RevokeAccount(acc)
	}
}

/* ---------- 运维与集成 ---------- */

func (s *Server) handleOpsMetrics(w http.ResponseWriter, r *http.Request, a *Actor) {
	snap := s.Metrics.Snapshot()
	dbLat, dbErr := s.St.Ping(r.Context())
	health := []map[string]any{
		{"name": "API 服务", "icon": "globe", "ok": true, "detail": "运行中 · " + s.Cfg.Version},
		{"name": "PostgreSQL 数据库", "icon": "database", "ok": dbErr == nil, "detail": map[bool]string{true: fmt.Sprintf("%d ms", dbLat.Milliseconds()), false: "连接失败"}[dbErr == nil]},
		{"name": "实时推送 (SSE)", "icon": "activity", "ok": true, "detail": fmt.Sprintf("%d 个在线连接", s.Hub.Count())},
		{"name": "异步任务", "icon": "layers", "ok": true, "detail": fmt.Sprintf("%d 个任务", s.Jobs.count())},
	}
	s.respond(w, func(d *store.Data) any {
		online := 0
		for _, n := range d.Nodes {
			if n.Status != "offline" {
				online++
			}
		}
		health = append(health, map[string]any{"name": "检测节点", "icon": "cpu", "ok": len(d.Nodes) == 0 || online == len(d.Nodes),
			"detail": map[bool]string{true: "尚无节点上报", false: fmt.Sprintf("%d / %d 在线", online, len(d.Nodes))}[len(d.Nodes) == 0]})
		agents, latest := map[string]int{}, ""
		for _, e := range d.Endpoints {
			agents[e.Agent]++
			if versionLess(latest, e.Agent) {
				latest = e.Agent
			}
		}
		return map[string]any{"nodes": d.Nodes, "qps": snap["qps"], "lat": snap["lat"], "fleet": d.Fleet(time.Now()), "health": health,
			"agentLatest": latest, "agentLatestCount": agents[latest], "version": s.Cfg.Version, "env": s.envName()}
	})
}

var secretKey = regexp.MustCompile(`(?i)key|secret|token|password|密码|口令|令牌|密钥`)

func maskIntegration(it *store.Integration) store.Integration {
	cp := *it
	cp.Config = map[string]string{}
	for k, v := range it.Config {
		if secretKey.MatchString(k) && v != "" {
			v = "******"
		}
		cp.Config[k] = v
	}
	return cp
}

func findIntegration(d *store.Data, key string) *store.Integration {
	for _, it := range d.Integrations {
		if it.Key == key {
			return it
		}
	}
	return nil
}

// POST /api/v1/integrations/{key}/test —— 生产模式下对配置地址做 TCP 连通性探测。
func (s *Server) handleIntegrationTest(w http.ResponseWriter, r *http.Request, a *Actor) {
	key := r.PathValue("key")
	var it store.Integration
	found := false
	s.St.Read(func(d *store.Data) {
		if x := findIntegration(d, key); x != nil {
			it, found = maskIntegration(x), true
		}
	})
	if !found {
		writeErr(w, http.StatusNotFound, "集成不存在")
		return
	}
	res := map[string]any{"ok": false}
	if _, isAlert := channelToggle[key]; isAlert && it.St != "off" && !s.Cfg.Demo {
		err := s.Alerts.sendNow(r.Context(), key, notify.Message{Title: "OpenDLP 告警通道测试", Severity: "info", Event: "test",
			Text: "这是一条测试消息，收到说明通道配置正确。\n发起人：" + a.Name, Link: "#/ops"})
		res["ok"], res["message"] = err == nil, map[bool]string{true: "测试消息已发送，请在接收端确认", false: ""}[err == nil]
		if err != nil {
			res["message"] = "发送失败：" + err.Error()
		}
		s.audit(a, "配置变更", "测试告警通道「"+it.Name+"」", err == nil, fmt.Sprint(map[bool]any{true: "", false: res["message"]}[err == nil]))
		writeJSON(w, http.StatusOK, res)
		return
	}
	if key == "ai" && it.St != "off" {
		conf, err := s.aiSetup()
		if err == nil {
			t := time.Now()
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			var u llm.Usage
			var msg llm.Message
			msg, u, err = conf.cli.Chat(ctx, []llm.Message{{Role: "user", Content: "这是连通性测试，请只回复：OK"}}, llm.Options{MaxTokens: 20})
			cancel()
			s.recordAI(u, err)
			if err == nil {
				lat := time.Since(t).Milliseconds()
				res["ok"], res["latency"], res["warn"] = true, lat, lat > 15000
				res["message"] = fmt.Sprintf("模型 %s 响应正常，耗时 %dms，回复：%s", conf.cli.Model, lat, clip(strings.TrimSpace(msg.Content), 30))
			}
		}
		if err != nil {
			res["message"] = err.Error()
		}
		s.audit(a, "配置变更", "测试 AI 大模型连接", res["ok"] == true, fmt.Sprint(map[bool]any{true: "", false: res["message"]}[res["ok"] == true]))
		writeJSON(w, http.StatusOK, res)
		return
	}
	switch {
	case it.St == "off":
		res["message"] = "尚未配置，请先完成配置"
	case s.Cfg.Demo:
		lat := 8 + rand.IntN(30)
		if it.St == "warn" {
			lat = 820
		}
		res["ok"], res["latency"], res["warn"] = true, lat, it.St == "warn"
		res["message"] = fmt.Sprintf("连接正常（演示模式模拟），往返 %dms", lat)
	default:
		addr := probeAddr(it.Config)
		if addr == "" {
			res["message"] = "配置中缺少可探测的服务地址"
			break
		}
		t := time.Now()
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			res["message"] = "连接 " + addr + " 失败：" + err.Error()
			break
		}
		c.Close()
		res["ok"], res["latency"], res["message"] = true, time.Since(t).Milliseconds(), "TCP 连接 "+addr+" 成功"
	}
	s.audit(a, "配置变更", "测试集成连接「"+it.Name+"」", res["ok"] == true, fmt.Sprint(map[bool]any{true: "", false: res["message"]}[res["ok"] == true]))
	writeJSON(w, http.StatusOK, res)
}

// probeAddr 从配置中提取 host:port。
func probeAddr(cfg map[string]string) string {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(cfg[k])
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			port := u.Port()
			if port == "" {
				port = map[string]string{"https": "443", "http": "80", "ldaps": "636", "ldap": "389", "icap": "1344"}[u.Scheme]
			}
			if port != "" {
				return net.JoinHostPort(u.Hostname(), port)
			}
		}
		if h, p, err := net.SplitHostPort(v); err == nil {
			return net.JoinHostPort(h, p)
		}
	}
	if h, p := cfg["Syslog 地址"], cfg["端口"]; h != "" && p != "" {
		return net.JoinHostPort(h, p)
	}
	return ""
}

// optionalIntegField 允许留空的集成配置项（例如免认证的内网 SMTP 中继、未启用加签的钉钉机器人）。
var optionalIntegField = map[string]bool{"用户名": true, "口令": true, "加签密钥": true, "加密方式": true, "端口": true, "协议": true, "API Key": true}

func (s *Server) handleIntegrationSave(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Config  map[string]string `json:"config"`
		Enabled bool              `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	key := r.PathValue("key")
	s.mutate(w, func(d *store.Data) (int, any) {
		it := findIntegration(d, key)
		if it == nil {
			return http.StatusNotFound, fail("集成不存在")
		}
		cfg := map[string]string{}
		for k, v := range req.Config {
			v = strings.TrimSpace(v)
			if v == "******" { // 掩码值表示保持原密钥不变
				v = it.Config[k]
			}
			if (v == "" && !optionalIntegField[k]) || len(v) > 500 || len(k) > 40 {
				return http.StatusUnprocessableEntity, fail("配置项「" + k + "」不能为空且不超过 500 字符")
			}
			cfg[k] = v
		}
		if msg := validateIntegration(key, cfg); msg != "" && req.Enabled {
			return http.StatusUnprocessableEntity, fail(msg)
		}
		it.Config = cfg
		if req.Enabled {
			it.St = "ok"
			if strings.HasPrefix(it.Info, "未配置") {
				it.Info = "已于 " + time.Now().In(s.St.Loc).Format("01-02 15:04") + " 完成配置并启用"
			}
		} else {
			it.St, it.Info = "off", "已停用"
		}
		s.auditIn(d, a, "配置变更", "更新集成配置「"+it.Name+"」", true, "")
		return http.StatusOK, maskIntegration(it)
	})
}

// POST /api/v1/ops/diagnose|backup|rules-update|trial
func (s *Server) handleOpsAction(w http.ResponseWriter, r *http.Request, a *Actor) {
	switch r.PathValue("action") {
	case "diagnose":
		var issues []string
		s.St.Read(func(d *store.Data) {
			for _, n := range d.Nodes {
				if n.Status != "online" {
					issues = append(issues, n.Name+" 状态异常")
				}
				if n.CPU > 85 {
					issues = append(issues, fmt.Sprintf("%s CPU %d%%", n.Name, n.CPU))
				}
			}
			for _, it := range d.Integrations {
				if it.St == "warn" {
					issues = append(issues, it.Name+"："+it.Info)
				}
			}
			cut := time.Now().Add(-10 * time.Minute).UnixMilli()
			off := 0
			for _, e := range d.Endpoints {
				if e.LastSeen < cut {
					off++
				}
			}
			if off > 0 {
				issues = append(issues, fmt.Sprintf("%d 台终端超过 10 分钟无心跳", off))
			}
			if len(d.Admins) > 0 {
				for _, a := range d.Admins {
					if a.Status == "active" && !a.MFA {
						issues = append(issues, "管理员 "+a.Acc+" 未启用双因素认证")
					}
				}
			}
		})
		if _, bad, err := s.St.VerifyAudit(r.Context()); err != nil || bad != "" {
			issues = append(issues, "审计日志哈希链校验未通过")
		}
		if _, err := s.St.Ping(r.Context()); err != nil {
			issues = append(issues, "数据库连接异常")
		}
		s.audit(a, "配置变更", fmt.Sprintf("执行系统诊断，发现 %d 项需关注", len(issues)), true, "")
		writeJSON(w, http.StatusOK, map[string]any{"issues": issues})
	case "backup":
		path, size, err := s.backup(r.Context())
		s.audit(a, "配置变更", "备份平台数据", err == nil, fmt.Sprint(err))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "备份失败："+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"file": filepath.Base(path), "size": humanSize(int(size))})
	case "rules-update":
		if !s.Cfg.Demo {
			writeErr(w, http.StatusNotImplemented, "未配置规则库更新源，请通过离线规则包升级")
			return
		}
		cur := ""
		s.St.Read(func(d *store.Data) { cur, _ = d.Settings["ruleVersion"].(string) })
		latest := time.Now().In(s.St.Loc).Format("2006.01.02")
		if cur == latest {
			writeJSON(w, http.StatusOK, map[string]any{"upToDate": true, "version": cur})
			return
		}
		job := s.Jobs.Start(a.Acc, "rules-update", "规则库更新至 "+latest, 4*time.Second, func() (string, string, []byte, error) {
			s.St.Write(func(d *store.Data) {
				d.Settings["ruleVersion"] = latest
				s.auditIn(d, a, "规则变更", "规则库更新至 "+latest+"（签名校验通过，已下发 6 个检测节点）", true, "")
			})
			return "", "", nil, nil
		})
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job, "version": latest})
	case "trial":
		s.audit(a, "配置变更", "申请模块试用授权", true, "")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeErr(w, http.StatusNotFound, "不支持的操作")
	}
}

// backup 导出配置快照（JSON）到 data/backups，保留最近 30 份。
// 事件、审计日志等业务数据存放在 PostgreSQL 中，请使用 pg_dump 进行数据库级备份。
func (s *Server) backup(ctx context.Context) (string, int64, error) {
	if err := s.St.Save(ctx); err != nil {
		return "", 0, err
	}
	var raw []byte
	if err := s.St.DB.QueryRow(ctx, `SELECT data FROM documents WHERE name = 'config'`).Scan(&raw); err != nil {
		return "", 0, err
	}
	dir := filepath.Join(s.Cfg.DataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	path := filepath.Join(dir, "opendlp-config-"+time.Now().Format("20060102-150405")+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", 0, err
	}
	if es, _ := os.ReadDir(dir); len(es) > 30 {
		for _, e := range es[:len(es)-30] {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return path, int64(len(raw)), nil
}

/* ---------- 系统设置 ---------- */

var settingKinds = map[string]string{
	"ocr": "bool", "edm": "bool", "fp": "bool", "ml": "bool", "mail": "bool", "wecom": "bool", "ding": "bool", "siem": "bool", "evi": "bool", "mask": "bool",
	"sens": "num", "freq": "str", "ret1": "str", "ret2": "str", "comp": "list",
	"licenseNo": "str", "licenseSeats": "seats", "licenseExpiry": "date", "consoleUrl": "url", "pwdMaxAge": "days", "aiRedact": "bool", "aiReport": "bool",
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req map[string]any
	if !readJSON(w, r, &req) {
		return
	}
	var changed []string
	for k, v := range req {
		kind, ok := settingKinds[k]
		if !ok {
			writeErr(w, http.StatusBadRequest, "未知配置项："+k)
			return
		}
		valid := false
		switch kind {
		case "bool":
			_, valid = v.(bool)
		case "num":
			f, ok := v.(float64)
			valid = ok && f >= 10 && f <= 100
		case "str":
			sv, ok := v.(string)
			valid = ok && len(sv) <= 40
		case "list":
			l, ok := v.([]any)
			valid = ok && len(l) <= 20
		case "days":
			f, ok := v.(float64)
			valid = ok && (f == 0 || f == 30 || f == 60 || f == 90 || f == 180 || f == 365)
		case "seats":
			f, ok := v.(float64)
			valid = ok && f >= 0 && f <= 10_000_000 && f == float64(int(f))
		case "url":
			sv, ok := v.(string)
			valid = ok && (sv == "" || notify.CheckWebhook(sv) == nil) && len(sv) <= 200
		case "date":
			sv, ok := v.(string)
			_, err := time.Parse("2006-01-02", sv)
			valid = ok && (sv == "" || err == nil)
		}
		if !valid {
			writeErr(w, http.StatusUnprocessableEntity, "配置项取值无效："+k)
			return
		}
	}
	if v, ok := req["ret2"].(string); ok && v != "180 天" && v != "365 天" && v != "3 年" {
		writeErr(w, http.StatusUnprocessableEntity, "审计日志保留期不得少于 180 天（等保 2.0 要求）")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		for k, v := range req {
			if fmt.Sprint(d.Settings[k]) != fmt.Sprint(v) {
				changed = append(changed, k)
				d.Settings[k] = v
			}
		}
		sort.Strings(changed)
		if len(changed) > 0 {
			s.auditIn(d, a, "配置变更", "修改系统设置："+strings.Join(changed, "、"), true, "")
		}
		return http.StatusOK, map[string]any{"settings": d.Settings, "changed": changed}
	})
}

// validateIntegration 告警通道配置的格式校验。
func validateIntegration(key string, c map[string]string) string {
	switch key {
	case "smtp":
		if _, _, err := net.SplitHostPort(c["SMTP 服务器"]); err != nil {
			return "SMTP 服务器须为 host:port，例如 smtp.corp.example:587"
		}
		if !strings.Contains(c["发件人"], "@") || !strings.Contains(c["收件人"], "@") {
			return "请填写有效的发件人与收件人邮箱（多个收件人用逗号分隔）"
		}
		if v := c["加密方式"]; v != "" && v != "starttls" && v != "tls" && v != "none" {
			return "加密方式须为 starttls、tls 或 none"
		}
	case "ai":
		if _, err := llm.New(c["接口地址"], c["模型"], c["API Key"]); err != nil {
			return err.Error()
		}
	case "wecom", "ding":
		if notify.CheckWebhook(c["Webhook 地址"]) != nil {
			return "请填写有效的机器人 Webhook 地址"
		}
	case "siem":
		if c["Syslog 地址"] == "" {
			return "请填写 Syslog 地址"
		}
		if v := strings.ToLower(c["协议"]); v != "" && v != "udp" && v != "tcp" {
			return "协议须为 udp 或 tcp"
		}
	}
	return ""
}
