package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"opendlp/internal/seed"
	"opendlp/internal/store"
)

func (s *Server) routes() {
	m := s.mux
	// 公开接口
	m.HandleFunc("GET /api/v1/health", s.handleHealth)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /readyz", s.handleHealth)
	m.HandleFunc("GET /api/v1/auth/config", s.handleAuthConfig)
	m.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	m.HandleFunc("POST /api/v1/auth/mfa", s.handleMFA)
	m.HandleFunc("POST /api/v1/auth/sso", s.handleFederated("企业 SSO"))
	m.HandleFunc("POST /api/v1/auth/qr", s.handleFederated("企业微信扫码"))
	m.HandleFunc("POST /api/v1/setup/begin", s.handleSetupBegin)
	m.HandleFunc("POST /api/v1/setup/complete", s.handleSetupComplete)

	// 终端 / 网关 / 审批门户上报（Bearer 令牌）
	m.HandleFunc("POST /api/v1/ingest/detections", s.agent(s.handleIngest))
	m.HandleFunc("POST /api/v1/ingest/heartbeat", s.agent(s.handleHeartbeat))
	m.HandleFunc("POST /api/v1/ingest/nodes", s.agent(s.handleNodeHeartbeat))
	m.HandleFunc("POST /api/v1/ingest/approvals", s.agent(s.handleApprovalSubmit))
	m.HandleFunc("POST /api/v1/ingest/discovery", s.agent(s.handleDiscoveryResult))

	// 终端 Agent（独立凭据）
	m.HandleFunc("POST /api/v1/agent/enroll", s.agent(s.handleAgentEnroll))
	m.HandleFunc("POST /api/v1/agent/heartbeat", s.agentAuth(s.handleAgentHeartbeat))
	m.HandleFunc("GET /api/v1/agent/policy", s.agentAuth(s.handleAgentPolicy))
	m.HandleFunc("POST /api/v1/agent/detections", s.agentAuth(s.handleAgentDetections))
	m.HandleFunc("POST /api/v1/agent/commands/{id}/result", s.agentAuth(s.handleAgentCommandResult))
	m.HandleFunc("POST /api/v1/ingest/approvals/{id}/leader", s.agent(s.handleLeaderDecision))

	// 会话与通用
	s.route("GET /api/v1/auth/me", "", "", s.handleMe)
	s.route("POST /api/v1/auth/logout", "", "", s.handleLogout)
	s.route("POST /api/v1/auth/password", "", "", s.handlePassword)
	s.route("POST /api/v1/auth/role", "", "", s.handleSwitchRole)
	s.route("GET /api/v1/bootstrap", "", "", s.handleBootstrap)
	s.route("GET /api/v1/stream", "", "", s.handleStream)
	s.route("GET /api/v1/dashboard", "dashboard", "view", s.handleDashboard)
	s.route("POST /api/v1/notes/read", "", "", s.handleNotesRead)
	s.route("GET /api/v1/jobs", "", "", s.handleJobs)
	s.route("DELETE /api/v1/jobs", "", "", s.handleJobsClear)
	s.route("GET /api/v1/jobs/{id}", "", "", s.handleJob)
	s.route("GET /api/v1/jobs/{id}/download", "", "", s.handleJobDownload)
	s.route("POST /api/v1/exports", "", "", s.handleExport) // 按导出类型在处理函数内鉴权

	// 事件
	s.route("GET /api/v1/incidents", "incidents", "view", s.handleIncidents)
	s.route("GET /api/v1/incidents/{id}", "incidents", "view", s.handleIncident)
	s.route("POST /api/v1/incidents/{id}/resolve", "incidents", "op", s.handleIncidentResolve)
	s.route("POST /api/v1/incidents/{id}/whitelist", "incidents", "op", s.handleIncidentWhitelist)
	s.route("POST /api/v1/incidents/batch-resolve", "incidents", "op", s.handleIncidentBatch)

	// 外发审批
	s.route("GET /api/v1/approvals", "approvals", "view", func(w http.ResponseWriter, r *http.Request, a *Actor) {
		s.respond(w, func(d *store.Data) any { return d.Approvals })
	})
	s.route("POST /api/v1/approvals/{id}/decision", "approvals", "op", s.handleApprovalDecision)
	s.route("POST /api/v1/approvals/{id}/urge", "approvals", "op", s.handleApprovalUrge)
	s.route("POST /api/v1/approvals/batch-approve", "approvals", "op", s.handleApprovalBatch)
	s.route("PUT /api/v1/approvals/flow", "approvals", "cfg", s.handleApprovalFlow)

	// UEBA
	s.route("POST /api/v1/ueba/watch", "ueba", "op", s.handleWatch)
	s.route("POST /api/v1/ueba/{action}", "ueba", "op", s.handleUebaAction)

	// 策略与规则
	s.route("POST /api/v1/policies", "policies", "cfg", s.handlePolicyCreate)
	s.route("PATCH /api/v1/policies/{id}", "policies", "cfg", s.handlePolicyPatch)
	s.route("POST /api/v1/policies/templates/sync", "policies", "cfg", s.handlePolicyTplSync)
	s.route("POST /api/v1/rules", "rules", "cfg", s.handleRuleCreate)
	s.route("PUT /api/v1/rules/{id}", "rules", "cfg", s.handleRuleUpdate)
	s.route("PATCH /api/v1/rules/{id}", "rules", "cfg", s.handleRulePatch)
	s.route("POST /api/v1/rules/{id}/{action}", "rules", "op", s.handleRuleAction)
	s.route("POST /api/v1/rules/test", "rules", "view", s.handleRuleTest)

	// 数据发现与终端
	s.route("POST /api/v1/discovery/scans", "discovery", "op", s.handleScanStart)
	s.route("POST /api/v1/discovery/repos", "discovery", "op", s.handleRepoAdd)
	s.route("POST /api/v1/discovery/repos/{idx}/rescan", "discovery", "op", s.handleRepoRescan)
	s.route("POST /api/v1/endpoints/{id}/actions", "endpoints", "op", s.handleEndpointAction)
	s.route("POST /api/v1/endpoints/batch-upgrade", "endpoints", "op", s.handleEndpointUpgrade)
	s.route("GET /api/v1/endpoints/{id}/commands", "endpoints", "view", s.handleEndpointCommands)
	s.route("POST /api/v1/endpoints/{id}/revoke", "endpoints", "cfg", s.handleEndpointRevoke)
	s.route("POST /api/v1/endpoints/deploy-token", "endpoints", "cfg", s.handleDeployToken)

	// 报表
	s.route("GET /api/v1/reports", "reports", "view", func(w http.ResponseWriter, r *http.Request, a *Actor) {
		s.respond(w, func(d *store.Data) any { return map[string]any{"history": d.Reports, "schedules": d.ReportSchedules} })
	})
	s.route("POST /api/v1/reports", "reports", "exp", s.handleReportCreate)
	s.route("GET /api/v1/reports/{id}/download", "reports", "exp", s.handleReportDownload)
	s.route("POST /api/v1/report-schedules", "reports", "op", s.handleScheduleCreate)
	s.route("PATCH /api/v1/report-schedules/{id}", "reports", "op", s.handleSchedulePatch)
	s.route("POST /api/v1/report-schedules/{id}/run", "reports", "exp", s.handleScheduleRun)
	s.route("DELETE /api/v1/report-schedules/{id}", "reports", "op", s.handleScheduleDelete)

	// 审计
	s.route("GET /api/v1/audit", "audit", "view", s.handleAudit)
	s.route("GET /api/v1/audit/verify", "audit", "view", s.handleAuditVerify)

	// 组织与权限
	s.route("POST /api/v1/iam/ad-sync", "iam", "op", s.handleADSync)
	s.route("POST /api/v1/iam/employees/import", "iam", "cfg", s.handleEmployeeImport)
	s.route("POST /api/v1/roles", "iam", "cfg", s.handleRoleCreate)
	s.route("PUT /api/v1/roles/{key}/perms", "iam", "cfg", s.handleRolePerms)
	s.route("POST /api/v1/admins", "iam", "cfg", s.handleAdminCreate)
	s.route("POST /api/v1/admins/{acc}/{action}", "iam", "cfg", s.handleAdminAction)
	s.route("PATCH /api/v1/admins/{acc}", "iam", "cfg", s.handleAdminPatch)
	// AI 分析
	s.route("POST /api/v1/ai/incidents/{id}/triage", "incidents", "op", s.handleAITriage)
	s.route("GET /api/v1/ai/incidents/{id}", "incidents", "view", s.handleAITriageGet)
	s.route("POST /api/v1/ai/chat", "", "", s.handleAIChat)

	// 运维与设置
	s.route("GET /api/v1/ops/metrics", "ops", "view", s.handleOpsMetrics)
	s.route("POST /api/v1/ops/{action}", "ops", "cfg", s.handleOpsAction)
	s.route("POST /api/v1/integrations/{key}/test", "ops", "op", s.handleIntegrationTest)
	s.route("PUT /api/v1/integrations/{key}", "ops", "cfg", s.handleIntegrationSave)
	s.route("PUT /api/v1/settings", "settings", "cfg", s.handleSettings)
}

// GET /readyz、/api/v1/health —— 就绪检查（含数据库连通性）。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	lat, err := s.St.Ping(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "database": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UnixMilli(), "dbLatencyMs": lat.Milliseconds(), "version": s.Cfg.Version})
}

func (s *Server) envName() string {
	switch {
	case s.Cfg.Demo:
		return "demo"
	case s.Cfg.Dev:
		return "development"
	}
	return "production"
}

/* ---------- 引导数据 ---------- */

// GET /api/v1/bootstrap —— 登录后一次性下发当前角色可见的数据。
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request, a *Actor) {
	can := func(mods ...string) bool {
		for _, m := range mods {
			if a.Perms[m].View {
				return true
			}
		}
		return false
	}
	me := s.meJSON(a)
	now := time.Now()
	// 近 30 天事件摘要（总览对所有角色可见；最多 600 条，完整数据通过分页接口查询）
	recent, err := s.St.RecentIncidents(r.Context(), now.Add(-30*24*time.Hour).UnixMilli(), 600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取事件失败")
		return
	}
	s.respond(w, func(d *store.Data) any {
		online := 0
		for _, n := range d.Nodes {
			if n.Status != "offline" {
				online++
			}
		}
		out := map[string]any{"now": now.UnixMilli(), "me": me, "level": seed.Level, "incidents": recent,
			"system": map[string]any{"env": s.envName(), "version": s.Cfg.Version, "ruleVersion": d.Settings["ruleVersion"], "nodes": len(d.Nodes), "nodesOnline": online}}
		out["channels"], out["dataTypes"], out["depts"], out["roles"] = d.Channels, d.DataTypes, d.Depts, d.Roles
		out["auditTypes"] = []string{"策略变更", "事件处置", "登录", "终端操作", "数据导出", "配置变更", "白名单", "外发审批", "规则变更", "权限变更", "越权访问"}
		out["fleet"] = d.Fleet(now)
		notes := d.Notes
		if len(notes) > 30 {
			notes = notes[:30]
		}
		out["notes"] = notes
		if can("ueba", "iam", "approvals") {
			out["employees"], out["deptLeaders"] = d.Employees, d.DeptLeaders
		}
		if can("ueba") {
			out["watchlist"] = d.Watchlist
		}
		if can("policies", "endpoints") {
			out["policies"] = d.Policies
		}
		if can("endpoints") {
			out["endpoints"] = d.Endpoints
		}
		if can("discovery") {
			out["repos"] = d.Repos
		}
		if can("approvals") {
			out["approvals"] = d.Approvals
			aps := []map[string]string{}
			for _, x := range d.Admins {
				if x.Status == "active" && x.Acc != a.Acc && d.Perms[x.Role]["approvals"].Op {
					aps = append(aps, map[string]string{"acc": x.Acc, "name": x.Name})
				}
			}
			out["approvers"] = aps
		}
		if can("rules") {
			out["rules"] = d.Rules
		}
		if can("iam") {
			adm := make([]store.AdminView, 0, len(d.Admins))
			for _, x := range d.Admins {
				v := x.View()
				if x.LockedUntil > now.UnixMilli() {
					v.Status = "locked"
				}
				adm = append(adm, v)
			}
			out["admins"], out["perms"] = adm, d.Perms
		}
		if can("ops") {
			out["nodes"] = d.Nodes
			ints := make([]store.Integration, 0, len(d.Integrations))
			for _, it := range d.Integrations {
				ints = append(ints, maskIntegration(it))
			}
			out["integrations"] = ints
		}
		if can("reports") {
			out["reportSchedules"], out["reportHistory"] = d.ReportSchedules, d.Reports
		}
		if can("settings", "approvals", "ops") {
			out["settings"] = d.Settings
		}
		return out
	})
}

// GET /api/v1/dashboard?range=today|7d|30d
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, a *Actor) {
	db, err := s.St.BuildDashboard(r.Context(), r.URL.Query().Get("range"), time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "统计失败："+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, db)
}

// POST /api/v1/notes/read {id} 或 {all:true}
func (s *Server) handleNotesRead(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		ID  string `json:"id"`
		All bool   `json:"all"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.St.Write(func(d *store.Data) {
		for _, n := range d.Notes {
			if req.All || n.ID == req.ID {
				n.Unread = false
			}
		}
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// addNote 生成一条通知并推送（须在写锁外调用）。
func (s *Server) addNote(typ, title, text, href string) {
	var n store.Note
	s.St.Write(func(d *store.Data) {
		x := &store.Note{ID: "N" + strconv.Itoa(store.NextSeq(d, "note")), Type: typ, Title: title, Text: text, TS: time.Now().UnixMilli(), Unread: true, Href: href}
		d.Notes = append([]*store.Note{x}, d.Notes...)
		if len(d.Notes) > 100 {
			d.Notes = d.Notes[:100]
		}
		n = *x
	})
	s.Hub.Publish(Event{Name: "note", Data: n})
}

func validUser(u string) bool { u = strings.TrimSpace(u); return u != "" && len([]rune(u)) <= 40 }

// POST /api/v1/ueba/watch {user, on}
func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		User string `json:"user"`
		On   bool   `json:"on"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validUser(req.User) {
		writeErr(w, http.StatusBadRequest, "用户无效")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		list := []string{}
		for _, u := range d.Watchlist {
			if u != req.User {
				list = append(list, u)
			}
		}
		if req.On {
			list = append(list, req.User)
		}
		d.Watchlist = list
		s.auditIn(d, a, "策略变更", map[bool]string{true: "将 " + req.User + " 加入观察名单", false: "将 " + req.User + " 移出观察名单"}[req.On], true, "")
		return http.StatusOK, map[string]any{"watchlist": list}
	})
}

// POST /api/v1/ueba/strict|case {user}
func (s *Server) handleUebaAction(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		User string `json:"user"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validUser(req.User) {
		writeErr(w, http.StatusBadRequest, "用户无效")
		return
	}
	switch r.PathValue("action") {
	case "strict":
		var hosts []string
		s.St.Write(func(d *store.Data) {
			for _, e := range d.Endpoints {
				if e.User == req.User {
					hosts = append(hosts, e.Host)
					e.Strict = true                    // 策略包随之变化，审计 / 加密动作升级为阻断
					enqueue(d, e.Host, "push", a.Name) // 通知 Agent 立即同步策略
				}
			}
		})
		s.audit(a, "策略变更", "对 "+req.User+" 启用严格管控（外发审批 / 禁用 USB 写入 / 截屏水印），下发终端："+strings.Join(hosts, "、"), true, "")
		writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
	case "case":
		linked, err := s.St.CountIncidents(r.Context(), store.IncidentFilter{User: req.User})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "统计失败")
			return
		}
		var id string
		s.St.Write(func(d *store.Data) { id = "CASE-" + strconv.Itoa(2000+store.NextSeq(d, "case")) })
		s.audit(a, "事件处置", "对 "+req.User+" 发起调查工单 "+id+"（关联 "+strconv.Itoa(linked)+" 起事件）", true, "")
		writeJSON(w, http.StatusCreated, map[string]any{"case": id, "linked": linked})
	default:
		writeErr(w, http.StatusBadRequest, "不支持的操作")
	}
}
