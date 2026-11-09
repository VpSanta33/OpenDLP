package api

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"opendlp/internal/notify"
	"opendlp/internal/store"
)

/* ---------- 数据发现 ---------- */

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request, a *Actor) {
	var n int
	var id string
	s.St.Write(func(d *store.Data) {
		n = len(d.Repos)
		id = fmt.Sprintf("SCAN-%d", store.NextSeq(d, "scan"))
	})
	if n == 0 && !s.Cfg.Demo {
		writeErr(w, http.StatusConflict, "尚未登记任何数据源，请先添加需要扫描的文件服务器、数据库或对象存储")
		return
	}
	s.audit(a, "终端操作", fmt.Sprintf("下发全量敏感数据发现任务 %s（%d 个数据源）", id, n), true, "")
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "repos": n})
}

// POST /api/v1/discovery/repos {name, type} —— 登记数据源（由扫描节点执行扫描并回传结果）。
func (s *Server) handleRepoAdd(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ Name, Type string }
	if !readJSON(w, r, &req) {
		return
	}
	icons := map[string]string{"文件服务器": "folder", "数据库": "database", "对象存储": "cloud", "协作平台": "layers", "邮件系统": "mail", "终端": "monitor"}
	req.Name = clip(req.Name, 120)
	if req.Name == "" || icons[req.Type] == "" {
		writeErr(w, http.StatusUnprocessableEntity, "请填写数据源地址并选择类型")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		for _, x := range d.Repos {
			if x.Name == req.Name {
				return http.StatusConflict, fail("该数据源已登记")
			}
		}
		rp := &store.Repo{Name: req.Name, Type: req.Type, Icon: icons[req.Type]}
		d.Repos = append(d.Repos, rp)
		s.auditIn(d, a, "配置变更", "登记数据源「"+rp.Name+"」", true, "")
		return http.StatusCreated, rp
	})
}

func (s *Server) handleRepoRescan(w http.ResponseWriter, r *http.Request, a *Actor) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "数据源编号无效")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		if idx < 0 || idx >= len(d.Repos) {
			return http.StatusNotFound, fail("数据源不存在")
		}
		rp := d.Repos[idx]
		s.auditIn(d, a, "终端操作", "对数据源「"+rp.Name+"」下发增量扫描任务", true, "")
		return http.StatusAccepted, rp
	})
}

/* ---------- 终端 ---------- */

func (s *Server) handleEndpointAction(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ Action string }
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		var e *store.Endpoint
		for _, x := range d.Endpoints {
			if x.ID == id {
				e = x
			}
		}
		if e == nil {
			return http.StatusNotFound, fail("终端不存在")
		}
		labels := map[string]string{"push": "推送策略", "scan": "发起远程扫描", "isolate": "隔离终端", "release": "解除隔离"}
		if labels[req.Action] == "" {
			return http.StatusBadRequest, fail("不支持的指令")
		}
		switch req.Action {
		case "isolate":
			e.Isolated = true
		case "release":
			e.Isolated = false
		}
		c := enqueue(d, e.Host, req.Action, a.Name)
		n := 0
		for _, p := range d.Policies {
			if p.Enabled {
				n++
			}
		}
		s.auditIn(d, a, "终端操作", fmt.Sprintf("向 %s 下发指令：%s（%s）", e.Host, labels[req.Action], c.ID), true, "")
		return http.StatusOK, map[string]any{"endpoint": e, "command": c, "policies": n, "offline": e.Status == "offline"}
	})
}

func (s *Server) handleEndpointUpgrade(w http.ResponseWriter, r *http.Request, a *Actor) {
	s.mutate(w, func(d *store.Data) (int, any) {
		latest := ""
		for _, e := range d.Endpoints {
			if versionLess(latest, e.Agent) {
				latest = e.Agent
			}
		}
		n := 0
		for _, e := range d.Endpoints {
			if e.Agent != latest && e.Status != "offline" {
				enqueue(d, e.Host, "upgrade:"+latest, a.Name)
				n++
			}
		}
		s.auditIn(d, a, "终端操作", fmt.Sprintf("下发 Agent 升级指令（目标版本 %s，%d 台终端）", latest, n), true, "")
		return http.StatusOK, map[string]any{"upgraded": n, "version": latest}
	})
}

// versionLess 比较形如 3.2.1 的版本号。
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// POST /api/v1/endpoints/deploy-token —— 返回终端接入参数（上报令牌由运维通过环境变量配置）。
func (s *Server) handleDeployToken(w http.ResponseWriter, r *http.Request, a *Actor) {
	if s.Cfg.AgentToken == "" {
		writeErr(w, http.StatusConflict, "服务端未配置 OPENDLP_AGENT_TOKEN，终端无法接入")
		return
	}
	s.audit(a, "终端操作", "查看终端接入令牌", true, "")
	var server string
	s.St.Read(func(d *store.Data) { server, _ = d.Settings["consoleUrl"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"token": s.Cfg.AgentToken, "server": server, "agentVersion": s.Cfg.Version,
		"heartbeat": "/api/v1/ingest/heartbeat", "detections": "/api/v1/ingest/detections"})
}

/* ---------- 审计 ---------- */

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, a *Actor) {
	qs := r.URL.Query()
	page, per := atoiDef(qs.Get("page"), 1, 1, 100000), atoiDef(qs.Get("per"), 12, 1, 100)
	items, total, err := s.St.ListAudits(r.Context(), store.AuditFilter{Q: qs.Get("q"), Type: qs.Get("type"), Result: qs.Get("result")}, page, per)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "查询审计日志失败")
		return
	}
	if items == nil {
		items = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "per": per})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request, a *Actor) {
	n, bad, err := s.St.VerifyAudit(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "校验失败")
		return
	}
	s.audit(a, "配置变更", fmt.Sprintf("执行审计日志完整性校验（%d 条）", n), bad == "", map[bool]string{true: "", false: "哈希链在 " + bad + " 处断裂"}[bad == ""])
	if bad != "" {
		s.Alerts.Human(notify.Message{Title: "审计日志完整性校验失败", Severity: "critical", Text: "哈希链在 " + bad + " 处断裂，审计日志可能被篡改", Link: "#/audit", Event: "audit"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n, "ok": bad == "", "broken": bad})
}

/* ---------- 报表 ---------- */

var reportTpl = map[string]string{"monthly": "数据安全合规月报", "djbh": "等保 2.0 数据安全自查报告", "pipl": "个人信息保护合规审计报告", "weekly": "事件处置周报", "dept": "部门风险排名", "exec": "高管安全简报"}

type reportReq struct {
	Tpl   string `json:"tpl"`
	Range string `json:"range"` // lm | q | y | c
	From  string `json:"from"`  // 自定义周期 YYYY-MM-DD
	To    string `json:"to"`
	Fmt   string `json:"fmt"`   // HTML | CSV
	Scope string `json:"scope"` // 全集团 或 部门名
}

func reportPeriod(req reportReq, now time.Time, loc *time.Location) (time.Time, time.Time, string, error) {
	now = now.In(loc)
	switch req.Range {
	case "q":
		qm := time.Month((int(now.Month())-1)/3*3 + 1)
		f := time.Date(now.Year(), qm, 1, 0, 0, 0, 0, loc)
		return f, now, fmt.Sprintf("%d Q%d", now.Year(), (int(qm)-1)/3+1), nil
	case "y":
		return time.Date(now.Year(), 1, 1, 0, 0, 0, 0, loc), now, fmt.Sprintf("%d 年度", now.Year()), nil
	case "c":
		f, err1 := time.ParseInLocation("2006-01-02", req.From, loc)
		t, err2 := time.ParseInLocation("2006-01-02", req.To, loc)
		if err1 != nil || err2 != nil || !t.After(f) && !t.Equal(f) || t.Sub(f) > 366*24*time.Hour {
			return f, t, "", fmt.Errorf("自定义周期无效（最长 1 年）")
		}
		return f, t.AddDate(0, 0, 1), req.From + " 至 " + req.To, nil
	default:
		f := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, loc)
		return f, f.AddDate(0, 1, 0), fmt.Sprintf("%d 年 %d 月", f.Year(), int(f.Month())), nil
	}
}

type reportData struct {
	Title, Period, Scope, Generated, By string
	Detections, Blocked, Incidents      int
	Critical, Resolved, ResolvedPct     int
	Channels, Severity                  []KVName
	TopUsers                            []KVName
	Depts                               []KVName
	Checks                              [][3]string
}

type KVName struct {
	Name  string
	Value int
	Pct   int
}

func (s *Server) buildReport(ctx context.Context, title, scope string, from, to time.Time, by string) (reportData, error) {
	loc := s.St.Loc
	rd := reportData{Title: title, Scope: scope, Generated: time.Now().In(loc).Format("2006-01-02 15:04"), By: by}
	if err := s.St.DB.QueryRow(ctx, `SELECT COALESCE(sum(total),0), COALESCE(sum(blocked),0) FROM detections_hourly WHERE h >= $1 AND h < $2`, from, to).Scan(&rd.Detections, &rd.Blocked); err != nil {
		return rd, err
	}
	chs, sev, users, depts := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	chName := map[string]string{}
	mfaAll := true
	s.St.Read(func(d *store.Data) {
		for _, c := range d.Channels {
			chName[c.Key] = c.Name
		}
		for _, a := range d.Admins {
			if a.Status == "active" && !a.MFA {
				mfaAll = false
			}
		}
	})
	err := s.St.EachIncident(ctx, store.IncidentFilter{From: from.UnixMilli(), To: to.UnixMilli()}, func(i *store.Incident) {
		if scope != "全集团" && i.Dept != scope {
			return
		}
		rd.Incidents++
		chs[chName[i.Channel]]++
		sev[sevName[i.Severity]]++
		users[i.User+"（"+i.Dept+"）"]++
		depts[i.Dept]++
		if i.Severity == "critical" {
			rd.Critical++
		}
		if i.Status == "resolved" || i.Status == "fp" {
			rd.Resolved++
		}
	})
	if err != nil {
		return rd, err
	}
	if rd.Incidents > 0 {
		rd.ResolvedPct = rd.Resolved * 100 / rd.Incidents
	}
	top := func(m map[string]int, n int) []KVName {
		var out []KVName
		mx := 1
		for k, v := range m {
			out = append(out, KVName{Name: k, Value: v})
			mx = max(mx, v)
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].Value > out[j].Value || out[i].Value == out[j].Value && out[i].Name < out[j].Name
		})
		if len(out) > n {
			out = out[:n]
		}
		for i := range out {
			out[i].Pct = out[i].Value * 100 / mx
		}
		return out
	}
	rd.Channels, rd.Severity, rd.TopUsers, rd.Depts = top(chs, 6), top(sev, 4), top(users, 10), top(depts, 8)
	ok := func(b bool) string {
		if b {
			return "符合"
		}
		return "部分符合"
	}
	n, bad, err := s.St.VerifyAudit(ctx)
	if err != nil {
		return rd, err
	}
	rd.Checks = [][3]string{
		{"敏感数据识别与分类分级", "数据安全法 第 21 条", ok(rd.Detections > 0)},
		{"数据外发渠道管控（邮件 / USB / 云盘 / IM / Web / 打印）", "GB/T 22239 8.1.4", ok(rd.Detections > 0)},
		{fmt.Sprintf("审计日志防篡改（哈希链校验 %d 条）", n), "网络安全法 第 21 条", ok(bad == "")},
		{"管理员三员分立与双因素认证", "GB/T 22239 8.1.4.2", ok(mfaAll)},
	}
	return rd, nil
}

var reportHTML = template.Must(template.New("r").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;color:#1e293b;max-width:860px;margin:32px auto;padding:0 24px;line-height:1.7}
h1{font-size:24px;margin:0}h2{font-size:16px;border-bottom:2px solid #2563eb;padding-bottom:6px;margin-top:32px}.meta{color:#64748b;font-size:13px}
.kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.kpi div{background:#f3f6fb;border-radius:6px;padding:12px;text-align:center}.kpi b{display:block;font-size:22px;color:#2563eb}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{border:1px solid #e2e8f0;padding:7px 10px;text-align:left}th{background:#f3f6fb}
.bar{height:8px;background:#2563eb;border-radius:4px}.foot{margin-top:40px;color:#94a3b8;font-size:12px;text-align:center}@media print{body{margin:0}}</style></head><body>
<p class="meta">OpenDLP · 数据安全报告 · 密级：内部</p><h1>{{.Title}}</h1>
<p class="meta">统计周期：{{.Period}}　范围：{{.Scope}}　生成时间：{{.Generated}}　生成人：{{.By}}</p>
<h2>一、总体态势</h2><div class="kpi"><div><b>{{.Detections}}</b>外发检测</div><div><b>{{.Blocked}}</b>阻断外发</div><div><b>{{.Incidents}}</b>DLP 事件</div><div><b>{{.ResolvedPct}}%</b>处置完成率</div></div>
<p>统计周期内共检测外发行为 {{.Detections}} 次，阻断 {{.Blocked}} 次，产生 DLP 事件 {{.Incidents}} 起，其中严重事件 {{.Critical}} 起，已处置 {{.Resolved}} 起。</p>
<h2>二、外发渠道分布</h2><table><tr><th>渠道</th><th>事件数</th><th style="width:50%"></th></tr>{{range .Channels}}<tr><td>{{.Name}}</td><td>{{.Value}}</td><td><div class="bar" style="width:{{.Pct}}%"></div></td></tr>{{end}}</table>
<h2>三、风险等级</h2><table><tr><th>级别</th><th>事件数</th></tr>{{range .Severity}}<tr><td>{{.Name}}</td><td>{{.Value}}</td></tr>{{end}}</table>
<h2>四、部门分布</h2><table><tr><th>部门</th><th>事件数</th></tr>{{range .Depts}}<tr><td>{{.Name}}</td><td>{{.Value}}</td></tr>{{end}}</table>
<h2>五、高风险用户 TOP 10</h2><table><tr><th>用户</th><th>事件数</th></tr>{{range .TopUsers}}<tr><td>{{.Name}}</td><td>{{.Value}}</td></tr>{{end}}</table>
<h2>六、合规项检查</h2><table><tr><th>检查项</th><th>依据</th><th>结果</th></tr>{{range .Checks}}<tr><td>{{index . 0}}</td><td>{{index . 1}}</td><td>{{index . 2}}</td></tr>{{end}}</table>
<p class="foot">本报告由 OpenDLP 自动生成，可使用浏览器「打印 → 另存为 PDF」输出。</p></body></html>`))

func renderReport(rd reportData, format string) (string, string, []byte, error) {
	if format == "CSV" {
		rows := [][]string{{"统计周期", rd.Period}, {"范围", rd.Scope}, {"外发检测", strconv.Itoa(rd.Detections)}, {"阻断外发", strconv.Itoa(rd.Blocked)},
			{"DLP 事件", strconv.Itoa(rd.Incidents)}, {"严重事件", strconv.Itoa(rd.Critical)}, {"处置完成率", strconv.Itoa(rd.ResolvedPct) + "%"}}
		for _, x := range rd.Channels {
			rows = append(rows, []string{"渠道：" + x.Name, strconv.Itoa(x.Value)})
		}
		for _, x := range rd.Depts {
			rows = append(rows, []string{"部门：" + x.Name, strconv.Itoa(x.Value)})
		}
		for _, x := range rd.TopUsers {
			rows = append(rows, []string{"用户：" + x.Name, strconv.Itoa(x.Value)})
		}
		return rd.Title + ".csv", "text/csv; charset=utf-8", buildCSV([]string{"指标", "数值"}, rows), nil
	}
	var buf bytes.Buffer
	if err := reportHTML.Execute(&buf, rd); err != nil {
		return "", "", nil, err
	}
	return rd.Title + ".html", "text/html; charset=utf-8", buf.Bytes(), nil
}

// POST /api/v1/reports —— 异步生成报告，完成后写入历史归档。
func (s *Server) handleReportCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req reportReq
	if !readJSON(w, r, &req) {
		return
	}
	s.startReport(w, a, req)
}

func (s *Server) startReport(w http.ResponseWriter, a *Actor, req reportReq) {
	title, ok := reportTpl[req.Tpl]
	if !ok {
		writeErr(w, http.StatusBadRequest, "报表模板不存在")
		return
	}
	if req.Fmt != "CSV" {
		req.Fmt = "HTML"
	}
	if req.Scope == "" {
		req.Scope = "全集团"
	}
	from, to, label, err := reportPeriod(req, time.Now(), s.St.Loc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	valid := req.Scope == "全集团"
	s.St.Read(func(d *store.Data) { valid = valid || validKey(req.Scope, d.Depts) })
	if !valid {
		writeErr(w, http.StatusBadRequest, "数据范围无效")
		return
	}
	name := fmt.Sprintf("%s（%s）", title, label)
	s.audit(a, "数据导出", fmt.Sprintf("生成报告「%s」（%s，%s）", name, req.Scope, req.Fmt), true, "")
	job := s.Jobs.Start(a.Acc, "report", name, 3*time.Second, func() (string, string, []byte, error) {
		rd, err := s.buildReport(context.Background(), name, req.Scope, from, to, a.Name)
		if err != nil {
			return "", "", nil, err
		}
		rd.Period = label
		fn, mime, data, err := renderReport(rd, req.Fmt)
		if err == nil {
			s.St.Write(func(d *store.Data) {
				d.Reports = append([]*store.Report{{ID: fmt.Sprintf("RPT-%d", 1+store.NextSeq(d, "report")), Name: name, Tpl: req.Tpl, Range: req.Range, Fmt: req.Fmt,
					Size: humanSize(len(data)), TS: time.Now().UnixMilli(), By: a.Name, From: from.UnixMilli(), To: to.UnixMilli()}}, d.Reports...)
			})
			s.Hub.Publish(Event{Name: "reports.changed", Module: "reports", Data: map[string]string{"name": name}})
		}
		return fn, mime, data, err
	})
	writeJSON(w, http.StatusAccepted, job)
}

// GET /api/v1/reports/{id}/download —— 按归档参数重新渲染报告。
func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request, a *Actor) {
	id := r.PathValue("id")
	var rp store.Report
	found := false
	s.St.Read(func(d *store.Data) {
		for _, x := range d.Reports {
			if x.ID == id {
				rp, found = *x, true
			}
		}
	})
	if !found {
		writeErr(w, http.StatusNotFound, "报告不存在")
		return
	}
	rd, err := s.buildReport(r.Context(), rp.Name, "全集团", time.UnixMilli(rp.From), time.UnixMilli(rp.To), rp.By)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "报告生成失败")
		return
	}
	rd.Period = time.UnixMilli(rp.From).In(s.St.Loc).Format("2006-01-02") + " 至 " + time.UnixMilli(rp.To).In(s.St.Loc).Format("2006-01-02")
	fn, mime, data, err := renderReport(rd, rp.Fmt)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "报告渲染失败")
		return
	}
	s.audit(a, "数据导出", "下载报告「"+rp.Name+"」", true, "")
	sendFile(w, fn, mime, data)
}

func (s *Server) handleScheduleCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req store.Schedule
	if !readJSON(w, r, &req) {
		return
	}
	title, ok := reportTpl[req.Tpl]
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "报表模板不存在")
		return
	}
	c, err := parseCron(req.Cron)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	to, err := parseRecipients(req.To)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if req.Fmt != "CSV" {
		req.Fmt = "HTML"
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		if len(d.ReportSchedules) >= 50 {
			return http.StatusUnprocessableEntity, fail("定时报表最多 50 个")
		}
		sc := &store.Schedule{ID: fmt.Sprintf("RS-%02d", store.NextSeq(d, "schedule")), Name: title, Tpl: req.Tpl, Cron: strings.TrimSpace(req.Cron), To: to, Fmt: req.Fmt, On: true,
			Next: c.next(time.Now(), s.St.Loc).UnixMilli()}
		d.ReportSchedules = append([]*store.Schedule{sc}, d.ReportSchedules...)
		s.auditIn(d, a, "配置变更", fmt.Sprintf("新建定时报表「%s」（%s）", sc.Name, sc.Cron), true, "")
		return http.StatusCreated, sc
	})
}

func (s *Server) handleSchedulePatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ On *bool }
	if !readJSON(w, r, &req) {
		return
	}
	if req.On == nil {
		writeErr(w, http.StatusBadRequest, "缺少 on 字段")
		return
	}
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		for _, sc := range d.ReportSchedules {
			if sc.ID == id {
				sc.On = *req.On
				if c, err := parseCron(sc.Cron); err == nil && sc.On {
					sc.Next = c.next(time.Now(), s.St.Loc).UnixMilli()
				}
				s.auditIn(d, a, "配置变更", fmt.Sprintf("%s定时报表「%s」", map[bool]string{true: "启用", false: "暂停"}[sc.On], sc.Name), true, "")
				return http.StatusOK, sc
			}
		}
		return http.StatusNotFound, fail("定时报表不存在")
	})
}

// POST /api/v1/report-schedules/{id}/run —— 立即执行一次：生成、归档并发送邮件，同时提供下载。
func (s *Server) handleScheduleRun(w http.ResponseWriter, r *http.Request, a *Actor) {
	id := r.PathValue("id")
	var name string
	s.St.Read(func(d *store.Data) {
		for _, sc := range d.ReportSchedules {
			if sc.ID == id {
				name = sc.Name
			}
		}
	})
	if name == "" {
		writeErr(w, http.StatusNotFound, "定时报表不存在")
		return
	}
	s.audit(a, "数据导出", "立即执行定时报表「"+name+"」", true, "")
	job := s.Jobs.Start(a.Acc, "report", name, time.Second, func() (string, string, []byte, error) {
		fn, mime, data, _, err := s.runSchedule(context.Background(), id, time.Now(), a.Name)
		if data != nil {
			// 邮件发送失败不影响下载，执行结果已记录在定时报表与通知中心
			return fn, mime, data, nil
		}
		return fn, mime, data, err
	})
	writeJSON(w, http.StatusAccepted, job)
}

// DELETE /api/v1/report-schedules/{id}
func (s *Server) handleScheduleDelete(w http.ResponseWriter, r *http.Request, a *Actor) {
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		for i, sc := range d.ReportSchedules {
			if sc.ID == id {
				d.ReportSchedules = append(d.ReportSchedules[:i], d.ReportSchedules[i+1:]...)
				s.auditIn(d, a, "配置变更", "删除定时报表「"+sc.Name+"」", true, "")
				return http.StatusOK, map[string]bool{"ok": true}
			}
		}
		return http.StatusNotFound, fail("定时报表不存在")
	})
}
