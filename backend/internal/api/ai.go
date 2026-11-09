package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"opendlp/internal/llm"
	"opendlp/internal/store"
)

/*
AI 分析（对接 OpenAI 兼容接口：DeepSeek、通义千问、智谱、Kimi 或内网 vLLM / Ollama）

	POST /api/v1/ai/incidents/{id}/triage   AI 研判单个事件（结合用户历史、员工状态、审批记录）
	GET  /api/v1/ai/incidents/{id}          读取已缓存的研判结果
	POST /api/v1/ai/chat                    AI 安全助手（只读工具查询，按当前角色权限收敛）
	定时 / 手动报表在开启「AI 管理摘要」时自动附带摘要

数据保护：默认开启脱敏——姓名、主机名、IP、邮箱替换为代号，身份证号与手机号遮盖，结果在本地还原；
任何情况下都不发送文件内容与命中原文。所有调用写入审计日志。
*/

var errAIOff = errors.New("尚未配置 AI 大模型，请在「运维与集成 → AI 大模型」中填写接口地址与模型")

type aiConf struct {
	cli    *llm.Client
	redact bool
	report bool
}

// aiSetup 读取 AI 配置（集成「ai」+ 系统设置开关）。
func (s *Server) aiSetup() (aiConf, error) {
	var c aiConf
	var base, model, key string
	on := false
	s.St.Read(func(d *store.Data) {
		if it := findIntegration(d, "ai"); it != nil && it.St != "off" && it.Config != nil {
			on, base, model, key = true, it.Config["接口地址"], it.Config["模型"], it.Config["API Key"]
		}
		c.redact = boolSetting(d, "aiRedact", true)
		c.report = boolSetting(d, "aiReport", true)
	})
	if !on {
		return c, errAIOff
	}
	cli, err := llm.New(base, model, key)
	if err != nil {
		return c, err
	}
	if s.aiHTTP != nil {
		cli.HTTP = s.aiHTTP
	}
	c.cli = cli
	return c, nil
}

func boolSetting(d *store.Data, k string, def bool) bool {
	if v, ok := d.Settings[k].(bool); ok {
		return v
	}
	return def
}

// recordAI 记录调用次数、失败与 token 用量（显示在集成卡片上）。
func (s *Server) recordAI(u llm.Usage, err error) {
	s.St.Write(func(d *store.Data) {
		it := findIntegration(d, "ai")
		if it == nil {
			return
		}
		if it.Delivery == nil {
			it.Delivery = &store.Delivery{}
		}
		it.Delivery.LastAt = time.Now().UnixMilli()
		it.Delivery.Tokens += u.Total
		if err != nil {
			it.Delivery.Fail++
			it.Delivery.LastErr = clip(err.Error(), 200)
		} else {
			it.Delivery.OK++
			it.Delivery.LastErr = ""
		}
	})
}

// knownEntities 登记全部员工姓名与终端主机名，自由文本（例如用户提问、历史回复）中出现时自动脱敏。
func (s *Server) knownEntities(r *llm.Redactor) {
	if !r.Enabled {
		return
	}
	s.St.Read(func(d *store.Data) {
		for _, e := range d.Employees {
			r.Known("user", e.Name)
		}
		for _, e := range d.Endpoints {
			r.Known("host", e.Host)
			r.Known("user", e.User)
		}
		for _, a := range d.Admins {
			r.Known("user", a.Name)
		}
	})
}

var empStatus = map[string]string{"active": "在职", "leaving": "离职流程中", "left": "已离职"}

/* ---------- AI 研判 ---------- */

const triagePrompt = `你是企业数据防泄漏（DLP）安全运营中心的资深分析师。根据给出的单个 DLP 事件及其上下文（该用户近 90 天的历史事件、员工状态、外发审批记录、部门基线），判断这次外发是真实的数据泄露风险、正常业务行为还是误报，并给出处置建议。

要求：
- 只依据给出的数据推理，不要编造未提供的事实；数据不足时降低置信度并说明还需核实什么。
- 方括号中的代号（例如 [用户A]、[终端B]）是脱敏后的标识，引用时保持原样。
- 重点关注：离职流程中的员工、非工作时间外发、短期内频率突增、多渠道 / 多数据类型集中外发、阻断后反复尝试、个人网盘与外部邮箱等去向。
- 处置建议要具体可执行（例如“联系部门负责人确认外发对象”“对该终端发起远程扫描”）。

只输出一个 JSON 对象，不要输出其他内容，字段：
{"risk":"high|medium|low","score":0到100的整数,"summary":"一句话结论（不超过60字）","reasons":["判断依据，2-5条"],"recommendations":["处置建议，2-4条"],"disposition":"escalate（升级调查）|monitor（持续观察）|resolve（确认后关闭）|fp（误报）","confidence":"high|medium|low"}`

// POST /api/v1/ai/incidents/{id}/triage
func (s *Server) handleAITriage(w http.ResponseWriter, r *http.Request, a *Actor) {
	if !s.aiLimit.allow("ai:" + a.Acc) {
		writeErr(w, http.StatusTooManyRequests, "AI 分析调用过于频繁，请稍后再试")
		return
	}
	conf, err := s.aiSetup()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	id := r.PathValue("id")
	inc, err := s.St.GetIncident(r.Context(), id)
	if err != nil || inc == nil {
		writeErr(w, http.StatusNotFound, "事件不存在")
		return
	}
	rd := llm.NewRedactor(conf.redact)
	s.knownEntities(rd)
	ctxData, err := s.triageContext(r.Context(), inc, rd)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取事件上下文失败")
		return
	}
	raw, _ := json.MarshalIndent(ctxData, "", " ")
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	prompt := []llm.Message{{Role: "system", Content: triagePrompt}, {Role: "user", Content: "请研判以下 DLP 事件：\n" + string(raw)}}
	msg, usage, err := conf.cli.Chat(ctx, prompt, llm.Options{JSON: true, MaxTokens: 1500})
	var le *llm.Error
	if errors.As(err, &le) && le.Status == http.StatusBadRequest { // 部分本地推理服务不支持 response_format，去掉后重试
		msg, usage, err = conf.cli.Chat(ctx, prompt, llm.Options{MaxTokens: 1500})
	}
	s.recordAI(usage, err)
	if err != nil {
		s.audit(a, "AI 分析", "AI 研判事件 "+id, false, clip(err.Error(), 100))
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	var res store.AITriage
	if err := llm.ExtractJSON(msg.Content, &res); err != nil || res.Summary == "" {
		s.audit(a, "AI 分析", "AI 研判事件 "+id, false, "模型输出格式无效")
		writeErr(w, http.StatusBadGateway, "模型输出格式无效，请重试或更换模型")
		return
	}
	res.Risk = pick(strings.ToLower(res.Risk), []string{"high", "medium", "low"}, "medium")
	res.Disposition = pick(strings.ToLower(res.Disposition), []string{"escalate", "monitor", "resolve", "fp"}, "monitor")
	res.Confidence = pick(strings.ToLower(res.Confidence), []string{"high", "medium", "low"}, "medium")
	res.Score = max(0, min(100, res.Score))
	res.Summary = clip(rd.Restore(res.Summary), 200)
	res.Reasons = restoreList(rd, res.Reasons, 6)
	res.Steps = restoreList(rd, res.Steps, 6)
	res.Model, res.Redacted, res.By, res.TS = conf.cli.Model, conf.redact, a.Name, time.Now().UnixMilli()
	s.St.Write(func(d *store.Data) {
		if d.AITriage == nil {
			d.AITriage = map[string]*store.AITriage{}
		}
		d.AITriage[id] = &res
		if len(d.AITriage) > 2000 { // 淘汰最早的结果
			var oldest string
			for k, v := range d.AITriage {
				if oldest == "" || v.TS < d.AITriage[oldest].TS {
					oldest = k
				}
			}
			delete(d.AITriage, oldest)
		}
	})
	s.audit(a, "AI 分析", fmt.Sprintf("AI 研判事件 %s：%s 风险（%d 分）", id, map[string]string{"high": "高", "medium": "中", "low": "低"}[res.Risk], res.Score), true, "")
	writeJSON(w, http.StatusOK, res)
}

// GET /api/v1/ai/incidents/{id}
func (s *Server) handleAITriageGet(w http.ResponseWriter, r *http.Request, a *Actor) {
	s.respond(w, func(d *store.Data) any {
		if t := d.AITriage[r.PathValue("id")]; t != nil {
			return t
		}
		return map[string]any{}
	})
}

func pick(v string, allowed []string, def string) string {
	for _, x := range allowed {
		if v == x {
			return v
		}
	}
	return def
}

func restoreList(rd *llm.Redactor, in []string, n int) []string {
	out := []string{}
	for _, x := range in {
		if x = strings.TrimSpace(x); x != "" && len(out) < n {
			out = append(out, clip(rd.Restore(x), 300))
		}
	}
	return out
}

func hourOf(ms int64, loc *time.Location) int { return time.UnixMilli(ms).In(loc).Hour() }

// triageContext 组装研判上下文（已脱敏）。
func (s *Server) triageContext(ctx context.Context, inc *store.Incident, rd *llm.Redactor) (map[string]any, error) {
	loc := s.St.Loc
	now := time.Now()
	hist, _, err := s.St.ListIncidents(ctx, store.IncidentFilter{User: inc.User, From: now.AddDate(0, 0, -90).UnixMilli()}, 1, 200)
	if err != nil {
		return nil, err
	}
	var chName, dtName func(string) string
	out := map[string]any{}
	s.St.Read(func(d *store.Data) {
		chName, dtName = d.ChannelName, d.DataTypeName
		ev := map[string]any{
			"事件编号": inc.ID, "时间": fmtTS(inc.TS, loc), "是否非工作时间": hourOf(inc.TS, loc) < 8 || hourOf(inc.TS, loc) >= 20 || time.UnixMilli(inc.TS).In(loc).Weekday()%6 == 0,
			"用户": rd.Mask("user", inc.User), "部门": inc.Dept, "终端": rd.Mask("host", inc.Host), "IP": rd.Mask("ip", inc.IP),
			"外发渠道": d.ChannelName(inc.Channel), "目的地": rd.Text(inc.Dest), "数据类型": d.DataTypeName(inc.DataType), "文件名": rd.Text(inc.File),
			"大小": inc.Size, "命中敏感内容数": inc.Matches, "命中策略": inc.Policy, "处置动作": actName[inc.Action], "级别": sevName[inc.Severity], "状态": stName[inc.Status],
		}
		out["事件"] = ev
		emp := map[string]any{"在员工名册中": false}
		if e := d.Employee(inc.User); e != nil {
			emp = map[string]any{"在员工名册中": true, "职位": e.Title, "部门": e.Dept, "状态": empStatus[e.Status], "入职时间": fmtTS(e.Joined, loc)}
		}
		out["员工信息"] = emp
		apr := map[string]int{}
		var recent []map[string]any
		for _, x := range d.Approvals {
			if x.User == inc.User && x.TS > now.AddDate(0, 0, -90).UnixMilli() {
				apr[x.Status]++
				if len(recent) < 5 {
					recent = append(recent, map[string]any{"时间": fmtTS(x.TS, loc), "文件": rd.Text(x.File), "渠道": d.ChannelName(x.Channel), "接收方": rd.Text(x.To), "理由": rd.Text(clip(x.Reason, 100)), "状态": x.Status})
				}
			}
		}
		out["近90天外发审批"] = map[string]any{"按状态统计": apr, "最近": recent}
	})
	byCh, bySev, byDt := map[string]int{}, map[string]int{}, map[string]int{}
	afterHours, blocked, last7 := 0, 0, 0
	var recent []map[string]any
	for _, h := range hist {
		byCh[chName(h.Channel)]++
		bySev[sevName[h.Severity]]++
		byDt[dtName(h.DataType)]++
		if hr := hourOf(h.TS, loc); hr < 8 || hr >= 20 {
			afterHours++
		}
		if h.Action == "block" {
			blocked++
		}
		if h.TS > now.AddDate(0, 0, -7).UnixMilli() {
			last7++
		}
		if h.ID != inc.ID && len(recent) < 12 {
			recent = append(recent, map[string]any{"时间": fmtTS(h.TS, loc), "渠道": chName(h.Channel), "数据类型": dtName(h.DataType), "文件名": rd.Text(h.File),
				"命中数": h.Matches, "处置": actName[h.Action], "状态": stName[h.Status]})
		}
	}
	out["该用户近90天事件"] = map[string]any{"总数": len(hist), "近7天": last7, "非工作时间": afterHours, "被阻断": blocked,
		"按渠道": byCh, "按级别": bySev, "按数据类型": byDt, "最近事件": recent}
	if inc.Dept != "" {
		users, total, err := s.St.IncidentGroup(ctx, store.IncidentFilter{Dept: inc.Dept, From: now.AddDate(0, 0, -30).UnixMilli()}, "user", 1000)
		if err == nil && len(users) > 0 {
			out["部门基线（近30天）"] = map[string]any{"部门事件总数": total, "涉及人数": len(users), "人均事件数": fmt.Sprintf("%.1f", float64(total)/float64(len(users)))}
		}
	}
	return out, nil
}

/* ---------- 报表 AI 管理摘要 ---------- */

const reportPrompt = `你是企业数据安全负责人的助理。根据给出的数据防泄漏统计报表，为管理层撰写一段中文管理摘要：
1. 先用一两句话概括本期整体态势（与数据直接相关的数字要准确引用）；
2. 指出 2-3 个最值得关注的风险点（渠道、部门、数据类型或人员集中度）；
3. 给出 2-3 条可执行的改进建议。
要求：不超过 350 字，分 3 段纯文本，不使用 Markdown 标题、列表符号或表格；不要编造报表中没有的数据；方括号中的代号保持原样。`

// aiReportSummary 生成报表管理摘要；未配置或关闭时返回空字符串。
func (s *Server) aiReportSummary(ctx context.Context, rd reportData) string {
	conf, err := s.aiSetup()
	if err != nil || !conf.report {
		return ""
	}
	red := llm.NewRedactor(conf.redact)
	top := []map[string]any{}
	for _, u := range rd.TopUsers {
		top = append(top, map[string]any{"用户": red.Mask("user", u.Name), "事件数": u.Value})
	}
	data := map[string]any{"报表": rd.Title, "统计周期": rd.Period, "范围": rd.Scope, "外发检测次数": rd.Detections, "阻断次数": rd.Blocked,
		"DLP事件数": rd.Incidents, "严重事件数": rd.Critical, "已处置": rd.Resolved, "处置完成率": fmt.Sprintf("%d%%", rd.ResolvedPct),
		"渠道分布": rd.Channels, "级别分布": rd.Severity, "部门分布": rd.Depts, "高风险用户TOP10": top, "合规检查": rd.Checks}
	raw, _ := json.MarshalIndent(data, "", " ")
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	msg, usage, err := conf.cli.Chat(cctx, []llm.Message{{Role: "system", Content: reportPrompt}, {Role: "user", Content: string(raw)}}, llm.Options{MaxTokens: 1200, Temperature: 0.3})
	s.recordAI(usage, err)
	if err != nil {
		slog.Warn("生成报表 AI 摘要失败", "err", err)
		return ""
	}
	return clip(strings.TrimSpace(red.Restore(msg.Content)), 2000)
}

/* ---------- AI 安全助手 ---------- */

const assistantPrompt = `你是 OpenDLP 数据防泄漏平台内置的安全运营助手，帮助安全管理员分析 DLP 事件、用户风险、策略与终端状态。

工作方式：
- 涉及数据的问题必须先调用工具查询，只依据工具返回的数据回答，不要编造数字；工具无权限或没有数据时如实说明。
- 时间范围未说明时默认近 30 天。
- 方括号中的代号（例如 [用户A]、[终端B]）是脱敏后的标识，回答中保持原样；需要查询某个人或终端时可以直接把代号作为工具参数。
- 回答使用简体中文，先给结论再给依据，适当使用 Markdown 列表或表格，控制在 400 字以内；可以给出下一步处置建议。
- 你只能查询，不能修改策略、处置事件或执行终端指令；需要操作时告诉管理员在控制台的哪个页面完成。`

type aiTool struct {
	def    llm.Tool
	module string // 需要的查看权限
	run    func(ctx context.Context, args map[string]any, rd *llm.Redactor) (any, error)
}

func argStr(a map[string]any, k string) string { v, _ := a[k].(string); return strings.TrimSpace(v) }
func argInt(a map[string]any, k string, def, lo, hi int) int {
	if v, ok := a[k].(float64); ok {
		return max(lo, min(hi, int(v)))
	}
	return def
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func prop(typ, desc string, enum ...string) map[string]any {
	p := map[string]any{"type": typ, "description": desc}
	if len(enum) > 0 {
		p["enum"] = enum
	}
	return p
}

// keyOf 把模型给出的中文名称或 key 转换为渠道 / 数据类型 key。
func (s *Server) keyOf(kind, v string) string {
	if v == "" {
		return ""
	}
	out := v
	s.St.Read(func(d *store.Data) {
		if kind == "channel" {
			for _, c := range d.Channels {
				if c.Key == v || c.Name == v || strings.Contains(c.Name, v) {
					out = c.Key
					return
				}
			}
		} else {
			for _, t := range d.DataTypes {
				if t.Key == v || t.Name == v || strings.Contains(t.Name, v) {
					out = t.Key
					return
				}
			}
		}
	})
	return out
}

func sevKey(v string) string {
	for k, n := range sevName {
		if v == k || v == n || strings.Contains(n, v) && v != "" {
			return k
		}
	}
	return ""
}

// filterFromArgs 解析通用过滤参数（天数、用户、部门、渠道、级别、数据类型）。
func (s *Server) filterFromArgs(a map[string]any, rd *llm.Redactor) store.IncidentFilter {
	days := argInt(a, "days", 30, 1, 365)
	return store.IncidentFilter{From: time.Now().AddDate(0, 0, -days).UnixMilli(), User: rd.Lookup(argStr(a, "user")), Dept: argStr(a, "dept"),
		Ch: s.keyOf("channel", argStr(a, "channel")), Sev: sevKey(argStr(a, "severity")), DataType: s.keyOf("dataType", argStr(a, "data_type")), St: statusKey(argStr(a, "status"))}
}

func statusKey(v string) string {
	for k, n := range stName {
		if v == k || v == n {
			return k
		}
	}
	return ""
}

var filterProps = map[string]any{
	"days":      prop("integer", "统计最近多少天，默认 30，最大 365"),
	"user":      prop("string", "按用户筛选（姓名或代号）"),
	"dept":      prop("string", "按部门名称筛选"),
	"channel":   prop("string", "按外发渠道筛选", "email", "usb", "cloud", "im", "web", "print"),
	"severity":  prop("string", "按级别筛选", "critical", "high", "medium", "low"),
	"data_type": prop("string", "按数据类型筛选（例如 idcard、customer、source，或中文名称）"),
	"status":    prop("string", "按处置状态筛选", "pending", "processing", "resolved", "fp"),
}

func withProps(extra map[string]any) map[string]any {
	m := map[string]any{}
	for k, v := range filterProps {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (s *Server) aiTools() []aiTool {
	loc := s.St.Loc
	maskKey := func(by string, rd *llm.Redactor, k string) string {
		switch by {
		case "user":
			return rd.Mask("user", k)
		case "host":
			return rd.Mask("host", k)
		}
		return k
	}
	return []aiTool{
		{module: "incidents", def: llm.NewTool("incident_stats", "按维度统计 DLP 事件数量（排行、分布、趋势）。",
			obj(withProps(map[string]any{
				"group_by": prop("string", "分组维度：渠道 channel、级别 severity、数据类型 data_type、部门 dept、用户 user、终端 host、处置动作 action、处置状态 status、策略 policy、按天 day、按小时 hour",
					"channel", "severity", "data_type", "dept", "user", "host", "action", "status", "policy", "day", "hour"),
				"limit": prop("integer", "最多返回多少组，默认 10，最大 50")}), "group_by")),
			run: func(ctx context.Context, a map[string]any, rd *llm.Redactor) (any, error) {
				by := argStr(a, "group_by")
				groups, total, err := s.St.IncidentGroup(ctx, s.filterFromArgs(a, rd), by, argInt(a, "limit", 10, 1, 50))
				if err != nil {
					return nil, err
				}
				var names func(string) string
				s.St.Read(func(d *store.Data) {
					names = func(k string) string {
						switch by {
						case "channel":
							return d.ChannelName(k)
						case "data_type":
							return d.DataTypeName(k)
						case "severity":
							return sevName[k]
						case "action":
							return actName[k]
						case "status":
							return stName[k]
						}
						return k
					}
				})
				rows := []map[string]any{}
				for _, g := range groups {
					rows = append(rows, map[string]any{"name": maskKey(by, rd, names(g.Key)), "count": g.Count})
				}
				return map[string]any{"total": total, "groups": rows}, nil
			}},
		{module: "incidents", def: llm.NewTool("search_incidents", "查询 DLP 事件明细（按时间倒序）。",
			obj(withProps(map[string]any{"keyword": prop("string", "按文件名或事件编号关键词搜索"), "limit": prop("integer", "返回条数，默认 10，最大 20")}))),
			run: func(ctx context.Context, a map[string]any, rd *llm.Redactor) (any, error) {
				f := s.filterFromArgs(a, rd)
				f.Q = argStr(a, "keyword")
				list, total, err := s.St.ListIncidents(ctx, f, 1, argInt(a, "limit", 10, 1, 20))
				if err != nil {
					return nil, err
				}
				rows := []map[string]any{}
				s.St.Read(func(d *store.Data) {
					for _, i := range list {
						rows = append(rows, map[string]any{"id": i.ID, "time": fmtTS(i.TS, loc), "user": rd.Mask("user", i.User), "dept": i.Dept, "host": rd.Mask("host", i.Host),
							"channel": d.ChannelName(i.Channel), "dest": rd.Text(i.Dest), "data_type": d.DataTypeName(i.DataType), "file": rd.Text(i.File), "matches": i.Matches,
							"severity": sevName[i.Severity], "action": actName[i.Action], "status": stName[i.Status], "policy": i.Policy})
					}
				})
				return map[string]any{"total": total, "items": rows}, nil
			}},
		{module: "incidents", def: llm.NewTool("user_profile", "查看某个员工的画像：部门、职位、在职状态、近 90 天事件统计与外发审批。",
			obj(map[string]any{"user": prop("string", "员工姓名或代号")}, "user")),
			run: func(ctx context.Context, a map[string]any, rd *llm.Redactor) (any, error) {
				name := rd.Lookup(argStr(a, "user"))
				out := map[string]any{"user": rd.Mask("user", name)}
				found := false
				s.St.Read(func(d *store.Data) {
					if e := d.Employee(name); e != nil {
						found = true
						out["dept"], out["title"], out["status"], out["joined"] = e.Dept, e.Title, empStatus[e.Status], fmtTS(e.Joined, loc)
					}
					apr := map[string]int{}
					for _, x := range d.Approvals {
						if x.User == name {
							apr[x.Status]++
						}
					}
					out["approvals"] = apr
				})
				f := store.IncidentFilter{User: name, From: time.Now().AddDate(0, 0, -90).UnixMilli()}
				for _, by := range []string{"channel", "severity", "data_type"} {
					g, total, err := s.St.IncidentGroup(ctx, f, by, 10)
					if err != nil {
						return nil, err
					}
					out["incidents_90d"] = total
					m := map[string]int{}
					s.St.Read(func(d *store.Data) {
						for _, x := range g {
							k := x.Key
							switch by {
							case "channel":
								k = d.ChannelName(k)
							case "data_type":
								k = d.DataTypeName(k)
							case "severity":
								k = sevName[k]
							}
							m[k] = x.Count
						}
					})
					out["by_"+by] = m
				}
				if !found && out["incidents_90d"] == 0 {
					return map[string]any{"error": "未找到该员工"}, nil
				}
				return out, nil
			}},
		{module: "policies", def: llm.NewTool("list_policies", "列出防泄漏策略：渠道、数据类型、动作、阈值、命中次数、是否启用。", nil),
			run: func(ctx context.Context, a map[string]any, rd *llm.Redactor) (any, error) {
				rows := []map[string]any{}
				s.St.Read(func(d *store.Data) {
					for _, p := range d.Policies {
						var chs, dts []string
						for _, c := range p.Channels {
							chs = append(chs, d.ChannelName(c))
						}
						for _, t := range p.DataTypes {
							dts = append(dts, d.DataTypeName(t))
						}
						rows = append(rows, map[string]any{"id": p.ID, "name": p.Name, "enabled": p.Enabled, "channels": chs, "data_types": dts,
							"action": actName[p.Action], "severity": sevName[p.Severity], "threshold": p.Threshold, "hits": p.Hits})
					}
				})
				return rows, nil
			}},
		{module: "endpoints", def: llm.NewTool("endpoint_overview", "终端 Agent 概况：在线 / 离线 / 异常数量、版本分布、严格管控终端、离线终端列表。", nil),
			run: func(ctx context.Context, a map[string]any, rd *llm.Redactor) (any, error) {
				out := map[string]any{}
				s.St.Read(func(d *store.Data) {
					st, ver := map[string]int{}, map[string]int{}
					offline, strict := []string{}, []string{}
					for _, e := range d.Endpoints {
						st[map[string]string{"online": "在线", "offline": "离线", "warning": "防护异常"}[e.Status]]++
						ver[e.Agent]++
						if e.Status == "offline" && len(offline) < 20 {
							offline = append(offline, rd.Mask("host", e.Host)+"（"+e.Dept+"，最后在线 "+fmtTS(e.LastSeen, loc)+"）")
						}
						if e.Strict {
							strict = append(strict, rd.Mask("host", e.Host))
						}
					}
					out["total"], out["by_status"], out["agent_versions"], out["offline"], out["strict"] = len(d.Endpoints), st, ver, offline, strict
				})
				return out, nil
			}},
	}
}

type chatTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// POST /api/v1/ai/chat {messages:[{role,content}]}
func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Messages []chatTurn `json:"messages"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if n := len(req.Messages); n == 0 || n > 20 || req.Messages[n-1].Role != "user" {
		writeErr(w, http.StatusBadRequest, "对话格式无效（最多 20 条，最后一条须为提问）")
		return
	}
	for _, m := range req.Messages {
		if (m.Role != "user" && m.Role != "assistant") || len([]rune(m.Content)) > 4000 || strings.TrimSpace(m.Content) == "" {
			writeErr(w, http.StatusBadRequest, "单条消息不能为空且不超过 4000 字")
			return
		}
	}
	if !s.aiLimit.allow("ai:" + a.Acc) {
		writeErr(w, http.StatusTooManyRequests, "AI 分析调用过于频繁，请稍后再试")
		return
	}
	conf, err := s.aiSetup()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	rd := llm.NewRedactor(conf.redact)
	s.knownEntities(rd)
	tools := map[string]aiTool{}
	var defs []llm.Tool
	var roleName string
	s.St.Read(func(d *store.Data) { roleName = d.RoleName(a.Role) })
	for _, t := range s.aiTools() {
		if allowed(a.Perms, t.module, "view") {
			tools[t.def.Function.Name] = t
			defs = append(defs, t.def)
		}
	}
	sys := assistantPrompt + fmt.Sprintf("\n\n当前时间：%s（%s）。提问者角色：%s。", time.Now().In(s.St.Loc).Format("2006-01-02 15:04"), s.St.Loc, roleName)
	if len(defs) == 0 {
		sys += "\n当前角色没有可查询的数据权限，只能回答平台使用方面的问题。"
	}
	msgs := []llm.Message{{Role: "system", Content: sys}}
	for _, m := range req.Messages {
		msgs = append(msgs, llm.Message{Role: m.Role, Content: rd.Text(m.Content)})
	}
	ctx, cancel := context.WithTimeout(r.Context(), 170*time.Second)
	defer cancel()
	type used struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
		OK   bool           `json:"ok"`
	}
	var trace []used
	var total llm.Usage
	var reply string
	for round := 0; ; round++ {
		opts := llm.Options{Tools: defs, MaxTokens: 2000}
		if round >= 6 { // 工具调用轮数上限：最后一轮不再提供工具，要求直接回答
			opts.Tools = nil
		}
		msg, u, err := conf.cli.Chat(ctx, msgs, opts)
		total.Prompt, total.Completion, total.Total = total.Prompt+u.Prompt, total.Completion+u.Completion, total.Total+u.Total
		if err != nil {
			s.recordAI(total, err)
			s.audit(a, "AI 分析", "AI 助手提问："+clip(req.Messages[len(req.Messages)-1].Content, 60), false, clip(err.Error(), 100))
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		if len(msg.ToolCalls) == 0 || opts.Tools == nil {
			reply = msg.Content
			break
		}
		msgs = append(msgs, msg)
		for _, tc := range msg.ToolCalls {
			var args map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			if args == nil {
				args = map[string]any{}
			}
			var result any
			t, ok := tools[tc.Function.Name]
			if !ok {
				result = map[string]string{"error": "工具不存在或当前角色无权使用"}
			} else if res, err := t.run(ctx, args, rd); err != nil {
				result = map[string]string{"error": clip(err.Error(), 200)}
			} else {
				result = res
			}
			raw, _ := json.Marshal(result)
			content := string(raw)
			if len(content) > 12000 {
				content = content[:12000] + "…（结果过长已截断）"
			}
			_, isErr := result.(map[string]string)
			trace = append(trace, used{Name: tc.Function.Name, Args: args, OK: ok && !isErr})
			msgs = append(msgs, llm.Message{Role: "tool", ToolCallID: tc.ID, Content: content})
		}
	}
	s.recordAI(total, nil)
	s.audit(a, "AI 分析", "AI 助手提问："+clip(req.Messages[len(req.Messages)-1].Content, 60), true, "")
	if trace == nil {
		trace = []used{}
	}
	for _, t := range trace { // 展示给管理员的工具参数还原为原值
		for k, v := range t.Args {
			if sv, ok := v.(string); ok {
				t.Args[k] = rd.Lookup(sv)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reply": rd.Restore(strings.TrimSpace(reply)), "tools": trace, "usage": total, "model": conf.cli.Model, "redacted": conf.redact})
}
