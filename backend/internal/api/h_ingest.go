package api

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"opendlp/internal/notify"
	"opendlp/internal/seed"
	"opendlp/internal/store"
)

// agent 上报接口鉴权：Authorization: Bearer <OPENDLP_AGENT_TOKEN>。未配置令牌时接口关闭。
func (s *Server) agent(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Cfg.AgentToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.Cfg.AgentToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "上报令牌无效")
			return
		}
		h(w, r)
	}
}

func validKey(v string, allowedKeys []string) bool {
	for _, k := range allowedKeys {
		if v == k {
			return true
		}
	}
	return false
}

var (
	channelKeys  = []string{"email", "usb", "cloud", "im", "web", "print"}
	actionKeys   = []string{"allow", "audit", "encrypt", "block"}
	severityKeys = []string{"critical", "high", "medium", "low"}
)

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

type ingestItem struct {
	TS       int64    `json:"ts"`
	User     string   `json:"user"`
	Host     string   `json:"host"`
	IP       string   `json:"ip"`
	Channel  string   `json:"channel"`
	Dest     string   `json:"dest"`
	DataType string   `json:"dataType"`
	File     string   `json:"file"`
	Size     string   `json:"size"`
	Matches  int      `json:"matches"`
	PolicyID string   `json:"policyId"`
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	RuleIDs  []string `json:"ruleIds"`
}

// POST /api/v1/ingest/detections —— 网关 / 共享令牌接入的终端上报检测结果。
// action 为 allow 且未指定 severity 时仅计入检测量，否则生成 DLP 事件。
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	s.ingestDetections(w, r, "")
}

// ingestDetections 处理检测上报；forcedHost 非空时（独立凭据的 Agent）忽略上报中的主机名，防止冒充其他终端。
func (s *Server) ingestDetections(w http.ResponseWriter, r *http.Request, forcedHost string) {
	var items []ingestItem
	if !readJSON(w, r, &items) {
		return
	}
	if len(items) > 500 {
		writeErr(w, http.StatusRequestEntityTooLarge, "单次最多上报 500 条")
		return
	}
	created, counted, skipped := 0, 0, 0
	now := time.Now()
	for _, it := range items {
		if forcedHost != "" {
			it.Host = forcedHost
		}
		// 离线补报允许 30 天内的历史数据，更早或未来的时间戳按当前时间处理
		if it.TS == 0 || it.TS > now.Add(5*time.Minute).UnixMilli() || it.TS < now.AddDate(0, 0, -30).UnixMilli() {
			it.TS = now.UnixMilli()
		}
		if !validKey(it.Channel, channelKeys) || !validKey(it.Action, actionKeys) || it.DataType == "" {
			skipped++
			continue
		}
		if len(it.RuleIDs) > 0 {
			s.St.Write(func(d *store.Data) {
				for _, ru := range d.Rules {
					if validKey(ru.ID, it.RuleIDs) {
						ru.Hits++
					}
				}
			})
		}
		if it.Action == "allow" && it.Severity == "" {
			if err := s.St.AddDetection(r.Context(), it.TS, it.Channel, clip(it.DataType, 20), it.Action); err != nil {
				writeErr(w, http.StatusInternalServerError, "写入失败")
				return
			}
			counted++
			continue
		}
		if !validKey(it.Severity, severityKeys) {
			it.Severity = "medium"
		}
		inc := &store.Incident{TS: it.TS, User: clip(it.User, 40), Host: clip(it.Host, 64), IP: clip(it.IP, 45), Channel: it.Channel, Dest: clip(it.Dest, 200),
			DataType: clip(it.DataType, 20), File: clip(it.File, 260), Size: clip(it.Size, 20), Matches: max(0, it.Matches),
			Severity: it.Severity, Action: it.Action, Status: "pending", PolicyID: clip(it.PolicyID, 20)}
		err := s.RecordIncident(r.Context(), inc, func(d *store.Data, i *store.Incident) {
			if e := d.Employee(i.User); e != nil {
				i.Dept = e.Dept
			}
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "写入失败")
			return
		}
		created++
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"incidents": created, "detections": counted, "skipped": skipped})
}

// enqueue 为终端排队一条指令（须在写锁内调用），保留最近 1000 条。
func enqueue(d *store.Data, host, action, by string) *store.Command {
	c := &store.Command{ID: fmt.Sprintf("CMD-%d", store.NextSeq(d, "command")), Host: host, Action: action, By: by, Created: time.Now().UnixMilli(), Status: "pending"}
	d.Commands = append(d.Commands, c)
	if len(d.Commands) > 1000 {
		d.Commands = d.Commands[len(d.Commands)-1000:]
	}
	return c
}

type heartbeatReq struct {
	Host, User, Dept, IP, OS, OSKey, Agent string
	CPU, Mem, Disk                         int
	Warning                                bool
	PolicyVersion                          string
}

// POST /api/v1/ingest/heartbeat —— 共享令牌接入的终端心跳（兼容旧版 Agent）。
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb heartbeatReq
	if !readJSON(w, r, &hb) {
		return
	}
	hb.Host = clip(hb.Host, 64)
	if hb.Host == "" {
		writeErr(w, http.StatusBadRequest, "缺少主机名")
		return
	}
	cmds, _ := s.heartbeat(hb)
	writeJSON(w, http.StatusOK, map[string]any{"commands": cmds, "interval": 60})
}

// heartbeat 登记 / 更新终端并领取待执行指令，返回指令与该终端应使用的策略包版本。
func (s *Server) heartbeat(hb heartbeatReq) ([]store.Command, string) {
	now := time.Now().UnixMilli()
	var cmds []store.Command
	var version string
	isNew := false
	s.St.Write(func(d *store.Data) {
		e := upsertEndpoint(d, hb.Host, now, &isNew)
		e.User, e.IP, e.OS, e.Agent = clip(hb.User, 40), clip(hb.IP, 45), clip(hb.OS, 60), clip(hb.Agent, 20)
		e.OSKey = map[string]string{"win": "win", "mac": "mac", "linux": "uos", "uos": "uos", "kylin": "kylin"}[hb.OSKey]
		e.OSShort = map[string]string{"win": "WIN", "mac": "MAC", "uos": "LNX", "kylin": "KY"}[e.OSKey]
		if emp := d.Employee(e.User); emp != nil {
			e.Dept = emp.Dept
		} else if hb.Dept != "" {
			e.Dept = clip(hb.Dept, 40)
		}
		e.CPU, e.Mem, e.Disk = min(100, max(-1, hb.CPU)), min(100, max(-1, hb.Mem)), min(100, max(-1, hb.Disk))
		e.LastSeen, e.Status = now, "online"
		if hb.Warning {
			e.Status = "warning"
		}
		version = buildBundle(d, e).Version
		if hb.PolicyVersion != "" {
			e.PolicyVersion, e.PolicySynced = clip(hb.PolicyVersion, 40), hb.PolicyVersion == version
		}
		for _, c := range d.Commands {
			if c.Host == hb.Host && c.Status == "pending" {
				c.Status, c.Delivered = "delivered", now
				cmds = append(cmds, *c)
			}
		}
	})
	if isNew {
		s.addNote("info", "新终端接入", hb.Host+"（"+hb.User+"）已注册到管理平台", "#/endpoints")
	}
	if cmds == nil {
		cmds = []store.Command{}
	}
	return cmds, version
}

// upsertEndpoint 按主机名查找终端，不存在则创建（须在写锁内调用）。
func upsertEndpoint(d *store.Data, host string, now int64, isNew *bool) *store.Endpoint {
	for _, x := range d.Endpoints {
		if x.Host == host {
			return x
		}
	}
	e := &store.Endpoint{ID: fmt.Sprintf("EP%d", store.NextSeq(d, "endpoint")), Host: host, First: now, Status: "online"}
	d.Endpoints = append(d.Endpoints, e)
	*isNew = true
	return e
}

// POST /api/v1/ingest/nodes —— 检测节点 / 网关心跳与运行指标。
func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var list []store.Node
	if !readJSON(w, r, &list) {
		return
	}
	if len(list) == 0 || len(list) > 100 {
		writeErr(w, http.StatusBadRequest, "请上报 1-100 个节点")
		return
	}
	now := time.Now().UnixMilli()
	s.St.Write(func(d *store.Data) {
		for _, n := range list {
			n.Name = clip(n.Name, 64)
			if n.Name == "" {
				continue
			}
			var x *store.Node
			for _, y := range d.Nodes {
				if y.Name == n.Name {
					x = y
				}
			}
			if x == nil {
				x = &store.Node{Name: n.Name}
				d.Nodes = append(d.Nodes, x)
			}
			x.Role, x.IP, x.Version = clip(n.Role, 40), clip(n.IP, 45), clip(n.Version, 20)
			x.CPU, x.Mem, x.QPS, x.Latency, x.Up = min(100, max(0, n.CPU)), min(100, max(0, n.Mem)), max(0, n.QPS), max(0, n.Latency), max(0, n.Up)
			x.Status, x.LastSeen = "online", now
			if n.Status == "warning" || x.CPU > 90 {
				x.Status = "warning"
			}
		}
	})
	s.publishNodes()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// publishNodes 汇总在线节点指标、写入指标曲线并推送到运维页。
func (s *Server) publishNodes() {
	var nodes []store.Node
	qps, lat, n := 0, 0, 0
	s.St.Read(func(d *store.Data) {
		for _, x := range d.Nodes {
			nodes = append(nodes, *x)
			if x.Status != "offline" {
				qps += x.QPS
				lat += x.Latency
				n++
			}
		}
	})
	if n > 0 {
		lat /= n
	}
	s.Metrics.Push(qps, lat)
	s.Hub.Publish(Event{Name: "nodes", Module: "ops", Data: map[string]any{"nodes": nodes, "qps": qps, "lat": lat}})
}

// POST /api/v1/ingest/approvals —— 员工通过 Agent / 门户提交外发申请。
func (s *Server) handleApprovalSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User, File, DataType, Size, Channel, To, Reason string
		Urgent                                          bool
		Matches, Risk                                   int
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validUser(req.User) || clip(req.File, 260) == "" || clip(req.To, 200) == "" || clip(req.Reason, 500) == "" || !validKey(req.Channel, channelKeys) {
		writeErr(w, http.StatusUnprocessableEntity, "请提供申请人、文件、外发方式、接收方与申请理由")
		return
	}
	now := time.Now()
	var a store.Approval
	s.St.Write(func(d *store.Data) {
		x := &store.Approval{ID: fmt.Sprintf("APV-%d", 3000+store.NextSeq(d, "approval")), TS: now.UnixMilli(), User: clip(req.User, 40), File: clip(req.File, 260),
			DataType: clip(req.DataType, 20), Size: clip(req.Size, 20), Channel: req.Channel, To: clip(req.To, 200), Reason: clip(req.Reason, 500),
			Urgent: req.Urgent, Matches: max(0, req.Matches), Risk: min(100, max(0, req.Risk)), Status: "pending", Stage: 2}
		x.Level = seed.Level[x.DataType]
		if x.Level == "" {
			x.Level = "内部"
		}
		dl := 24 * time.Hour
		if x.Urgent {
			dl = 4 * time.Hour
		}
		x.Deadline = now.Add(dl).UnixMilli()
		if e := d.Employee(x.User); e != nil {
			x.Dept = e.Dept
			if l := d.DeptLeaders[e.Dept]; l != "" && l != x.User {
				x.Leader, x.Stage = l, 1 // 先由部门负责人审批
			}
		}
		d.Approvals = append([]*store.Approval{x}, d.Approvals...)
		a = *x
	})
	s.Hub.Publish(Event{Name: "approvals.changed", Module: "approvals", Data: map[string]string{"id": a.ID}})
	if a.Stage == 2 {
		s.addNote("warning", "新的外发申请", a.User+" 申请外发 "+a.File+" 至 "+a.To, "#/approvals")
		s.Alerts.Human(notify.Message{Title: "待审批：" + a.User + " 申请外发 " + a.File, Severity: map[bool]string{true: "high", false: "medium"}[a.Urgent],
			Text: fmt.Sprintf("申请单：%s\n接收方：%s\n密级：%s\n理由：%s", a.ID, a.To, a.Level, a.Reason), Link: "#/approvals", Event: "approval"})
	}
	writeJSON(w, http.StatusCreated, a)
}

// POST /api/v1/ingest/approvals/{id}/leader {leader, approve, comment} —— 部门负责人审批结果回传（企业微信 / 门户）。
func (s *Server) handleLeaderDecision(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Leader  string `json:"leader"`
		Approve bool   `json:"approve"`
		Comment string `json:"comment"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	code, msg := 0, ""
	var a store.Approval
	s.St.Write(func(d *store.Data) {
		x := findApproval(d, id)
		switch {
		case x == nil:
			code, msg = http.StatusNotFound, "审批单不存在"
		case x.Status != "pending" || x.Stage != 1:
			code, msg = http.StatusConflict, "该申请不在部门负责人审批阶段"
		case req.Leader != x.Leader:
			code, msg = http.StatusForbidden, "审批人与部门负责人不一致"
		case req.Approve:
			x.Stage = 2
		default:
			x.Status, x.Approver, x.Comment, x.DecidedAt = "rejected", x.Leader, clip(req.Comment, 500), time.Now().UnixMilli()
		}
		if x != nil {
			a = *x
		}
	})
	if code != 0 {
		writeErr(w, code, msg)
		return
	}
	_ = s.St.AppendAudit(r.Context(), store.AuditEntry{Op: "leader:" + req.Leader, Role: "部门负责人", Type: "外发审批",
		Detail: fmt.Sprintf("%s %s 的外发申请 %s", map[bool]string{true: "同意", false: "驳回"}[req.Approve], a.User, a.ID), IP: s.clientIP(r), OK: true})
	s.Hub.Publish(Event{Name: "approvals.changed", Module: "approvals", Data: map[string]string{"id": id}})
	if a.Stage == 2 && a.Status == "pending" {
		s.addNote("warning", "待您审批", a.User+" 的外发申请已通过部门负责人审批", "#/approvals")
	}
	writeJSON(w, http.StatusOK, a)
}

// POST /api/v1/ingest/discovery {repo, type, total, sens, risk, levels} —— 扫描节点回传数据源扫描结果。
func (s *Server) handleDiscoveryResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo, Type        string
		Total, Sens, Risk int
		Levels            map[string]int
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Repo = clip(req.Repo, 120)
	if req.Repo == "" || req.Total < 0 || req.Sens < 0 || req.Sens > req.Total {
		writeErr(w, http.StatusUnprocessableEntity, "扫描结果无效")
		return
	}
	lv := map[string]int{}
	for _, k := range []string{"绝密", "机密", "内部", "公开"} {
		lv[k] = max(0, req.Levels[k])
	}
	s.St.Write(func(d *store.Data) {
		var rp *store.Repo
		for _, x := range d.Repos {
			if x.Name == req.Repo {
				rp = x
			}
		}
		if rp == nil {
			icons := map[string]string{"文件服务器": "folder", "数据库": "database", "对象存储": "cloud", "协作平台": "layers", "邮件系统": "mail", "终端": "monitor"}
			icon := icons[req.Type]
			if icon == "" {
				req.Type, icon = "文件服务器", "folder"
			}
			rp = &store.Repo{Name: req.Repo, Type: req.Type, Icon: icon}
			d.Repos = append(d.Repos, rp)
		}
		rp.Total, rp.Sens, rp.Risk, rp.Levels, rp.Last = req.Total, req.Sens, min(100, max(0, req.Risk)), lv, time.Now().UnixMilli()
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
