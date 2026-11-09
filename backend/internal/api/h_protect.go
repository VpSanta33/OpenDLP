package api

import (
	"fmt"

	"net/http"
	"opendlp/internal/seed"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"opendlp/internal/store"
)

/* ---------- 外发审批 ---------- */

type decisionReq struct {
	Decision   string                `json:"decision"` // approve | reject | forward
	Comment    string                `json:"comment"`
	Conditions *store.ReleaseOptions `json:"conditions"`
	To         string                `json:"to"`
}

func findApproval(d *store.Data, id string) *store.Approval {
	for _, x := range d.Approvals {
		if x.ID == id {
			return x
		}
	}
	return nil
}

// checkActionable 当前阶段须为「数据安全官」审批（stage 2），且未超时。
func checkActionable(x *store.Approval, now int64) (int, string) {
	if x.Status == "pending" && now > x.Deadline {
		x.Status = "expired"
		return http.StatusConflict, "该申请已超过审批时限，系统已自动关闭"
	}
	if x.Status != "pending" {
		return http.StatusConflict, "该申请已处理"
	}
	if x.Stage != 2 {
		return http.StatusConflict, "该申请尚在部门负责人审批阶段"
	}
	return 0, ""
}

func (s *Server) handleApprovalDecision(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req decisionReq
	if !readJSON(w, r, &req) {
		return
	}
	req.Comment = strings.TrimSpace(req.Comment)
	if len([]rune(req.Comment)) > 500 {
		writeErr(w, http.StatusBadRequest, "审批意见不能超过 500 字")
		return
	}
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		x := findApproval(d, id)
		if x == nil {
			return http.StatusNotFound, fail("审批单不存在")
		}
		if code, msg := checkActionable(x, time.Now().UnixMilli()); code != 0 {
			return code, fail(msg)
		}
		switch req.Decision {
		case "approve":
			c := req.Conditions
			if c == nil {
				c = &store.ReleaseOptions{Encrypt: true, Watermark: true, ExpireDays: 7, MaxOpens: 10}
			}
			if x.Level == "机密" {
				c.Encrypt = true // 机密文件必须加密外发
			}
			if c.ExpireDays <= 0 || c.ExpireDays > 30 {
				return http.StatusBadRequest, fail("文件有效期须为 1-30 天")
			}
			x.Status, x.Stage, x.Conditions = "approved", 3, c
		case "reject":
			if req.Comment == "" {
				return http.StatusUnprocessableEntity, fail("驳回申请时请填写审批意见")
			}
			x.Status = "rejected"
		case "forward":
			to := d.Admin(req.To)
			if to == nil || to.Acc == a.Acc || !d.Perms[to.Role]["approvals"].Op {
				return http.StatusBadRequest, fail("转交对象无审批权限")
			}
			s.auditIn(d, a, "外发审批", fmt.Sprintf("将审批单 %s 转交给 %s", x.ID, to.Name), true, "")
			return http.StatusOK, x
		default:
			return http.StatusBadRequest, fail("审批决定无效")
		}
		x.Approver, x.Comment, x.DecidedAt = a.Name, req.Comment, time.Now().UnixMilli()
		verb := map[string]string{"approve": "同意", "reject": "驳回"}[req.Decision]
		s.auditIn(d, a, "外发审批", fmt.Sprintf("%s %s 的外发申请 %s（%s → %s）", verb, x.User, x.ID, x.File, x.To), true, "")
		return http.StatusOK, x
	})
	s.Hub.Publish(Event{Name: "approvals.changed", Module: "approvals", Data: map[string]string{"id": id}})
}

func (s *Server) handleApprovalBatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ IDs []string }
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 100 {
		writeErr(w, http.StatusBadRequest, "请选择 1-100 个审批单")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		ok, skipped := 0, 0
		now := time.Now().UnixMilli()
		for _, id := range req.IDs {
			x := findApproval(d, id)
			if x == nil {
				skipped++
				continue
			}
			if code, _ := checkActionable(x, now); code != 0 {
				skipped++
				continue
			}
			x.Status, x.Stage, x.Approver, x.DecidedAt = "approved", 3, a.Name, now
			x.Comment = "批量审批同意"
			x.Conditions = &store.ReleaseOptions{Encrypt: true, Watermark: true, ExpireDays: 7, MaxOpens: 10}
			ok++
		}
		s.auditIn(d, a, "外发审批", fmt.Sprintf("批量同意 %d 个外发申请（跳过 %d 个）", ok, skipped), true, "")
		return http.StatusOK, map[string]int{"approved": ok, "skipped": skipped}
	})
	s.Hub.Publish(Event{Name: "approvals.changed", Module: "approvals", Data: map[string]any{"ids": req.IDs}})
}

func (s *Server) handleApprovalUrge(w http.ResponseWriter, r *http.Request, a *Actor) {
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		x := findApproval(d, id)
		if x == nil || x.Status != "pending" || x.Stage != 1 {
			return http.StatusConflict, fail("该申请当前无需催办")
		}
		s.auditIn(d, a, "外发审批", fmt.Sprintf("催办 %s 审批 %s", x.Leader, x.ID), true, "")
		return http.StatusOK, map[string]string{"leader": x.Leader}
	})
}

func (s *Server) handleApprovalFlow(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		AutoWhitelist bool `json:"autoWhitelist"`
		Delegate      bool `json:"delegate"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		d.Settings["apvAutoWhitelist"], d.Settings["apvDelegate"] = req.AutoWhitelist, req.Delegate
		s.auditIn(d, a, "配置变更", fmt.Sprintf("更新外发审批流程：白名单自动通过=%t，离线自动转交=%t", req.AutoWhitelist, req.Delegate), true, "")
		return http.StatusOK, map[string]bool{"ok": true}
	})
}

/* ---------- 策略 ---------- */

var (
	actions    = []string{"block", "encrypt", "audit"}
	severities = []string{"critical", "high", "medium", "low"}
)

func (s *Server) handlePolicyCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var p store.Policy
	if !readJSON(w, r, &p) {
		return
	}
	p.Name, p.Desc = strings.TrimSpace(p.Name), strings.TrimSpace(p.Desc)
	switch {
	case p.Name == "" || len([]rune(p.Name)) > 40:
		writeErr(w, http.StatusUnprocessableEntity, "策略名称须为 1-40 个字符")
		return
	case len(p.Channels) == 0 || len(p.DataTypes) == 0:
		writeErr(w, http.StatusUnprocessableEntity, "请至少选择一个外发渠道与一种数据类型")
		return
	case !validKey(p.Action, actions) || !validKey(p.Severity, severities):
		writeErr(w, http.StatusUnprocessableEntity, "响应动作或风险等级无效")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		for _, x := range d.Policies {
			if x.Name == p.Name {
				return http.StatusConflict, fail("已存在同名策略")
			}
		}
		p.ID = fmt.Sprintf("POL-%d", 100+store.NextSeq(d, "policy"))
		p.Enabled, p.Hits, p.Updated, p.Owner = true, 0, time.Now().UnixMilli(), a.Name
		if p.Desc == "" {
			p.Desc = "自定义策略"
		}
		d.Policies = append([]*store.Policy{&p}, d.Policies...)
		s.auditIn(d, a, "策略变更", fmt.Sprintf("新建策略「%s」（%s）", p.Name, p.ID), true, "")
		return http.StatusCreated, p
	})
}

func (s *Server) handlePolicyPatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ Enabled *bool }
	if !readJSON(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "缺少 enabled 字段")
		return
	}
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		for _, p := range d.Policies {
			if p.ID == id {
				p.Enabled, p.Updated = *req.Enabled, time.Now().UnixMilli()
				s.auditIn(d, a, "策略变更", fmt.Sprintf("%s策略「%s」", map[bool]string{true: "启用", false: "停用"}[p.Enabled], p.Name), true, "")
				return http.StatusOK, p
			}
		}
		return http.StatusNotFound, fail("策略不存在")
	})
}

// POST /api/v1/policies/templates/sync —— 以停用状态导入内置合规策略模板（已存在的同名策略跳过）。
func (s *Server) handlePolicyTplSync(w http.ResponseWriter, r *http.Request, a *Actor) {
	s.mutate(w, func(d *store.Data) (int, any) {
		added := 0
		now := time.Now().UnixMilli()
		for _, t := range seed.PolicyTemplates() {
			exists := false
			for _, p := range d.Policies {
				if p.Name == t.Name {
					exists = true
				}
			}
			if exists {
				continue
			}
			p := t
			p.ID, p.Enabled, p.Updated, p.Owner = fmt.Sprintf("POL-%d", 100+store.NextSeq(d, "policy")), false, now, a.Name
			d.Policies = append(d.Policies, &p)
			added++
		}
		s.auditIn(d, a, "策略变更", fmt.Sprintf("导入内置合规策略模板 %d 条（停用状态）", added), true, "")
		return http.StatusOK, map[string]any{"added": added, "policies": d.Policies}
	})
}

/* ---------- 识别规则 ---------- */

var ruleCats = []string{"pii", "fin", "cred", "corp"}

// normalizeRule 校验并规整自定义规则（仅支持正则与关键词类型）。
func normalizeRule(name, cat, typ string, cfg map[string]any) (map[string]any, string) {
	if name = strings.TrimSpace(name); name == "" || len([]rune(name)) > 40 {
		return nil, "规则名称须为 1-40 个字符"
	}
	if !validKey(cat, ruleCats) {
		return nil, "数据分类无效"
	}
	switch typ {
	case "regex":
		src, _ := cfg["src"].(string)
		src = strings.TrimSpace(src)
		if src == "" || len(src) > 1000 {
			return nil, "请填写正则表达式（不超过 1000 字符）"
		}
		if _, err := regexp.Compile(src); err != nil {
			return nil, "正则语法错误（检测引擎使用 RE2 语法，不支持前后断言与反向引用）：" + err.Error()
		}
		out := map[string]any{"src": src}
		if c, _ := cfg["check"].(string); c == "idcard" || c == "luhn" {
			out["check"] = c
		}
		return out, ""
	case "keyword":
		raw, _ := cfg["words"].([]any)
		var words []any
		for _, w := range raw {
			if s, ok := w.(string); ok && strings.TrimSpace(s) != "" {
				words = append(words, strings.TrimSpace(s))
			}
		}
		if len(words) == 0 || len(words) > 500 {
			return nil, "请填写 1-500 个关键词"
		}
		return map[string]any{"words": words}, ""
	}
	return nil, "自定义规则仅支持正则表达式与关键词词典"
}

type ruleReq struct {
	Name string         `json:"name"`
	Cat  string         `json:"cat"`
	Type string         `json:"type"`
	Cfg  map[string]any `json:"cfg"`
	Desc string         `json:"desc"`
}

func (s *Server) handleRuleCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req ruleReq
	if !readJSON(w, r, &req) {
		return
	}
	cfg, msg := normalizeRule(req.Name, req.Cat, req.Type, req.Cfg)
	if msg != "" {
		writeErr(w, http.StatusUnprocessableEntity, msg)
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		ru := &store.Rule{ID: fmt.Sprintf("R-%d", 100+store.NextSeq(d, "rule")), Name: strings.TrimSpace(req.Name), Cat: req.Cat, Type: req.Type, Cfg: cfg,
			Desc: "自定义规则", Enabled: true, Updated: time.Now().UnixMilli()}
		if strings.TrimSpace(req.Desc) != "" {
			ru.Desc = strings.TrimSpace(req.Desc)
		}
		d.Rules = append([]*store.Rule{ru}, d.Rules...)
		s.auditIn(d, a, "规则变更", fmt.Sprintf("新建识别规则「%s」（%s）", ru.Name, ru.ID), true, "")
		return http.StatusCreated, ru
	})
}

func findRule(d *store.Data, id string) *store.Rule {
	for _, x := range d.Rules {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req ruleReq
	if !readJSON(w, r, &req) {
		return
	}
	cfg, msg := normalizeRule(req.Name, req.Cat, req.Type, req.Cfg)
	if msg != "" {
		writeErr(w, http.StatusUnprocessableEntity, msg)
		return
	}
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		ru := findRule(d, id)
		if ru == nil {
			return http.StatusNotFound, fail("规则不存在")
		}
		if ru.Builtin {
			return http.StatusForbidden, fail("内置规则不可修改，请复制为自定义规则")
		}
		ru.Name, ru.Cat, ru.Type, ru.Cfg, ru.Updated = strings.TrimSpace(req.Name), req.Cat, req.Type, cfg, time.Now().UnixMilli()
		s.auditIn(d, a, "规则变更", fmt.Sprintf("修改识别规则「%s」（%s）", ru.Name, ru.ID), true, "")
		return http.StatusOK, ru
	})
}

// PATCH /api/v1/rules/{id} {enabled?, sim?}
func (s *Server) handleRulePatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Enabled *bool `json:"enabled"`
		Sim     *int  `json:"sim"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		ru := findRule(d, id)
		if ru == nil {
			return http.StatusNotFound, fail("规则不存在")
		}
		if req.Enabled != nil {
			ru.Enabled = *req.Enabled
			s.auditIn(d, a, "规则变更", fmt.Sprintf("%s识别规则「%s」", map[bool]string{true: "启用", false: "停用"}[ru.Enabled], ru.Name), true, "")
		}
		if req.Sim != nil && ru.Type == "idm" {
			if *req.Sim < 40 || *req.Sim > 100 {
				return http.StatusBadRequest, fail("相似度阈值须在 40-100 之间")
			}
			cfg := map[string]any{}
			for k, v := range ru.Cfg {
				cfg[k] = v
			}
			cfg["sim"] = *req.Sim
			ru.Cfg = cfg
			s.auditIn(d, a, "规则变更", fmt.Sprintf("调整「%s」相似度阈值为 %d%%", ru.Name, *req.Sim), true, "")
		}
		ru.Updated = time.Now().UnixMilli()
		return http.StatusOK, ru
	})
}

// POST /api/v1/rules/{id}/sync|train —— EDM 索引同步 / 模型增量训练
func (s *Server) handleRuleAction(w http.ResponseWriter, r *http.Request, a *Actor) {
	id, act := r.PathValue("id"), r.PathValue("action")
	if !s.Cfg.Demo {
		writeErr(w, http.StatusNotImplemented, "EDM 索引同步与模型训练由检测引擎执行，请在检测节点上配置数据源后进行")
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		ru := findRule(d, id)
		if ru == nil {
			return http.StatusNotFound, fail("规则不存在")
		}
		switch {
		case act == "sync" && ru.Type == "edm":
			s.auditIn(d, a, "规则变更", fmt.Sprintf("同步 EDM 索引「%s」", ru.Name), true, "")
			ru.Updated = time.Now().UnixMilli()
			return http.StatusOK, map[string]any{"records": ru.Cfg["records"]}
		case act == "train" && ru.Type == "ml":
			s.auditIn(d, a, "规则变更", fmt.Sprintf("基于误报反馈增量训练模型「%s」", ru.Name), true, "")
			ru.Updated = time.Now().UnixMilli()
			return http.StatusOK, map[string]any{"samples": 214}
		}
		return http.StatusBadRequest, fail("该规则不支持此操作")
	})
}

/* ---------- 规则测试（与检测引擎同一套 RE2 实现） ---------- */

var idW = []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

func idcardOK(s string) bool {
	if len(s) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(s[i]-'0') * idW[i]
	}
	return "10X98765432"[sum%11] == strings.ToUpper(s[17:])[0]
}

func luhnOK(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

type match struct {
	S      int    `json:"s"` // UTF-16 偏移，便于前端直接切片
	E      int    `json:"e"`
	V      string `json:"v"`
	RuleID string `json:"ruleId"`
	OK     bool   `json:"ok"`
	bs, be int
}

// utf16Index 把字节偏移转换为 UTF-16 码元偏移。
func utf16Index(text string) func(int) int {
	idx := make([]int, len(text)+1)
	u := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		for k := 0; k < size; k++ {
			idx[i+k] = u
		}
		u += len(utf16.Encode([]rune{r}))
		i += size
	}
	idx[len(text)] = u
	return func(b int) int { return idx[b] }
}

// FindMatches 用规则集扫描文本，返回去重叠后的命中列表。
func FindMatches(text string, rules []*store.Rule) []match {
	var out []match
	for _, ru := range rules {
		switch ru.Type {
		case "regex":
			src, _ := ru.Cfg["src"].(string)
			re, err := regexp.Compile(src)
			if err != nil {
				continue
			}
			check, _ := ru.Cfg["check"].(string)
			for _, loc := range re.FindAllStringIndex(text, 200) {
				v := text[loc[0]:loc[1]]
				ok := true
				switch check {
				case "idcard":
					ok = idcardOK(v)
				case "luhn":
					ok = luhnOK(v)
				}
				out = append(out, match{V: v, RuleID: ru.ID, OK: ok, bs: loc[0], be: loc[1]})
			}
		case "keyword":
			words, _ := ru.Cfg["words"].([]any)
			for _, w := range words {
				ws, _ := w.(string)
				if ws == "" {
					continue
				}
				for i := 0; ; {
					k := strings.Index(text[i:], ws)
					if k < 0 {
						break
					}
					out = append(out, match{V: ws, RuleID: ru.ID, OK: true, bs: i + k, be: i + k + len(ws)})
					i += k + len(ws)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].bs != out[j].bs {
			return out[i].bs < out[j].bs
		}
		return out[i].be-out[i].bs > out[j].be-out[j].bs
	})
	conv := utf16Index(text)
	res := []match{}
	end := -1
	for _, m := range out {
		if m.bs >= end {
			m.S, m.E = conv(m.bs), conv(m.be)
			res = append(res, m)
			end = m.be
		}
	}
	return res
}

// POST /api/v1/rules/test {text, ruleIds?}；测试文本不落盘、不写日志。
func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Text    string   `json:"text"`
		RuleIDs []string `json:"ruleIds"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Text) > 20000 {
		writeErr(w, http.StatusRequestEntityTooLarge, "测试文本不能超过 20,000 字符")
		return
	}
	var rules []*store.Rule
	s.St.Read(func(d *store.Data) {
		for _, ru := range d.Rules {
			if (len(req.RuleIDs) == 0 && ru.Enabled) || validKey(ru.ID, req.RuleIDs) {
				cp := *ru
				rules = append(rules, &cp)
			}
		}
	})
	writeJSON(w, http.StatusOK, map[string]any{"matches": FindMatches(req.Text, rules)})
}
