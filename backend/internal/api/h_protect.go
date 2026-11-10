package api

import (
	"fmt"

	"net/http"
	"opendlp/internal/detect"
	"opendlp/internal/seed"
	"regexp"
	"strings"
	"time"

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
	DataType string         `json:"dataType"`
	Name     string         `json:"name"`
	Cat      string         `json:"cat"`
	Type     string         `json:"type"`
	Cfg      map[string]any `json:"cfg"`
	Desc     string         `json:"desc"`
}

func (s *Server) handleRuleCreate(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req ruleReq
	if !readJSON(w, r, &req) {
		return
	}
	cfg, msg := normalizeRule(req.Name, req.Cat, req.Type, req.Cfg)
	if msg == "" && !s.validDataType(req.DataType) {
		msg = "数据类型无效"
	}
	if msg != "" {
		writeErr(w, http.StatusUnprocessableEntity, msg)
		return
	}
	s.mutate(w, func(d *store.Data) (int, any) {
		ru := &store.Rule{ID: fmt.Sprintf("R-%d", 100+store.NextSeq(d, "rule")), Name: strings.TrimSpace(req.Name), Cat: req.Cat, Type: req.Type, DataType: req.DataType, Cfg: cfg,
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
	if msg == "" && !s.validDataType(req.DataType) {
		msg = "数据类型无效"
	}
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
		ru.Name, ru.Cat, ru.Type, ru.DataType, ru.Cfg, ru.Updated = strings.TrimSpace(req.Name), req.Cat, req.Type, req.DataType, cfg, time.Now().UnixMilli()
		s.auditIn(d, a, "规则变更", fmt.Sprintf("修改识别规则「%s」（%s）", ru.Name, ru.ID), true, "")
		return http.StatusOK, ru
	})
}

// PATCH /api/v1/rules/{id} {enabled}
func (s *Server) handleRulePatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Enabled *bool `json:"enabled"`
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
		ru.Updated = time.Now().UnixMilli()
		return http.StatusOK, ru
	})
}

/* ---------- 规则测试（与检测引擎同一套 RE2 实现） ---------- */

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
	var rules []detect.Rule
	s.St.Read(func(d *store.Data) {
		for _, ru := range d.Rules {
			if (len(req.RuleIDs) == 0 && ru.Enabled) || validKey(ru.ID, req.RuleIDs) {
				rules = append(rules, detectRule(ru))
			}
		}
	})
	writeJSON(w, http.StatusOK, map[string]any{"matches": detect.New(rules, nil).Scan(req.Text)})
}

// validDataType 空值（仅提示）或已定义的数据类型。
func (s *Server) validDataType(k string) bool {
	if k == "" {
		return true
	}
	ok := false
	s.St.Read(func(d *store.Data) {
		for _, t := range d.DataTypes {
			ok = ok || t.Key == k
		}
	})
	return ok
}

func detectRule(r *store.Rule) detect.Rule {
	return detect.Rule{ID: r.ID, Name: r.Name, Cat: r.Cat, Type: r.Type, DataType: r.DataType, Cfg: r.Cfg}
}
