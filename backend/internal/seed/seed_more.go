package seed

import (
	"fmt"
	"slices"

	"opendlp/internal/auth"
	"opendlp/internal/store"
)

var Level = map[string]string{"finance": "机密", "source": "机密", "customer": "机密", "idcard": "机密", "design": "秘密", "contract": "秘密", "bankcard": "机密", "phone": "内部"}

func seedApprovals(d *store.Data, r *Rand, now int64) {
	cases := [][3]string{
		{"finance", "向会计师事务所提交 Q3 审计资料", "audit@ey-partner.example"},
		{"design", "外包工厂需要结构图纸用于打样", "pm@factory-sz.example"},
		{"contract", "律所审核战略合作协议条款", "counsel@kinglaw.example"},
		{"source", "与合作方联调支付接口 SDK", "dev@partner-tech.cn"},
		{"customer", "向渠道商同步华东区重点客户名单", "sales@channel-hz.example"},
		{"idcard", "向社保代理机构报送员工参保信息", "hr@social-agent.example"},
		{"finance", "向银行提交授信申请所需财务报表", "credit@bank.example"},
		{"design", "向新加坡子公司同步新品外观设计", "design@corp-sg.example"},
		{"contract", "投标文件提交至招标代理平台", "bid-portal.example.cn"},
	}
	core := d.Employees[:16]
	for i := 0; i < 28; i++ {
		c, u := Pick(r, cases), Pick(r, core)
		pending := i < 10
		ts := now - int64(r.Int(8, 300))*hourMs
		if pending {
			ts = now - int64(r.Int(4, 420))*minMs
		}
		urgent := r.F() < 0.3
		dl := int64(24)
		if urgent {
			dl = 4
		}
		ch := Pick(r, []string{"email", "email", "usb", "cloud"})
		if c[0] == "source" || c[0] == "design" {
			ch = Pick(r, []string{"email", "web"})
		}
		a := &store.Approval{ID: fmt.Sprintf("APV-%d", 3860-i), TS: ts, User: u.Name, Dept: u.Dept, Leader: d.DeptLeaders[u.Dept],
			File: Pick(r, Files[c[0]]), DataType: c[0], Level: Level[c[0]], Size: fmt.Sprintf("%.1f MB", r.F()*30+0.4),
			Channel: ch, To: c[2], Reason: c[1], Urgent: urgent, Deadline: ts + dl*hourMs, Matches: r.Int(4, 420), Risk: r.Int(38, 92), Stage: 3}
		if pending {
			a.Status = "pending"
			a.Stage = 1
			if r.F() < 0.65 {
				a.Stage = 2
			}
		} else {
			a.Status = weighted(r, wv{"approved", 7}, wv{"rejected", 2}, wv{"expired", 1})
			a.DecidedAt = ts + int64(r.Int(20, 120))*minMs
			switch a.Status {
			case "approved":
				a.Approver, a.Comment = "李华", "业务需要，同意加密外发"
				a.Conditions = &store.ReleaseOptions{Encrypt: true, Watermark: true, ExpireDays: 7, MaxOpens: 10}
			case "rejected":
				a.Stage = Pick(r, []int{1, 2})
				a.Approver, a.Comment = "李华", "接收方不在合作伙伴白名单内，请补充 NDA 后重新申请"
				if a.Stage == 1 {
					a.Approver = a.Leader
				}
			case "expired":
				a.Stage = 1
			}
		}
		d.Approvals = append(d.Approvals, a)
	}
	d.Seq["approval"] = 3860
}

type ruleDef struct {
	name, cat, typ string
	cfg            map[string]any
	desc           string
}

// 正则均采用 RE2 语法（检测引擎使用 Go regexp），以 \b 代替前后断言。
var ruleDefs = []ruleDef{
	{"中国居民身份证号", "pii", "regex", map[string]any{"src": `\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`, "check": "idcard"}, "18 位身份证号，校验出生日期合法性与 GB 11643 校验位"},
	{"手机号码", "pii", "regex", map[string]any{"src": `\b1[3-9]\d{9}\b`}, "中国大陆 11 位手机号码，排除更长数字串中的误匹配"},
	{"电子邮箱地址", "pii", "regex", map[string]any{"src": `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`}, "标准 RFC 5322 邮箱格式"},
	{"护照号码", "pii", "regex", map[string]any{"src": `\b[EeGg]\d{8}\b`}, "中国因私 / 电子护照号码"},
	{"银行卡号", "fin", "regex", map[string]any{"src": `\b(?:62|4\d|5[1-5])\d{14,17}\b`, "check": "luhn"}, "银联 / Visa / MasterCard 卡号，Luhn 算法校验"},
	{"统一社会信用代码", "fin", "regex", map[string]any{"src": `\b[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}\b`}, "GB 32100 法人和其他组织统一社会信用代码"},
	{"财务敏感词典", "fin", "keyword", map[string]any{"words": []any{"营业收入", "净利润", "资产负债表", "现金流量表", "预算草案", "审计底稿", "毛利率"}}, "财务报表与预算类文档的高频专有词汇"},
	{"AWS Access Key", "cred", "regex", map[string]any{"src": `AKIA[0-9A-Z]{16}`}, "AWS IAM 访问密钥 ID"},
	{"私钥文件", "cred", "regex", map[string]any{"src": `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`}, "PEM 格式 RSA / EC / OpenSSH 私钥"},
	{"数据库连接串", "cred", "regex", map[string]any{"src": `(?:mysql|postgres(?:ql)?|mongodb|redis|jdbc:[a-z]+)://[^\s，。]+`}, "含账号口令的数据库连接 URI"},
	{"内网 IP 地址", "cred", "regex", map[string]any{"src": `\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b`}, "RFC 1918 私有网段地址，用于识别网络拓扑外泄"},
	{"密级标识关键词", "corp", "keyword", map[string]any{"words": []any{"绝密", "机密", "秘密", "内部资料", "未经授权不得外传", "仅限内部使用"}}, "文档页眉页脚中的密级标识"},
	{"源代码特征", "corp", "keyword", map[string]any{"words": []any{"private static", "import java", "def __init__", "#include", "SECRET_KEY", "package main"}}, "常见编程语言的语法特征词（区分大小写的子串匹配）"},
	{"工程图纸文件类型", "corp", "file", map[string]any{"exts": []any{".dwg", ".dxf", ".step", ".igs", ".fig", ".psd"}}, "按文件扩展名识别（改后缀可绕过）"},
}

func seedRules(d *store.Data, now int64) {
	for i, x := range ruleDefs {
		d.Rules = append(d.Rules, &store.Rule{ID: fmt.Sprintf("R-%d", 101+i), Name: x.name, Cat: x.cat, Type: x.typ, DataType: ruleDataType[x.name], Cfg: x.cfg, Desc: x.desc,
			Builtin: true, Enabled: x.typ == "regex" || x.typ == "keyword" || x.typ == "file", Updated: now})
	}
	d.Seq["rule"] = 100 + len(ruleDefs)
}

var (
	sysMods  = []string{"iam", "ops", "settings"}
	roleMods = map[string][]string{
		"sysadmin": {"dashboard", "endpoints", "iam", "ops", "settings"},
		"secadmin": {"dashboard", "incidents", "ueba", "policies", "rules", "discovery", "approvals", "endpoints", "reports"},
		"auditor":  {"dashboard", "reports", "audit"},
		"analyst":  {"dashboard", "incidents", "ueba", "discovery", "reports"},
		"owner":    {"dashboard", "incidents", "approvals", "reports"},
	}
)

// DefaultMatrix 内置角色的默认权限矩阵（三员分立）。
func DefaultMatrix(role string) store.Matrix {
	m := store.Matrix{}
	for _, k := range store.Modules {
		v := role == "super" || slices.Contains(roleMods[role], k)
		m[k] = store.Ops{
			View: v,
			Op:   v && role != "auditor" && k != "dashboard" && k != "audit",
			Cfg:  v && (role == "super" || (role == "sysadmin" && slices.Contains(sysMods, k)) || (role == "secadmin" && slices.Contains([]string{"policies", "rules", "approvals"}, k))),
			Exp:  v && k != "settings" && role != "owner",
		}
	}
	if role == "auditor" { // 审计员可导出审计日志
		m["audit"] = store.Ops{View: true, Exp: true}
	}
	return m
}

func seedRoles(d *store.Data) {
	d.Roles = []*store.Role{
		{Key: "super", Name: "超级管理员", Desc: "演示用全局角色，生产环境建议禁用", Builtin: true, Color: "danger"},
		{Key: "sysadmin", Name: "系统管理员", Desc: "负责系统配置、终端部署、组织架构与集成运维", Builtin: true, Color: "primary"},
		{Key: "secadmin", Name: "安全管理员", Desc: "负责策略制定、事件研判处置与外发审批", Builtin: true, Color: "warning"},
		{Key: "auditor", Name: "审计管理员", Desc: "负责审计系统管理员与安全管理员的全部操作", Builtin: true, Color: "purple"},
		{Key: "analyst", Name: "安全分析师", Desc: "一线事件研判，无策略修改权限", Color: "info"},
		{Key: "owner", Name: "部门数据负责人", Desc: "仅查看与审批本部门的事件与外发申请", Color: "success"},
	}
	d.Perms = map[string]store.Matrix{}
	for _, ro := range d.Roles {
		d.Perms[ro.Key] = DefaultMatrix(ro.Key)
	}
}

func seedAdmins(d *store.Data, r *Rand, now int64, pw string) error {
	admins := []struct {
		acc, name, role string
		mfa             bool
		ip              string
	}{
		{"admin", "安全管理员", "super", true, "10.0.8.21"}, {"sys_zhou", "周建国", "sysadmin", true, "10.0.8.32"},
		{"sec_lihua", "李华", "secadmin", true, "10.0.8.45"}, {"sec_wangjun", "王军", "secadmin", true, "10.0.8.46"},
		{"audit_zhao", "赵琪", "auditor", true, "10.0.8.60"}, {"ana_chen", "陈思远", "analyst", false, "10.0.8.71"},
		{"ana_lin", "林佳琪", "analyst", true, "10.0.8.72"}, {"own_sun", "孙海燕", "owner", false, "10.15.2.18"},
	}
	for i, a := range admins {
		h, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		ad := &store.Admin{Acc: a.acc, Name: a.name, Role: a.role, MFA: a.mfa, IP: a.ip, Status: "active",
			Last: now - int64(r.Int(3, 3000))*minMs, Created: now - int64(r.Int(30, 900))*dayMs, PwdHash: h, TOTPSecret: auth.NewTOTPSecret(), PwdChanged: now}
		if i == 7 {
			ad.Status = "disabled"
		}
		d.Admins = append(d.Admins, ad)
	}
	return nil
}

func seedOps(d *store.Data, r *Rand, now int64) {
	// 演示数据不包含检测节点：本项目不提供检测引擎服务器或网关，该区域只显示第三方系统通过 /api/v1/ingest/nodes 上报的心跳
	// 演示环境：部分集成已配置
	cfgs := map[string]map[string]string{
		"siem":  {"Syslog 地址": "10.0.2.15", "端口": "514", "格式": "CEF"},
		"wecom": {"Webhook 地址": "https://webhook.corp.example/cgi-bin/webhook/send?key=demo"},
	}
	info := map[string]string{"siem": "10.0.2.15:514 · CEF 格式（演示）", "wecom": "群机器人「数据安全响应」· 告警推送（演示）"}
	for _, it := range d.Integrations {
		if c, ok := cfgs[it.Key]; ok {
			it.Config, it.Info, it.St = c, info[it.Key], "ok"
			if it.Key == "proxy" {
				it.St = "warn"
			}
		}
	}
	d.ReportSchedules = []*store.Schedule{
		{ID: "RS-01", Name: "数据安全月报", Tpl: "monthly", Cron: "每月 1 日 08:00", To: []string{"ciso@corp.example", "compliance@corp.example"}, Fmt: "HTML", On: true, Next: now + 22*dayMs},
		{ID: "RS-02", Name: "事件处置周报", Tpl: "weekly", Cron: "每周一 09:00", To: []string{"soc@corp.example"}, Fmt: "HTML", On: true, Next: now + dayMs},
		{ID: "RS-03", Name: "部门风险排名", Tpl: "dept", Cron: "每月 5 日 10:00", To: []string{"dept-heads@corp.example"}, Fmt: "CSV", On: true, Next: now + 26*dayMs},
		{ID: "RS-04", Name: "管理层简报", Tpl: "exec", Cron: "每季度首日 09:00", To: []string{"ceo@corp.example", "cio@corp.example"}, Fmt: "HTML", On: false, Next: now + 53*dayMs},
	}
	d.Seq["schedule"] = 4
	hist := [][4]string{{"数据安全月报（2026 年 10 月）", "monthly", "HTML", "定时任务"}, {"事件处置周报（第 45 周）", "weekly", "HTML", "定时任务"}, {"事件处置周报（第 44 周）", "weekly", "HTML", "定时任务"},
		{"10 月部门风险排名", "dept", "CSV", "定时任务"}}
	t := now - 2*dayMs
	for i, h := range hist {
		d.Reports = append(d.Reports, &store.Report{ID: fmt.Sprintf("RPT-%d", 720-i), Name: h[0], Tpl: h[1], Fmt: h[2], By: h[3], TS: t, From: t - 30*dayMs, To: t, Size: fmt.Sprintf("%d KB", r.Int(40, 380))})
		t -= int64(r.Int(2, 7)) * dayMs
	}
	d.Seq["report"] = 720
}

func demoAudits(d *store.Data, r *Rand, now int64, incidents []*store.Incident) []store.AuditEntry {
	ops := [][2]string{{"admin", "超级管理员"}, {"sec_lihua", "安全管理员"}, {"sec_wangjun", "安全管理员"}, {"audit_zhao", "审计管理员"}, {"sys_zhou", "系统管理员"}}
	types := []string{"策略变更", "事件处置", "登录", "终端操作", "数据导出", "配置变更", "白名单"}
	var list []store.AuditEntry
	t := now - 4*minMs
	for i := 0; i < 120; i++ {
		op := Pick(r, ops)
		typ := Pick(r, types)
		var detail string
		switch typ {
		case "策略变更":
			detail = fmt.Sprintf("%s策略「%s」", Pick(r, []string{"更新", "启用", "停用"}), Pick(r, d.Policies).Name)
		case "事件处置":
			detail = fmt.Sprintf("将事件 %s 标记为%s", Pick(r, incidents).ID, Pick(r, []string{"已处置", "误报", "处置中"}))
		case "登录":
			detail = fmt.Sprintf("登录管理控制台（%s）", Pick(r, []string{"口令 + TOTP", "SSO 单点登录", "企业微信扫码"}))
		case "终端操作":
			detail = fmt.Sprintf("向 %s %s", Pick(r, d.Endpoints).Host, Pick(r, []string{"推送策略", "发起远程扫描", "升级 Agent 至 3.2.1"}))
		case "数据导出":
			detail = fmt.Sprintf("导出%s（%s）", Pick(r, []string{"事件报表", "审计日志", "终端清单", "合规月报"}), Pick(r, []string{"CSV", "HTML"}))
		case "配置变更":
			detail = Pick(r, []string{"修改告警通知渠道", "调整检测引擎灵敏度为 75", "更新合规模板 PIPL", "修改日志保留周期为 180 天"})
		default:
			detail = fmt.Sprintf("添加白名单：文件指纹 %08x…", uint32(r.F()*4294967295))
		}
		ok := r.F() >= 0.08
		reason := ""
		if !ok {
			reason = Pick(r, []string{"权限不足", "会话已过期", "参数校验失败"})
		}
		list = append(list, store.AuditEntry{TS: t, Op: op[0], Role: op[1], Type: typ, Detail: detail, IP: fmt.Sprintf("10.0.8.%d", r.Int(10, 90)), OK: ok, Reason: reason})
		t -= int64(r.Int(4, 140)) * minMs
	}
	out := make([]store.AuditEntry, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- { // 从最早到最新接入哈希链
		out = append(out, list[i])
	}
	return out
}

// baseIntegrations 支持的第三方集成清单（初始均未配置）。
func baseIntegrations() []*store.Integration {
	return []*store.Integration{
		{Key: "siem", Name: "SIEM / Syslog", Cat: "安全运营", Icon: "activity", St: "off", Info: "未配置"},
		{Key: "smtp", Name: "告警邮件 (SMTP)", Cat: "通知协同", Icon: "mail", St: "off", Info: "未配置，用于告警与定时报表邮件"},
		{Key: "wecom", Name: "企业微信群机器人", Cat: "通知协同", Icon: "message", St: "off", Info: "未配置"},
		{Key: "ding", Name: "钉钉机器人", Cat: "通知协同", Icon: "message", St: "off", Info: "未配置"},
		{Key: "ai", Name: "AI 大模型", Cat: "智能分析", Icon: "wand", St: "off", Info: "未配置，支持 DeepSeek、通义千问等 OpenAI 兼容接口及本地部署模型"},
	}
}

// ruleDataType 内置规则命中后计入的敏感数据类型（与策略的数据类型对应；空表示仅提示）。
var ruleDataType = map[string]string{
	"中国居民身份证号":       "idcard",
	"手机号码":           "phone",
	"电子邮箱地址":         "",
	"护照号码":           "idcard",
	"员工花名册 (HR)":     "idcard",
	"简历识别模型":         "",
	"银行卡号":           "bankcard",
	"统一社会信用代码":       "",
	"财务敏感词典":         "finance",
	"AWS Access Key": "source",
	"私钥文件":           "source",
	"数据库连接串":         "source",
	"内网 IP 地址":       "",
	"密级标识关键词":        "contract",
	"源代码特征":          "source",
	"客户主数据 (CRM)":    "customer",
	"核心产品设计文档":       "design",
	"战略合同模板":         "contract",
	"源代码分类模型":        "source",
	"工程图纸文件类型":       "design",
}

// Upgrade 启动时的数据升级（须在写锁内调用）：补齐新增集成项、移除未实现的集成与规则类型、修复重复终端编号。
func Upgrade(d *store.Data) {
	EnsureIntegrations(d)
	keep := map[string]bool{}
	for _, b := range baseIntegrations() {
		keep[b.Key] = true
	}
	ints := d.Integrations[:0]
	for _, it := range d.Integrations {
		if keep[it.Key] {
			ints = append(ints, it)
		}
	}
	d.Integrations = ints
	rules := d.Rules[:0]
	for _, r := range d.Rules {
		if !(r.Builtin && (r.Type == "edm" || r.Type == "idm" || r.Type == "ml")) {
			rules = append(rules, r)
		}
	}
	d.Rules = rules
	for _, k := range []string{"ocr", "edm", "fp", "ml", "sens", "comp", "evi", "mask", "ret2", "ruleVersion", "apvAutoWhitelist", "apvDelegate"} {
		delete(d.Settings, k)
	}
	store.RepairEndpointIDs(d)
}

// EnsureIntegrations 为旧版本数据补齐新增的集成项（须在写锁内调用）。
func EnsureIntegrations(d *store.Data) {
	for _, base := range baseIntegrations() {
		found := false
		for _, it := range d.Integrations {
			found = found || it.Key == base.Key
		}
		if !found {
			d.Integrations = append(d.Integrations, base)
		}
	}
}
