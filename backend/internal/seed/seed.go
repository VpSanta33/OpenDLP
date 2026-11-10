// Package seed 提供首次启动所需的基础数据（渠道、数据类型、内置角色与规则等），
// 以及仅在 -demo 模式下写入的演示数据与事件生成器。
package seed

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"opendlp/internal/store"
)

// Rand mulberry32 伪随机数，保证每次初始化数据一致。
type Rand struct{ s uint32 }

func NewRand(seed uint32) *Rand { return &Rand{s: seed} }

func (r *Rand) F() float64 {
	r.s += 0x6D2B79F5
	t := r.s
	t = (t ^ t>>15) * (1 | t)
	t = (t + (t^t>>7)*(61|t)) ^ t
	return float64(t^t>>14) / 4294967296
}
func (r *Rand) Int(a, b int) int   { return a + int(r.F()*float64(b-a+1)) }
func Pick[T any](r *Rand, a []T) T { return a[int(r.F()*float64(len(a)))] }

type wv struct {
	v string
	w float64
}

func weighted(r *Rand, list ...wv) string {
	t := 0.0
	for _, x := range list {
		t += x.w
	}
	x := r.F() * t
	for _, it := range list {
		x -= it.w
		if x <= 0 {
			return it.v
		}
	}
	return list[len(list)-1].v
}

const (
	minMs  = int64(time.Minute / time.Millisecond)
	hourMs = int64(time.Hour / time.Millisecond)
	dayMs  = 24 * hourMs
)

var deptCode = map[string]string{"研发中心": "RD", "财务部": "FIN", "销售部": "SAL", "人力资源": "HR", "法务合规": "LGL", "市场部": "MKT", "供应链": "SCM", "客户服务": "CS"}
var Depts = []string{"研发中心", "财务部", "销售部", "人力资源", "法务合规", "市场部", "供应链", "客户服务"}

var Files = map[string][]string{
	"idcard":   {"员工信息表.xlsx", "入职材料汇总.zip", "社保参保名单_2026.xlsx"},
	"bankcard": {"工资发放明细_10月.xlsx", "供应商付款信息.csv"},
	"customer": {"客户名单_华东区.csv", "CRM导出_1109.xlsx", "重点客户联系人.docx"},
	"source":   {"core-engine-src.zip", "payment-service.tar.gz", "risk_model_v3.py"},
	"finance":  {"2026Q3_财务报表_终版.xlsx", "2027年度预算草案.xlsx", "审计底稿.pdf"},
	"contract": {"采购合同_盖章版.pdf", "战略合作框架协议.docx", "投标方案_最终版.docx"},
	"design":   {"产品设计稿_v4.fig", "结构图纸_A3.dwg", "新品外观渲染.psd"},
	"phone":    {"活动报名名单.xlsx", "用户回访记录.csv"},
}

func deptIndex(d string) int {
	for i, x := range Depts {
		if x == d {
			return i
		}
	}
	return 0
}
func mkHost(r *Rand, dept string) string {
	return fmt.Sprintf("%s-%s-%04d", Pick(r, []string{"BJ", "SH", "SZ", "HZ"}), deptCode[dept], r.Int(10, 980))
}
func mkIP(r *Rand, dept string) string {
	return fmt.Sprintf("10.%d.%d.%d", 10+deptIndex(dept), r.Int(1, 8), r.Int(20, 240))
}

// NewIncident 生成一条 DLP 事件（须在 Write 内调用，会分配事件编号）。
func NewIncident(d *store.Data, r *Rand, id string, ts int64, live bool, now int64) *store.Incident {
	core := []*store.Employee{}
	for _, e := range d.Employees {
		if e.Core {
			core = append(core, e)
		}
	}
	if len(core) == 0 || len(d.Policies) == 0 {
		return nil
	}
	u := Pick(r, core)
	ch := Pick(r, d.Channels)
	var cands []*store.Policy
	for _, p := range d.Policies {
		for _, c := range p.Channels {
			if c == ch.Key {
				cands = append(cands, p)
				break
			}
		}
	}
	pol := d.Policies[0]
	if len(cands) > 0 {
		pol = Pick(r, cands)
	}
	dtKey := Pick(r, pol.DataTypes)
	sev := weighted(r, wv{pol.Severity, 5}, wv{"critical", 1}, wv{"high", 2}, wv{"medium", 3}, wv{"low", 3})
	var action string
	if pol.Action == "block" {
		action = weighted(r, wv{"block", 8}, wv{"audit", 2})
	} else {
		action = weighted(r, wv{pol.Action, 6}, wv{"allow", 2}, wv{"audit", 1})
	}
	age := now - ts
	var status string
	switch {
	case live:
		status = "pending"
	case age < 2*hourMs:
		status = weighted(r, wv{"pending", 6}, wv{"processing", 2}, wv{"resolved", 1})
	default:
		status = weighted(r, wv{"pending", 2}, wv{"processing", 2}, wv{"resolved", 6}, wv{"fp", 1})
	}
	inc := &store.Incident{
		ID: id, TS: ts,
		User: u.Name, Dept: u.Dept, Host: u.Host, IP: u.IP,
		Channel: ch.Key, Dest: Pick(r, ch.Dest), DataType: dtKey, File: Pick(r, Files[dtKey]),
		Size: fmt.Sprintf("%.1f MB", r.F()*48+0.2), Matches: r.Int(3, 860),
		Severity: sev, Action: action, Status: status, Policy: pol.Name, PolicyID: pol.ID,
	}
	if status == "resolved" || status == "fp" {
		inc.Closed = ts + int64(r.Int(20, 600))*minMs
		inc.Handler = Pick(r, []string{"李华", "王军", "林佳琪"})
	}
	return inc
}

var chWeight = []wv{{"email", 3820}, {"usb", 2410}, {"cloud", 1980}, {"im", 2960}, {"web", 1460}, {"print", 640}}
var dtWeight = []wv{{"idcard", 2840}, {"customer", 2210}, {"source", 1680}, {"finance", 1420}, {"phone", 1260}, {"contract", 980}, {"bankcard", 760}, {"design", 540}}

// RandomDetection 返回一次检测的渠道、数据类型与响应动作（按全网分布加权）。
func RandomDetection(r *Rand) (ch, dt, action string) {
	return weighted(r, chWeight...), weighted(r, dtWeight...),
		weighted(r, wv{"allow", 58}, wv{"audit", 20}, wv{"encrypt", 13}, wv{"block", 9})
}

// Reference 生产环境首次启动的基础数据：渠道与数据类型字典、内置角色与权限、内置识别规则、
// 集成清单（均未配置）与默认设置。组织、终端、策略等业务数据为空，由管理员配置或终端上报产生。
func Reference(nowT time.Time) *store.Data {
	now := nowT.UnixMilli()
	d := &store.Data{Seq: map[string]int{}, Depts: []string{}, DeptLeaders: map[string]string{}, Employees: []*store.Employee{},
		Policies: []*store.Policy{}, Endpoints: []*store.Endpoint{}, Commands: []*store.Command{}, Repos: []*store.Repo{}, Notes: []*store.Note{},
		Approvals: []*store.Approval{}, Admins: []*store.Admin{}, Nodes: []*store.Node{}, ReportSchedules: []*store.Schedule{}, Reports: []*store.Report{}, Watchlist: []string{}}
	d.Channels = []store.Channel{
		{Key: "email", Name: "邮件外发", Icon: "mail", Dest: []string{"外部邮箱 @gmail.com", "外部邮箱 @163.com", "合作方 @partner-tech.cn"}},
		{Key: "usb", Name: "USB 存储", Icon: "usb", Dest: []string{"SanDisk Ultra (E:)", "Kingston DT 64G (F:)", "移动硬盘 WD (G:)"}},
		{Key: "cloud", Name: "云盘上传", Icon: "cloud", Dest: []string{"百度网盘", "阿里云盘", "Dropbox"}},
		{Key: "im", Name: "即时通讯", Icon: "message", Dest: []string{"微信 PC 版", "QQ", "Telegram Desktop"}},
		{Key: "web", Name: "Web 上传", Icon: "globe", Dest: []string{"github.com", "transfer.sh", "pastebin.com"}},
		{Key: "print", Name: "打印输出", Icon: "printer", Dest: []string{"HP LaserJet 4F-01", "Canon iR-ADV 3F", "Brother HL 2F-HR"}},
	}
	d.DataTypes = []store.DataType{
		{Key: "idcard", Name: "身份证号", Sample: "110105********2316"},
		{Key: "bankcard", Name: "银行卡号", Sample: "6222 02** **** 8841"},
		{Key: "customer", Name: "客户名单", Sample: "华东**集团, 联系人 陈**, 138****5521"},
		{Key: "source", Name: "源代码", Sample: `private static final String SECRET_KEY = "********";`},
		{Key: "finance", Name: "财务报表", Sample: "营业收入 ¥3,2**,***,***  净利润率 1*.*%"},
		{Key: "contract", Name: "合同文件", Sample: "甲方：******科技有限公司  合同总金额 ¥***万"},
		{Key: "design", Name: "设计图纸", Sample: "图纸编号 DWG-2026-****  密级：机密"},
		{Key: "phone", Name: "手机号码", Sample: "139****0912, 186****3374, 152****8810"},
	}

	seedRoles(d)
	seedRules(d, now)
	d.Integrations = baseIntegrations()
	d.Settings = DefaultSettings()
	return d
}

// PolicyTemplates 内置合规策略模板（「合规模板」同步时以停用状态导入）。
func PolicyTemplates() []store.Policy {
	pols := []struct {
		name, desc string
		chs, dts   []string
		act, sev   string
	}{
		{"身份证号外发拦截", "邮件、IM、Web 渠道单次外发包含 10 个及以上有效身份证号时阻断", []string{"email", "im", "web"}, []string{"idcard"}, "block", "critical"},
		{"源代码防泄漏", "识别源代码特征关键词，经 Web、网盘或 U 盘外发时阻断", []string{"web", "cloud", "usb"}, []string{"source"}, "block", "critical"},
		{"财务报表加密外发", "财务类内容经邮件或 U 盘外发时要求加密放行（需网关支持加密；终端 Agent 按审计记录）", []string{"email", "usb"}, []string{"finance"}, "encrypt", "high"},
		{"客户数据批量导出告警", "单次外发命中客户名单或手机号 50 处及以上时生成事件", []string{"usb", "cloud", "email"}, []string{"customer", "phone"}, "audit", "high"},
		{"USB 存储设备管控", "拷贝到 U 盘的文件含身份证号、财务、源代码或设计图纸内容时隔离", []string{"usb"}, []string{"idcard", "finance", "source", "design"}, "block", "high"},
		{"云盘上传敏感内容检测", "网盘同步目录中出现合同、客户名单或设计图纸内容时生成事件", []string{"cloud"}, []string{"contract", "customer", "design"}, "audit", "medium"},
		{"打印内容审计", "打印渠道（由打印审计系统上报）中的合同与财务内容生成事件", []string{"print"}, []string{"contract", "finance"}, "audit", "medium"},
		{"IM 文件传输检测", "IM 文件目录中出现客户名单、合同或手机号内容时生成事件", []string{"im"}, []string{"customer", "contract", "phone"}, "audit", "medium"},
		{"高敏感数据外发阻断", "客户名单、源代码与合同内容经任一渠道外发时阻断", []string{"email", "usb", "cloud", "im", "web"}, []string{"customer", "source", "contract"}, "block", "critical"},
		{"设计图纸加密外发", "设计图纸经邮件或 Web 外发时要求加密放行（需网关支持加密）", []string{"email", "web"}, []string{"design"}, "encrypt", "high"},
		{"银行卡号外发拦截", "通过 Luhn 校验识别银行卡号，经邮件、Web、IM 或打印外发时阻断", []string{"email", "web", "im", "print"}, []string{"bankcard"}, "block", "high"},
		{"个人信息外发审计", "身份证号、手机号或银行卡号经邮件、Web 或网盘外发时生成事件", []string{"email", "web", "cloud"}, []string{"idcard", "phone", "bankcard"}, "audit", "low"},
	}
	out := make([]store.Policy, len(pols))
	for i, p := range pols {
		out[i] = store.Policy{Name: p.name, Desc: p.desc, Channels: p.chs, DataTypes: p.dts, Action: p.act, Severity: p.sev, Threshold: map[string]int{"身份证号外发拦截": 10, "客户数据批量导出告警": 50}[p.name]}
	}
	return out

}

// Demo 写入演示数据（仅 -demo 模式且数据库中尚无事件时调用）：组织、策略、终端、审批、管理员账号、
// 近 60 天检测量、近 30 天事件与审计日志。所有演示管理员使用 demoPassword。
func Demo(ctx context.Context, st *store.Store, nowT time.Time, demoPassword string) error {
	r := NewRand(20261109)
	now := nowT.UnixMilli()
	loc := st.Loc
	dets := map[store.DetectionKey]*store.DetectionCount{}
	var incidents []*store.Incident
	var audits []store.AuditEntry
	incSeq := 48000
	var err error
	st.Write(func(d *store.Data) {
		d.Depts = Depts
		/* 员工 */
		titles := map[string][]string{
			"研发中心": {"高级工程师", "架构师", "测试工程师", "研发经理", "算法工程师"}, "财务部": {"会计", "财务经理", "出纳", "税务专员"},
			"销售部": {"大客户经理", "销售总监", "销售代表", "售前顾问"}, "人力资源": {"HRBP", "招聘专员", "薪酬主管"},
			"法务合规": {"法务经理", "合规专员"}, "市场部": {"品牌经理", "市场专员", "设计师"},
			"供应链": {"采购经理", "物流专员", "供应商管理"}, "客户服务": {"客服主管", "客服专员", "技术支持"},
		}
		core := [][2]string{{"张伟", "研发中心"}, {"王芳", "财务部"}, {"李娜", "销售部"}, {"刘洋", "研发中心"}, {"陈静", "人力资源"}, {"杨磊", "销售部"}, {"赵敏", "市场部"}, {"黄晓明", "供应链"},
			{"周杰", "研发中心"}, {"吴婷", "法务合规"}, {"徐强", "客户服务"}, {"孙丽", "财务部"}, {"马超", "研发中心"}, {"朱琳", "销售部"}, {"胡斌", "市场部"}, {"郭鹏", "供应链"}}
		for i, c := range core {
			d.Employees = append(d.Employees, &store.Employee{ID: fmt.Sprintf("U%d", 1001+i), Name: c[0], Dept: c[1], Host: mkHost(r, c[1]), IP: mkIP(r, c[1]), Title: Pick(r, titles[c[1]]), Status: "active", Core: true})
		}
		d.Employees[12].Status, d.Employees[5].Status = "leaving", "leaving"
		sur := strings.Split("王李张刘陈杨黄赵吴周徐孙马朱胡郭何林高罗宋谢", "")
		giv := []string{"子涵", "雨轩", "浩然", "思远", "欣怡", "梓萱", "俊杰", "嘉懿", "明轩", "诗涵", "一鸣", "宇航", "若曦", "晨阳", "书瑶", "志强", "海燕", "文博", "佳琪", "天佑"}
		for len(d.Employees) < 84 {
			dept, name := Pick(r, Depts), Pick(r, sur)+Pick(r, giv)
			if d.Employee(name) != nil {
				continue
			}
			d.Employees = append(d.Employees, &store.Employee{ID: fmt.Sprintf("U%d", 1001+len(d.Employees)), Name: name, Dept: dept, Host: mkHost(r, dept), IP: mkIP(r, dept), Title: Pick(r, titles[dept]),
				Status: weighted(r, wv{"active", 30}, wv{"leaving", 1}, wv{"left", 1})})
		}
		for _, e := range d.Employees {
			e.Email = strings.ToLower(e.ID) + "@corp.example"
			e.Joined = now - int64(r.Int(60, 2600))*dayMs
		}
		d.DeptLeaders = map[string]string{"研发中心": "周建国", "财务部": "孙海燕", "销售部": "林志强", "人力资源": "何丽华", "法务合规": "高文博", "市场部": "罗晨阳", "供应链": "郭明轩", "客户服务": "徐书瑶"}

		for i, t := range PolicyTemplates() {
			p := t
			p.ID, p.Enabled, p.Hits = fmt.Sprintf("POL-%d", 101+i), i != 6 && i != 11, r.Int(120, 4800)
			p.Updated, p.Owner = now-int64(r.Int(1, 40))*dayMs-int64(r.Int(0, 23))*hourMs, Pick(r, []string{"李华", "王军", "安全管理员", "赵琪"})
			d.Policies = append(d.Policies, &p)
		}
		d.Seq["policy"] = len(d.Policies)

		/* 近 60 天检测量（按小时） */
		start := (now - 60*dayMs) - (now-60*dayMs)%hourMs
		for h := start; h <= now; h += hourMs {
			t := time.UnixMilli(h).In(loc)
			hr, wd := t.Hour(), t.Weekday()
			base := 6.0
			switch {
			case hr >= 9 && hr <= 18:
				base = 62 + 9*math.Sin(float64(hr))
			case hr >= 7 && hr <= 22:
				base = 26
			}
			if wd == time.Saturday || wd == time.Sunday {
				base *= 0.42
			}
			if (hr == 23 || hr <= 1) && (wd == time.Tuesday || wd == time.Thursday) {
				base += 14 // 深夜异常外发
			}
			n := int(base * (0.75 + r.F()*0.5))
			if h+hourMs > now { // 当前小时只生成已过去的部分
				n = n * int(now-h) / int(hourMs)
			}
			for k := 0; k < n; k++ {
				ch, dt, act := RandomDetection(r)
				k := store.DetectionKey{H: h, Ch: ch, DT: dt}
				if dets[k] == nil {
					dets[k] = &store.DetectionCount{}
				}
				dets[k].Add(act)
			}
		}

		/* 近 30 天事件 */
		var stamps []int64
		for t := now - 2*minMs; t > now-30*dayMs; t -= int64(r.Int(3, 95)) * minMs {
			stamps = append(stamps, t)
		}
		for i := len(stamps) - 1; i >= 0; i-- { // 从最早到最新分配编号
			incSeq++
			incidents = append(incidents, NewIncident(d, r, fmt.Sprintf("INC-%d", incSeq), stamps[i], false, now))
		}

		/* 样本终端 & 全网汇总 */
		osList := []struct {
			name, key, short string
			w                float64
		}{{"Windows 11 专业版", "win", "WIN", 10}, {"macOS 15 Sequoia", "mac", "MAC", 4}, {"统信 UOS 20", "uos", "UOS", 3}, {"银河麒麟 V10", "kylin", "KY", 2}}
		epUsers := append([]*store.Employee{}, d.Employees[:16]...)
		epUsers = append(epUsers, d.Employees[:8]...)
		for i, u := range epUsers {
			host, ip := u.Host, u.IP
			if i >= 16 {
				host, ip = mkHost(r, u.Dept), mkIP(r, u.Dept)
			}
			oi := 0
			{
				ws := []wv{}
				for k, o := range osList {
					ws = append(ws, wv{fmt.Sprint(k), o.w})
				}
				fmt.Sscan(weighted(r, ws...), &oi)
			}
			st := weighted(r, wv{"online", 16}, wv{"offline", 5}, wv{"warning", 3})
			ep := &store.Endpoint{ID: fmt.Sprintf("EP%d", i+1), Host: host, User: u.Name, Dept: u.Dept, IP: ip, OS: osList[oi].name, OSKey: osList[oi].key, OSShort: osList[oi].short,
				Status: st, Agent: weighted(r, wv{"3.2.1", 7}, wv{"3.2.0", 2}, wv{"3.1.8", 1}), Disk: r.Int(30, 92), LastSeen: now}
			if st != "offline" {
				ep.CPU, ep.Mem = r.Int(4, 88), r.Int(22, 86)
			} else {
				ep.LastSeen = now - int64(r.Int(20, 3000))*minMs
			}
			if st == "warning" {
				ep.LastSeen = now - int64(r.Int(20, 3000))*minMs
			}
			d.Endpoints = append(d.Endpoints, ep)
		}
		d.Seq["endpoint"] = len(d.Endpoints)
		d.Settings["licenseSeats"], d.Settings["licenseExpiry"], d.Settings["licenseNo"] = 3000.0, time.UnixMilli(now).AddDate(0, 8, 0).Format("2006-01-02"), "ODLP-DEMO-0001"

		/* 数据资产 */
		d.Repos = []*store.Repo{
			{Name: `\\fs01.corp\财务共享`, Type: "文件服务器", Icon: "folder", Total: 182340, Sens: 4821, Risk: 86, Last: now - 26*hourMs},
			{Name: "SharePoint · 研发知识库", Type: "协作平台", Icon: "layers", Total: 96512, Sens: 2210, Risk: 71, Last: now - 26*hourMs},
			{Name: "CRM 生产库 (MySQL)", Type: "数据库", Icon: "database", Total: 4386, Sens: 1290, Risk: 92, Last: now - 50*hourMs},
			{Name: "oss://corp-backup", Type: "对象存储", Icon: "cloud", Total: 328004, Sens: 3105, Risk: 64, Last: now - 3*dayMs},
			{Name: "Exchange 邮件归档", Type: "邮件系统", Icon: "mail", Total: 1204880, Sens: 6620, Risk: 58, Last: now - 26*hourMs},
			{Name: "终端文档目录（2,318 台）", Type: "终端", Icon: "monitor", Total: 3820415, Sens: 12940, Risk: 47, Last: now - 5*hourMs},
		}
		for _, rp := range d.Repos { // 演示：按敏感对象数推算分级分布
			rp.Levels = map[string]int{"绝密": rp.Sens / 25, "机密": rp.Sens / 3, "内部": rp.Sens * 2, "公开": rp.Total / 8}
		}

		/* 通知 */
		note := func(typ, title, text string, ago int64, unread bool, href string) {
			d.Notes = append(d.Notes, &store.Note{ID: fmt.Sprintf("N%d", store.NextSeq(d, "note")), Type: typ, Title: title, Text: text, TS: now - ago, Unread: unread, Href: href})
		}
		note("danger", "严重事件", "马超 尝试通过 USB 外发 core-engine-src.zip（源代码），已阻断", 6*minMs, true, "#/incidents?sev=critical")
		note("warning", "策略命中激增", "「客户数据批量导出告警」1 小时内命中 128 次，环比 +320%", 38*minMs, true, "#/policies")
		note("warning", "终端防护异常", "3 台终端 Agent 心跳丢失超过 30 分钟，请排查", 2*hourMs, true, "#/endpoints")
		note("success", "扫描完成", "全量敏感数据发现任务完成，新增敏感文件 1,204 个", 26*hourMs, false, "#/discovery")
		note("info", "合规报告", "《2026 年 10 月数据安全合规月报》已生成，可前往下载", 2*dayMs, false, "#/reports")

		seedApprovals(d, r, now)
		for _, ru := range d.Rules {
			ru.Hits, ru.FP = r.Int(80, 26000), float64(int(r.F()*30))/10
		}
		if err = seedAdmins(d, r, now, demoPassword); err != nil {
			return
		}
		seedOps(d, r, now)
		audits = demoAudits(d, r, now, incidents)
		d.Watchlist = []string{"马超", "杨磊"}
	})
	if err != nil {
		return err
	}
	if err := st.CopyIncidents(ctx, incidents); err != nil {
		return fmt.Errorf("写入演示事件失败: %w", err)
	}
	if err := st.SetIncidentSeq(ctx, int64(incSeq)); err != nil {
		return err
	}
	if err := st.CopyDetections(ctx, dets); err != nil {
		return fmt.Errorf("写入演示检测量失败: %w", err)
	}
	for _, e := range audits {
		if err := st.AppendAudit(ctx, e); err != nil {
			return err
		}
	}
	return st.Save(ctx)
}

// DefaultSettings 系统设置默认值（键与前端设置页 data-k 一致）。
func DefaultSettings() map[string]any {
	return map[string]any{
		"mail": true, "wecom": true, "ding": false, "siem": true, "freq": "每 15 分钟", "ret1": "365 天",
	}
}
