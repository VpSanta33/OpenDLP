package api

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"opendlp/internal/store"
)

func TestPasswordChangeAndExpiry(t *testing.T) {
	s, ts := newTestServer(t, true)
	admin := newClient(t, ts)
	admin.login(s, "admin")

	// 新建管理员：初始口令只返回一次，首次登录须修改
	code, out := admin.do("POST", "/api/v1/admins", `{"acc":"ops_new","name":"新运维","role":"analyst","allow":["127.0.0.1"," 10.1.0.0/16 "]}`, true)
	if code != http.StatusCreated {
		t.Fatalf("新建管理员失败：%d %v", code, out)
	}
	initPW := out["initialPassword"].(string)
	if v := out["admin"].(map[string]any); v["mustChange"] != true || len(v["allow"].([]any)) != 2 {
		t.Fatalf("新建管理员应标记首次改密并保存来源限制：%v", v)
	}
	// 不让测试依赖 TOTP：关闭该账号 MFA
	s.St.Write(func(d *store.Data) { d.Admin("ops_new").MFA = false })

	u := newClient(t, ts)
	code, out = u.do("POST", "/api/v1/auth/login", `{"account":"ops_new","password":"`+initPW+`"}`, true)
	if code != 200 || out["pwdChange"] == "" || out["pwdChange"] == nil {
		t.Fatalf("初始口令登录应提示修改口令：%d %v", code, out)
	}
	if code, out := u.do("GET", "/api/v1/bootstrap", "", false); code != http.StatusForbidden || out["code"] != "pwd_change" {
		t.Fatalf("修改口令前不应访问业务接口：%d %v", code, out)
	}
	if code, me := u.do("GET", "/api/v1/auth/me", "", false); code != 200 || me["pwdChange"] == "" {
		t.Fatalf("/auth/me 应可访问并返回改密原因：%d %v", code, me)
	}
	if code, _ := u.do("POST", "/api/v1/auth/password", `{"old":"wrong","new":"Another-Pass-2026!"}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("当前口令错误应拒绝：%d", code)
	}
	if code, _ := u.do("POST", "/api/v1/auth/password", `{"old":"`+initPW+`","new":"short"}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("弱口令应拒绝：%d", code)
	}
	if code, _ := u.do("POST", "/api/v1/auth/password", `{"old":"`+initPW+`","new":"Ops_New-Pass-2026!"}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("包含账号名的口令应拒绝：%d", code)
	}
	// 另一个会话在改密后应失效
	other := newClient(t, ts)
	other.do("POST", "/api/v1/auth/login", `{"account":"ops_new","password":"`+initPW+`"}`, true)
	if code, out := u.do("POST", "/api/v1/auth/password", `{"old":"`+initPW+`","new":"Another-Pass-2026!"}`, true); code != 200 {
		t.Fatalf("修改口令失败：%d %v", code, out)
	}
	if code, _ := u.do("GET", "/api/v1/bootstrap", "", false); code != 200 {
		t.Fatalf("改密后当前浏览器应继续可用：%d", code)
	}
	if code, _ := other.do("GET", "/api/v1/auth/me", "", false); code != http.StatusUnauthorized {
		t.Fatalf("改密后其他会话应失效：%d", code)
	}

	// 口令有效期：超过「口令有效期」后同样要求修改；设为 0 则不过期
	s.St.Write(func(d *store.Data) { d.Admin("ops_new").PwdChanged = time.Now().AddDate(0, 0, -91).UnixMilli() })
	if code, out := u.do("GET", "/api/v1/bootstrap", "", false); code != http.StatusForbidden || !strings.Contains(out["error"].(string), "90") {
		t.Fatalf("口令过期应要求修改：%d %v", code, out)
	}
	if code, _ := admin.do("PUT", "/api/v1/settings", `{"pwdMaxAge":7}`, true); code == 200 {
		t.Fatal("口令有效期只允许预设值")
	}
	admin.do("PUT", "/api/v1/settings", `{"pwdMaxAge":0}`, true)
	if code, _ := u.do("GET", "/api/v1/bootstrap", "", false); code != 200 {
		t.Fatalf("关闭口令有效期后应可访问：%d", code)
	}

	// 管理员重置口令：吊销会话，返回新的一次性口令，并再次要求首次改密
	code, out = admin.do("POST", "/api/v1/admins/ops_new/reset-password", `{}`, true)
	if code != 200 || out["initialPassword"] == nil {
		t.Fatalf("重置口令失败：%d %v", code, out)
	}
	if code, _ := u.do("GET", "/api/v1/auth/me", "", false); code != http.StatusUnauthorized {
		t.Fatalf("重置口令后原会话应失效：%d", code)
	}
	if code, out := u.do("POST", "/api/v1/auth/login", `{"account":"ops_new","password":"`+out["initialPassword"].(string)+`"}`, true); code != 200 || out["pwdChange"] == "" {
		t.Fatalf("重置后应可用新口令登录并要求改密：%d %v", code, out)
	}
	if code, _ := admin.do("POST", "/api/v1/admins/admin/reset-password", `{}`, true); code != http.StatusForbidden {
		t.Fatalf("不能重置当前登录账号的口令：%d", code)
	}
}

func TestAdminIPRestriction(t *testing.T) {
	s, ts := newTestServer(t, true)
	admin := newClient(t, ts)
	admin.login(s, "admin")
	analyst := newClient(t, ts)
	analyst.login(s, "ana_chen")

	if code, _ := admin.do("PATCH", "/api/v1/admins/ana_chen", `{"allow":["not-an-ip"]}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("无效来源应拒绝：%d", code)
	}
	if code, _ := admin.do("PATCH", "/api/v1/admins/admin", `{"allow":["10.9.0.0/16"]}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("不能把自己当前来源排除在外：%d", code)
	}
	code, out := admin.do("PATCH", "/api/v1/admins/ana_chen", `{"allow":["10.9.0.0/16","10.9.1.1"]}`, true)
	if code != 200 || len(out["allow"].([]any)) != 2 {
		t.Fatalf("设置来源限制失败：%d %v", code, out)
	}
	// 已登录会话立即受限
	if code, _ := analyst.do("GET", "/api/v1/auth/me", "", false); code != http.StatusUnauthorized {
		t.Fatalf("来源不在允许范围的会话应失效：%d", code)
	}
	if code, out := newClient(t, ts).do("POST", "/api/v1/auth/login", `{"account":"ana_chen","password":"`+testPW+`"}`, true); code != http.StatusForbidden {
		t.Fatalf("来源不在允许范围时应拒绝登录：%d %v", code, out)
	}
	_, logs := admin.do("GET", "/api/v1/audit?q=ana_chen&result=fail", "", false)
	if logs["total"].(float64) < 1 {
		t.Fatal("被拒绝的登录应写入审计日志")
	}
	admin.do("PATCH", "/api/v1/admins/ana_chen", `{"allow":["127.0.0.0/8"]}`, true)
	newClient(t, ts).login(s, "ana_chen")
	admin.do("PATCH", "/api/v1/admins/ana_chen", `{"allow":[]}`, true)
	newClient(t, ts).login(s, "ana_chen")
}

func TestCronSpec(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	base := time.Date(2026, 11, 10, 9, 30, 0, 0, loc) // 周二
	cases := []struct{ label, next, from, to string }{
		{"每日 08:00", "2026-11-11 08:00", "2026-11-10", "2026-11-11"},
		{"每日 23:59", "2026-11-10 23:59", "2026-11-09", "2026-11-10"},
		{"每周一 09:00", "2026-11-16 09:00", "2026-11-09", "2026-11-16"},
		{"每周二 10:00", "2026-11-10 10:00", "2026-11-03", "2026-11-10"},
		{"每周日 09:00", "2026-11-15 09:00", "2026-11-08", "2026-11-15"},
		{"每月 1 日 08:00", "2026-12-01 08:00", "2026-11-01", "2026-12-01"},
		{"每月 28 日 10:00", "2026-11-28 10:00", "2026-10-01", "2026-11-01"},
		{"每季度首日 09:00", "2027-01-01 09:00", "2026-10-01", "2027-01-01"},
	}
	for _, c := range cases {
		spec, err := parseCron(c.label)
		if err != nil {
			t.Fatalf("%s：%v", c.label, err)
		}
		n := spec.next(base, loc)
		if got := n.Format("2006-01-02 15:04"); got != c.next {
			t.Errorf("%s 下次执行 %s，期望 %s", c.label, got, c.next)
		}
		f, to, _ := spec.period(n, loc)
		if f.Format("2006-01-02") != c.from || to.Format("2006-01-02") != c.to {
			t.Errorf("%s 统计周期 %s ~ %s，期望 %s ~ %s", c.label, f.Format("2006-01-02"), to.Format("2006-01-02"), c.from, c.to)
		}
	}
	for _, bad := range []string{"每月 31 日 08:00", "每日 25:00", "every day", "每周八 09:00"} {
		if _, err := parseCron(bad); err == nil {
			t.Errorf("%s 应无效", bad)
		}
	}
}

// smtpSink 最小化的 SMTP 服务器（无 TLS），收集每封邮件的 DATA。
func smtpSink(t *testing.T) (string, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan string, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := func(s string) { c.Write([]byte(s + "\r\n")) }
				w("220 sink")
				var data strings.Builder
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case cmd == "DATA":
						w("354 go")
						for {
							l, err := r.ReadString('\n')
							if err != nil || strings.TrimRight(l, "\r\n") == "." {
								break
							}
							data.WriteString(l)
						}
						w("250 queued")
						out <- data.String()
					case cmd == "QUIT":
						w("221 bye")
						return
					default:
						w("250 OK")
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), out
}

func TestScheduledReports(t *testing.T) {
	s, ts := newTestServer(t, false)
	c := newClient(t, ts)
	initAdmin(t, s, c)
	addr, mails := smtpSink(t)

	if code, _ := c.do("POST", "/api/v1/report-schedules", `{"tpl":"weekly","cron":"每月 31 日 08:00","to":["soc@corp.example"],"fmt":"HTML"}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("无效周期应拒绝：%d", code)
	}
	if code, _ := c.do("POST", "/api/v1/report-schedules", `{"tpl":"weekly","cron":"每周一 09:00","to":["安全运营组"],"fmt":"HTML"}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("接收人须为邮箱：%d", code)
	}
	code, sc := c.do("POST", "/api/v1/report-schedules", `{"tpl":"weekly","cron":"每周一 09:00","to":["soc@corp.example","CISO@corp.example"],"fmt":"HTML"}`, true)
	if code != http.StatusCreated {
		t.Fatalf("创建定时报表失败：%d %v", code, sc)
	}
	id := sc["id"].(string)
	next := time.UnixMilli(int64(sc["next"].(float64))).In(s.St.Loc)
	if next.Weekday() != time.Monday || next.Hour() != 9 || !next.After(time.Now()) {
		t.Fatalf("下次执行时间错误：%v", next)
	}

	// 未配置 SMTP：立即执行仍可生成并下载，但记录发送失败
	_, job := c.do("POST", "/api/v1/report-schedules/"+id+"/run", `{}`, true)
	waitJob(t, c, job["id"].(string))
	var lastErr string
	s.St.Read(func(d *store.Data) { lastErr = d.ReportSchedules[0].LastErr })
	if !strings.Contains(lastErr, "SMTP") {
		t.Fatalf("未配置 SMTP 时应记录失败原因：%q", lastErr)
	}

	// 配置 SMTP 后，到期任务由维护逻辑自动执行并发送带附件的邮件
	c.do("PUT", "/api/v1/integrations/smtp", `{"config":{"SMTP 服务器":"`+addr+`","加密方式":"none","发件人":"dlp@corp.example","收件人":"sec@corp.example"},"enabled":true}`, true)
	s.St.Write(func(d *store.Data) { d.ReportSchedules[0].Next = time.Now().Add(-time.Minute).UnixMilli() })
	s.runDueSchedules(t.Context(), time.Now())
	select {
	case m := <-mails:
		if !strings.Contains(m, "soc@corp.example") || !strings.Contains(m, "Content-Disposition: attachment") {
			t.Fatalf("报表邮件内容错误：%s", m[:min(len(m), 600)])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("到期的定时报表未发送")
	}
	var after store.Schedule
	var reports int
	s.St.Read(func(d *store.Data) { after, reports = *d.ReportSchedules[0], len(d.Reports) })
	if after.LastErr != "" || time.UnixMilli(after.Next).Before(time.Now()) || reports != 2 {
		t.Fatalf("执行后应推进下次时间并归档：%+v reports=%d", after, reports)
	}
	// 暂停的任务不执行
	c.do("PATCH", "/api/v1/report-schedules/"+id, `{"on":false}`, true)
	s.St.Write(func(d *store.Data) { d.ReportSchedules[0].Next = time.Now().Add(-time.Minute).UnixMilli() })
	s.runDueSchedules(t.Context(), time.Now())
	select {
	case <-mails:
		t.Fatal("已暂停的定时报表不应执行")
	case <-time.After(300 * time.Millisecond):
	}
	if code, _ := c.do("DELETE", "/api/v1/report-schedules/"+id, "", true); code != 200 {
		t.Fatalf("删除定时报表失败：%d", code)
	}
}

func waitJob(t *testing.T, c *client, id string) map[string]any {
	t.Helper()
	for i := 0; i < 100; i++ {
		_, j := c.do("GET", "/api/v1/jobs/"+id, "", false)
		if j["status"] != "run" {
			return j
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("任务超时")
	return nil
}
