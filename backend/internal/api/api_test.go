package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/seed"
	"opendlp/internal/store"
	"opendlp/internal/storetest"
)

const testPW = "Test-Password-2026!"

// newTestServer 生产模式服务；demo 为 true 时写入演示数据（含演示管理员）。
func newTestServer(t *testing.T, demo bool) (*Server, *httptest.Server) {
	t.Helper()
	st := storetest.Open(t, func() *store.Data { return seed.Reference(time.Now()) })
	if demo {
		if err := seed.Demo(context.Background(), st, time.Now(), testPW); err != nil {
			t.Fatal(err)
		}
	}
	s := New(st, Config{AgentToken: "agent-token-for-tests", Version: "test"})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

type client struct {
	t  *testing.T
	ts *httptest.Server
	c  *http.Client
}

func newClient(t *testing.T, ts *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t, ts, &http.Client{Jar: jar}}
}

func (c *client) do(method, path, body string, csrf bool) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-OpenDLP-Request", "1")
	}
	res, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (c *client) agent(path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest("POST", c.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-token-for-tests")
	res, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// login 完成口令 + TOTP 登录（读取测试数据中的 TOTP 密钥计算动态码）。
func (c *client) login(s *Server, acc string) {
	c.t.Helper()
	code, out := c.do("POST", "/api/v1/auth/login", `{"account":"`+acc+`","password":"`+testPW+`"}`, true)
	if code != 200 {
		c.t.Fatalf("登录失败：%d %v", code, out)
	}
	if out["mfa"] != true {
		return
	}
	var secret string
	s.St.Read(func(d *store.Data) { secret = d.Admin(acc).TOTPSecret })
	otp, _ := auth.TOTPCode(secret, time.Now())
	code, out = c.do("POST", "/api/v1/auth/mfa", `{"challenge":"`+out["challenge"].(string)+`","code":"`+otp+`"}`, true)
	if code != 200 {
		c.t.Fatalf("MFA 失败：%d %v", code, out)
	}
}

func TestFirstRunSetup(t *testing.T) {
	s, ts := newTestServer(t, false)
	c := newClient(t, ts)
	tok := s.SetupToken("")
	if _, cfg := c.do("GET", "/api/v1/auth/config", "", false); cfg["setup"] != true {
		t.Fatal("空库应要求初始化")
	}
	if code, _ := c.do("POST", "/api/v1/auth/login", `{"account":"admin","password":"`+testPW+`"}`, true); code != http.StatusUnauthorized {
		t.Fatalf("未初始化时不应存在可登录账号，实际 %d", code)
	}
	if code, _ := c.do("POST", "/api/v1/setup/begin", `{"token":"wrong","account":"secadmin","name":"王安全","password":"`+testPW+`"}`, true); code != http.StatusUnauthorized {
		t.Fatalf("错误令牌应返回 401，实际 %d", code)
	}
	if code, _ := c.do("POST", "/api/v1/setup/begin", `{"token":"`+tok+`","account":"secadmin","name":"王安全","password":"weakpass"}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("弱口令应返回 422，实际 %d", code)
	}
	code, en := c.do("POST", "/api/v1/setup/begin", `{"token":"`+tok+`","account":"secadmin","name":"王安全","password":"`+testPW+`"}`, true)
	if code != 200 {
		t.Fatalf("初始化第一步失败：%d %v", code, en)
	}
	if code, _ := c.do("POST", "/api/v1/setup/complete", `{"enrollment":"`+en["enrollment"].(string)+`","code":"000000"}`, true); code != http.StatusUnauthorized {
		t.Fatalf("错误动态码应返回 401，实际 %d", code)
	}
	otp, _ := auth.TOTPCode(en["secret"].(string), time.Now())
	if code, out := c.do("POST", "/api/v1/setup/complete", `{"enrollment":"`+en["enrollment"].(string)+`","code":"`+otp+`"}`, true); code != 200 {
		t.Fatalf("初始化失败：%d %v", code, out)
	}
	if code, me := c.do("GET", "/api/v1/auth/me", "", false); code != 200 || me["role"] != "super" || me["mfa"] != true {
		t.Fatalf("初始化后应以超级管理员登录：%d %v", code, me)
	}
	if code, _ := c.do("POST", "/api/v1/setup/begin", `{"token":"`+tok+`","account":"x","name":"x","password":"`+testPW+`"}`, true); code != http.StatusConflict {
		t.Fatalf("重复初始化应返回 409，实际 %d", code)
	}
	if _, db := c.do("GET", "/api/v1/dashboard?range=7d", "", false); db["empty"] != true {
		t.Fatal("空库看板应标记 empty")
	}
}

func TestLoginLockoutAndCSRF(t *testing.T) {
	_, ts := newTestServer(t, true)
	c := newClient(t, ts)
	if code, _ := c.do("POST", "/api/v1/auth/login", `{"account":"admin","password":"x"}`, false); code != http.StatusForbidden {
		t.Fatalf("缺少 CSRF 头应返回 403，实际 %d", code)
	}
	for i := 1; i <= 4; i++ {
		if code, _ := c.do("POST", "/api/v1/auth/login", `{"account":"sec_lihua","password":"wrong"}`, true); code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误口令应返回 401，实际 %d", i, code)
		}
	}
	if code, _ := c.do("POST", "/api/v1/auth/login", `{"account":"sec_lihua","password":"wrong"}`, true); code != http.StatusLocked {
		t.Fatalf("第 5 次错误口令应锁定账号，实际 %d", code)
	}
	if code, _ := c.do("POST", "/api/v1/auth/login", `{"account":"sec_lihua","password":"`+testPW+`"}`, true); code != http.StatusLocked {
		t.Fatalf("锁定期间正确口令也应被拒绝，实际 %d", code)
	}
	if code, _ := c.do("POST", "/api/v1/auth/login", `{"account":"own_sun","password":"`+testPW+`"}`, true); code != http.StatusForbidden {
		t.Fatalf("禁用账号应返回 403，实际 %d", code)
	}
	if code, _ := c.do("GET", "/api/v1/bootstrap", "", false); code != http.StatusUnauthorized {
		t.Fatalf("未登录访问应返回 401，实际 %d", code)
	}
}

func TestRBACAndSessions(t *testing.T) {
	s, ts := newTestServer(t, true)
	c := newClient(t, ts)
	c.login(s, "audit_zhao")
	if code, _ := c.do("GET", "/api/v1/audit", "", false); code != 200 {
		t.Fatalf("审计员应能查看审计日志，实际 %d", code)
	}
	if code, _ := c.do("GET", "/api/v1/incidents", "", false); code != http.StatusForbidden {
		t.Fatalf("审计员不应查看事件明细，实际 %d", code)
	}
	if code, _ := c.do("PUT", "/api/v1/settings", `{"sens":80}`, true); code != http.StatusForbidden {
		t.Fatalf("审计员不应修改系统设置，实际 %d", code)
	}
	_, boot := c.do("GET", "/api/v1/bootstrap", "", false)
	for _, k := range []string{"admins", "rules", "approvals", "integrations"} {
		if _, ok := boot[k]; ok {
			t.Errorf("审计员的引导数据不应包含 %s", k)
		}
	}
	_, logs := c.do("GET", "/api/v1/audit?type=越权访问", "", false)
	if logs["total"].(float64) < 1 {
		t.Fatal("越权写操作应写入审计日志")
	}
	// 会话保存在数据库：新的 Server 实例（模拟重启）可识别同一 Cookie
	s2 := New(s.St, Config{Version: "test"})
	ts2 := httptest.NewServer(s2.Handler())
	defer ts2.Close()
	req, _ := http.NewRequest("GET", ts2.URL+"/api/v1/auth/me", nil)
	for _, ck := range c.c.Jar.Cookies(mustURL(ts.URL)) {
		req.AddCookie(ck)
	}
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 200 {
		t.Fatalf("重启后会话应仍然有效：%v %v", err, res)
	}
}

func TestBusinessRules(t *testing.T) {
	s, ts := newTestServer(t, true)
	c := newClient(t, ts)
	c.login(s, "admin")
	if code, out := c.do("POST", "/api/v1/rules", `{"name":"x","cat":"pii","type":"regex","cfg":{"src":"(?<!\\d)1"}}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("非 RE2 正则应返回 422，实际 %d %v", code, out)
	}
	if code, _ := c.do("POST", "/api/v1/rules", `{"name":"员工工号","cat":"pii","type":"regex","cfg":{"src":"EMP-\\d{6}"}}`, true); code != http.StatusCreated {
		t.Fatalf("合法规则应创建成功，实际 %d", code)
	}
	if code, _ := c.do("PUT", "/api/v1/roles/analyst/perms", `{"audit":{"view":true},"settings":{"view":true,"cfg":true}}`, true); code != http.StatusUnprocessableEntity {
		t.Fatalf("违反三员分立的权限应返回 422，实际 %d", code)
	}
	if code, _ := c.do("PUT", "/api/v1/roles/secadmin/perms", `{"dashboard":{"view":true}}`, true); code != http.StatusForbidden {
		t.Fatalf("内置角色不可修改，实际 %d", code)
	}
	// 外发审批状态机
	var id string
	s.St.Read(func(d *store.Data) {
		for _, a := range d.Approvals {
			if a.Status == "pending" && a.Stage == 2 && a.Deadline > time.Now().UnixMilli() {
				id = a.ID
				break
			}
		}
	})
	if id != "" {
		if code, _ := c.do("POST", "/api/v1/approvals/"+id+"/decision", `{"decision":"reject"}`, true); code != http.StatusUnprocessableEntity {
			t.Fatalf("无意见驳回应返回 422，实际 %d", code)
		}
		code, out := c.do("POST", "/api/v1/approvals/"+id+"/decision", `{"decision":"approve","conditions":{"encrypt":false,"expireDays":7}}`, true)
		if code != 200 || (out["level"] == "机密" && out["conditions"].(map[string]any)["encrypt"] != true) {
			t.Fatalf("审批失败或机密文件未强制加密：%d %v", code, out)
		}
		if code, _ := c.do("POST", "/api/v1/approvals/"+id+"/decision", `{"decision":"approve"}`, true); code != http.StatusConflict {
			t.Fatalf("重复审批应返回 409，实际 %d", code)
		}
	}
	// 事件处置写入数据库
	_, list := c.do("GET", "/api/v1/incidents?st=pending&per=1", "", true)
	inc := list["items"].([]any)[0].(map[string]any)
	if code, _ := c.do("POST", "/api/v1/incidents/"+inc["id"].(string)+"/resolve", `{"status":"resolved"}`, true); code != 200 {
		t.Fatalf("处置失败：%d", code)
	}
	if code, _ := c.do("POST", "/api/v1/incidents/"+inc["id"].(string)+"/resolve", `{"status":"fp"}`, true); code != http.StatusConflict {
		t.Fatalf("重复处置应返回 409，实际 %d", code)
	}
	if code, out := c.do("GET", "/api/v1/audit/verify", "", false); code != 200 || out["ok"] != true {
		t.Fatalf("审计哈希链校验失败：%v", out)
	}
}

func TestIngestFlow(t *testing.T) {
	s, ts := newTestServer(t, false)
	c := newClient(t, ts)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/ingest/heartbeat", strings.NewReader(`{"host":"h"}`))
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无令牌上报应返回 401，实际 %d", res.StatusCode)
	}
	if code, _ := c.agent("/api/v1/ingest/heartbeat", `{"host":"BJ-RD-0001","user":"张伟","agent":"3.2.1","osKey":"win"}`); code != 200 {
		t.Fatalf("心跳失败：%d", code)
	}
	if code, out := c.agent("/api/v1/ingest/detections", `[{"user":"张伟","host":"BJ-RD-0001","channel":"usb","dataType":"source","file":"a.zip","action":"block","severity":"critical"},{"channel":"email","dataType":"phone","action":"allow"},{"channel":"fax","dataType":"x","action":"allow"}]`); code != http.StatusAccepted || out["incidents"].(float64) != 1 || out["skipped"].(float64) != 1 {
		t.Fatalf("检测上报结果错误：%d %v", code, out)
	}
	n, _ := s.St.CountIncidents(context.Background(), store.IncidentFilter{})
	var epID, notes string
	s.St.Read(func(d *store.Data) {
		epID = d.Endpoints[0].ID
		for _, x := range d.Notes {
			notes += x.Title + ";"
		}
	})
	if n != 1 || !strings.Contains(notes, "严重事件") || !strings.Contains(notes, "新终端接入") {
		t.Fatalf("事件或通知未生成：%d %s", n, notes)
	}
	// 管理端下发指令，终端心跳领取后状态变为已送达
	tok := s.SetupToken("")
	_, en := c.do("POST", "/api/v1/setup/begin", `{"token":"`+tok+`","account":"secadmin","name":"王安全","password":"`+testPW+`"}`, true)
	otp, _ := auth.TOTPCode(en["secret"].(string), time.Now())
	c.do("POST", "/api/v1/setup/complete", `{"enrollment":"`+en["enrollment"].(string)+`","code":"`+otp+`"}`, true)
	if code, _ := c.do("POST", "/api/v1/endpoints/"+epID+"/actions", `{"action":"isolate"}`, true); code != 200 {
		t.Fatalf("下发指令失败：%d", code)
	}
	_, hb := c.agent("/api/v1/ingest/heartbeat", `{"host":"BJ-RD-0001","user":"张伟","agent":"3.2.1"}`)
	cmds := hb["commands"].([]any)
	if len(cmds) != 1 || cmds[0].(map[string]any)["action"] != "isolate" {
		t.Fatalf("终端未领取到指令：%v", hb)
	}
	if _, hb2 := c.agent("/api/v1/ingest/heartbeat", `{"host":"BJ-RD-0001"}`); len(hb2["commands"].([]any)) != 0 {
		t.Fatal("指令不应被重复领取")
	}
	// 外发申请进入审批
	if code, a := c.agent("/api/v1/ingest/approvals", `{"user":"张伟","file":"方案.docx","dataType":"contract","channel":"email","to":"a@b.example","reason":"投标"}`); code != http.StatusCreated || a["stage"].(float64) != 2 {
		t.Fatalf("外发申请提交失败：%d %v", code, a)
	}
	// 组织架构导入
	if code, out := c.do("POST", "/api/v1/iam/employees/import", `{"csv":"工号,姓名,部门\nE1,张伟,研发中心,工程师,,离职中,是\nE2,李娜,销售部"}`, true); code != 200 || out["added"].(float64) != 2 {
		t.Fatalf("组织架构导入失败：%d %v", code, out)
	}
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

// agentReq 以终端独立凭据发起请求。
func agentReq(t *testing.T, ts *httptest.Server, method, path, cred, body string, hdr ...string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Agent "+cred)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func TestAgentProtocol(t *testing.T) {
	s, ts := newTestServer(t, false)
	c := newClient(t, ts)
	// 注册需要注册令牌
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/agent/enroll", strings.NewReader(`{"host":"BJ-RD-0001"}`))
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无注册令牌应返回 401，实际 %d", res.StatusCode)
	}
	code, en := c.agent("/api/v1/agent/enroll", `{"host":"BJ-RD-0001","user":"张伟","agent":"3.3.0","osKey":"mac"}`)
	if code != 200 || en["agentId"] == nil {
		t.Fatalf("注册失败：%d %v", code, en)
	}
	cred := en["agentId"].(string) + ":" + en["secret"].(string)
	if res, _ := agentReq(t, ts, "POST", "/api/v1/agent/heartbeat", en["agentId"].(string)+":wrong", `{}`); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误凭据应返回 401，实际 %d", res.StatusCode)
	}
	// 心跳返回策略版本；拉取策略包支持 ETag
	_, hb := agentReq(t, ts, "POST", "/api/v1/agent/heartbeat", cred, `{"host":"OTHER-HOST","user":"张伟","agent":"3.3.0"}`)
	v1 := hb["policyVersion"].(string)
	res, bundle := agentReq(t, ts, "GET", "/api/v1/agent/policy", cred, "")
	if res.StatusCode != 200 || bundle["version"] != v1 || len(bundle["rules"].([]any)) == 0 {
		t.Fatalf("策略包错误：%d %v", res.StatusCode, bundle["version"])
	}
	if res, _ := agentReq(t, ts, "GET", "/api/v1/agent/policy", cred, "", "If-None-Match", `"`+v1+`"`); res.StatusCode != http.StatusNotModified {
		t.Fatalf("版本未变应返回 304，实际 %d", res.StatusCode)
	}
	var hosts []string
	s.St.Read(func(d *store.Data) {
		for _, e := range d.Endpoints {
			hosts = append(hosts, e.Host)
		}
	})
	if len(hosts) != 1 || hosts[0] != "BJ-RD-0001" {
		t.Fatalf("心跳不应能冒充其他主机：%v", hosts)
	}
	// 管理员导入合规模板后策略版本变化
	tok := s.SetupToken("")
	_, su := c.do("POST", "/api/v1/setup/begin", `{"token":"`+tok+`","account":"secadmin","name":"王安全","password":"`+testPW+`"}`, true)
	otp, _ := auth.TOTPCode(su["secret"].(string), time.Now())
	c.do("POST", "/api/v1/setup/complete", `{"enrollment":"`+su["enrollment"].(string)+`","code":"`+otp+`"}`, true)
	_, tpl := c.do("POST", "/api/v1/policies/templates/sync", `{}`, true)
	pol := tpl["policies"].([]any)[0].(map[string]any)["id"].(string)
	c.do("PATCH", "/api/v1/policies/"+pol, `{"enabled":true}`, true)
	_, hb2 := agentReq(t, ts, "POST", "/api/v1/agent/heartbeat", cred, `{"policyVersion":"`+v1+`"}`)
	if hb2["policyVersion"] == v1 {
		t.Fatal("启用策略后策略包版本应变化")
	}
	// 检测上报的主机以凭据为准
	agentReq(t, ts, "POST", "/api/v1/agent/detections", cred, `[{"host":"SPOOF","user":"张伟","channel":"usb","dataType":"idcard","file":"a.xlsx","action":"block","severity":"high"}]`)
	list, _, _ := s.St.ListIncidents(context.Background(), store.IncidentFilter{}, 1, 5)
	if len(list) != 1 || list[0].Host != "BJ-RD-0001" {
		t.Fatalf("事件主机应为凭据绑定的主机：%+v", list)
	}
	// 指令下发 → 领取 → 回传结果
	var epID string
	s.St.Read(func(d *store.Data) { epID = d.Endpoints[0].ID })
	c.do("POST", "/api/v1/endpoints/"+epID+"/actions", `{"action":"scan"}`, true)
	_, hb3 := agentReq(t, ts, "POST", "/api/v1/agent/heartbeat", cred, `{}`)
	cmd := hb3["commands"].([]any)[0].(map[string]any)
	if res, out := agentReq(t, ts, "POST", "/api/v1/agent/commands/"+cmd["id"].(string)+"/result", cred, `{"ok":true,"message":"扫描 120 个文件"}`); res.StatusCode != 200 || out["status"] != "done" {
		t.Fatalf("回传结果失败：%v", out)
	}
	// 吊销后凭据失效
	if code, _ := c.do("POST", "/api/v1/endpoints/"+epID+"/revoke", `{}`, true); code != 200 {
		t.Fatalf("吊销失败：%d", code)
	}
	if res, _ := agentReq(t, ts, "POST", "/api/v1/agent/heartbeat", cred, `{}`); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("吊销后应返回 401，实际 %d", res.StatusCode)
	}
}
