package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"opendlp/internal/store"
)

// fakeLLM 模拟 OpenAI 兼容接口：按系统提示词区分研判 / 摘要 / 助手，并记录全部请求体。
type fakeLLM struct {
	mu   sync.Mutex
	reqs []string
	srv  *httptest.Server
}

var codeRe = regexp.MustCompile(`\[用户[A-Z]\d*\]`)

func newFakeLLM(t *testing.T) *fakeLLM {
	f := &fakeLLM{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, string(raw))
		f.mu.Unlock()
		var req struct {
			Messages []struct{ Role, Content string }
			Tools    []struct{ Function struct{ Name string } }
		}
		json.Unmarshal(raw, &req)
		sys, last := req.Messages[0].Content, req.Messages[len(req.Messages)-1]
		reply := func(m map[string]any) {
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": m, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}})
		}
		switch {
		case strings.Contains(last.Content, "请研判"):
			user := codeRe.FindString(last.Content)
			if user == "" { // 关闭脱敏时取原名
				user = "原名"
			}
			reply(map[string]any{"role": "assistant", "content": "```json\n" + `{"risk":"HIGH","score":130,"summary":"` + user + ` 在非工作时间通过U盘拷贝客户数据","reasons":["` + user + ` 近7天事件增多","阻断后仍在尝试"],"recommendations":["联系部门负责人核实"],"disposition":"escalate","confidence":"medium"}` + "\n```"})
		case strings.Contains(sys, "管理摘要"):
			reply(map[string]any{"role": "assistant", "content": "本期整体态势平稳。\n\n高风险集中在 " + codeRe.FindString(last.Content) + "。"})
		case strings.Contains(sys, "安全运营助手"):
			if last.Role == "tool" {
				m := codeRe.FindString(last.Content)
				reply(map[string]any{"role": "assistant", "content": "事件最多的用户是 " + m + "。"})
				return
			}
			if len(req.Tools) == 0 {
				reply(map[string]any{"role": "assistant", "content": "当前角色无数据权限。"})
				return
			}
			reply(map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{"id": "call_1", "type": "function",
				"function": map[string]any{"name": "incident_stats", "arguments": `{"group_by":"user","days":365,"limit":3}`}}}})
		default:
			reply(map[string]any{"role": "assistant", "content": "OK"})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLLM) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.reqs, "\n")
}

func (f *fakeLLM) reset() {
	f.mu.Lock()
	f.reqs = nil
	f.mu.Unlock()
}

func TestAIFeatures(t *testing.T) {
	s, ts := newTestServer(t, true)
	c := newClient(t, ts)
	c.login(s, "admin")
	fake := newFakeLLM(t)

	// 未配置时返回明确提示
	var incID, user, host string
	list, _, _ := s.St.ListIncidents(t.Context(), store.IncidentFilter{}, 1, 1)
	incID, user, host = list[0].ID, list[0].User, list[0].Host
	if code, out := c.do("POST", "/api/v1/ai/incidents/"+incID+"/triage", `{}`, true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "AI 大模型") {
		t.Fatalf("未配置时应提示配置：%d %v", code, out)
	}
	if code, _ := c.do("PUT", "/api/v1/integrations/ai", `{"config":{"接口地址":"ftp://x","模型":"m"},"enabled":true}`, true); code != http.StatusUnprocessableEntity {
		t.Fatal("无效接口地址应拒绝")
	}
	if code, out := c.do("PUT", "/api/v1/integrations/ai", `{"config":{"接口地址":"`+fake.srv.URL+`/v1","模型":"qwen-test","API Key":""},"enabled":true}`, true); code != 200 {
		t.Fatalf("保存 AI 配置失败：%d %v", code, out)
	}
	if _, out := c.do("POST", "/api/v1/integrations/ai/test", `{}`, true); out["ok"] != true {
		t.Fatalf("连接测试失败：%v", out)
	}

	// AI 研判：默认脱敏，结果中的代号在本地还原
	fake.reset()
	code, tri := c.do("POST", "/api/v1/ai/incidents/"+incID+"/triage", `{}`, true)
	if code != 200 {
		t.Fatalf("研判失败：%d %v", code, tri)
	}
	sent := fake.all()
	if strings.Contains(sent, user) || strings.Contains(sent, host) {
		t.Fatalf("发送给模型的数据不应包含真实姓名或主机名：%s / %s", user, host)
	}
	if tri["risk"] != "high" || tri["score"].(float64) != 100 || tri["disposition"] != "escalate" || !strings.HasPrefix(tri["summary"].(string), user) || tri["redacted"] != true {
		t.Fatalf("研判结果归一化或还原错误：%v", tri)
	}
	if _, cached := c.do("GET", "/api/v1/ai/incidents/"+incID, "", false); cached["summary"] != tri["summary"] {
		t.Fatal("研判结果应被缓存")
	}

	// AI 助手：工具调用结果脱敏，最终回答还原
	fake.reset()
	code, chat := c.do("POST", "/api/v1/ai/chat", `{"messages":[{"role":"user","content":"今年哪个员工的事件最多？"}]}`, true)
	if code != 200 {
		t.Fatalf("助手调用失败：%d %v", code, chat)
	}
	groups, _, _ := s.St.IncidentGroup(t.Context(), store.IncidentFilter{}, "user", 1)
	if chat["reply"] != "事件最多的用户是 "+groups[0].Key+"。" {
		t.Fatalf("助手回答未正确还原：%v（期望 %s）", chat["reply"], groups[0].Key)
	}
	if strings.Contains(fake.all(), groups[0].Key) {
		t.Fatal("工具结果发送给模型前应脱敏")
	}
	if tools := chat["tools"].([]any); len(tools) != 1 || tools[0].(map[string]any)["name"] != "incident_stats" {
		t.Fatalf("应返回工具调用记录：%v", chat["tools"])
	}
	// 多轮对话：历史中的真实姓名会被重新脱敏
	fake.reset()
	c.do("POST", "/api/v1/ai/chat", `{"messages":[{"role":"user","content":"今年哪个员工的事件最多？"},{"role":"assistant","content":"`+chat["reply"].(string)+`"},{"role":"user","content":"`+groups[0].Key+`最近外发了什么？"}]}`, true)
	if strings.Contains(fake.all(), groups[0].Key) {
		t.Fatal("对话历史中的真实姓名应被脱敏")
	}

	// 审计员没有事件查看权限：不向模型提供任何数据工具
	aud := newClient(t, ts)
	aud.login(s, "audit_zhao")
	fake.reset()
	if code, out := aud.do("POST", "/api/v1/ai/chat", `{"messages":[{"role":"user","content":"统计事件"}]}`, true); code != 200 || out["reply"] != "当前角色无数据权限。" {
		t.Fatalf("无权限角色不应获得数据工具：%d %v", code, out)
	}
	if strings.Contains(fake.all(), "incident_stats") {
		t.Fatal("无权限角色的请求中不应包含数据工具")
	}
	if code, _ := aud.do("POST", "/api/v1/ai/incidents/"+incID+"/triage", `{}`, true); code != http.StatusForbidden {
		t.Fatal("无事件处置权限不应发起研判")
	}

	// 报表附带 AI 管理摘要（脱敏后还原）
	_, job := c.do("POST", "/api/v1/reports", `{"tpl":"monthly","range":"y","fmt":"HTML"}`, true)
	waitJob(t, c, job["id"].(string))
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/jobs/"+job["id"].(string)+"/download", nil)
	res, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(html), "AI 管理摘要") || !strings.Contains(string(html), "本期整体态势平稳") || codeRe.Match(html) {
		t.Fatalf("报表应包含已还原的 AI 摘要：%s", html[:min(len(html), 400)])
	}

	// 关闭脱敏后发送原值；用量统计
	c.do("PUT", "/api/v1/settings", `{"aiRedact":false}`, true)
	fake.reset()
	c.do("POST", "/api/v1/ai/incidents/"+incID+"/triage", `{}`, true)
	if !strings.Contains(fake.all(), user) {
		t.Fatal("关闭脱敏后应发送原始姓名")
	}
	var dl *store.Delivery
	s.St.Read(func(d *store.Data) { dl = findIntegration(d, "ai").Delivery })
	if dl == nil || dl.OK < 5 || dl.Tokens < 600 {
		t.Fatalf("应记录调用次数与 token 用量：%+v", dl)
	}
	// 参数校验
	if code, _ := c.do("POST", "/api/v1/ai/chat", `{"messages":[{"role":"assistant","content":"x"}]}`, true); code != http.StatusBadRequest {
		t.Fatal("最后一条须为提问")
	}
}
