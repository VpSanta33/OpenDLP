package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactor(t *testing.T) {
	r := NewRedactor(true)
	r.Known("user", "张伟", "张伟华")
	a := r.Mask("host", "BJ-RD-0001")
	in := "张伟华和张伟在 BJ-RD-0001（10.1.2.3）上拷贝了含 110105199001011234 的文件，联系 13912345678 / zw@corp.example"
	out := r.Text(in)
	for _, leak := range []string{"张伟", "BJ-RD-0001", "10.1.2.3", "110105199001011234", "13912345678", "zw@corp.example"} {
		if strings.Contains(out, leak) {
			t.Fatalf("脱敏后仍包含 %s：%s", leak, out)
		}
	}
	if a != "[终端A]" || !strings.Contains(out, "[用户A]") || !strings.Contains(out, "[用户B]") {
		t.Fatalf("代号分配错误：%s", out)
	}
	back := r.Restore(out)
	if !strings.Contains(back, "张伟华和张伟在 BJ-RD-0001（10.1.2.3）") {
		t.Fatalf("还原错误：%s", back)
	}
	if r.Lookup("[终端A]") != "BJ-RD-0001" || r.Lookup("终端A") != "BJ-RD-0001" || r.Lookup("其他") != "其他" {
		t.Fatal("代号查找错误")
	}
	// 关闭脱敏时原样透传
	off := NewRedactor(false)
	if off.Text(in) != in || off.Mask("user", "张伟") != "张伟" {
		t.Fatal("关闭脱敏时不应改动文本")
	}
	// 超过 26 个代号
	many := NewRedactor(true)
	for i := 0; i < 30; i++ {
		many.Mask("user", string(rune('甲'+i))+"某")
	}
	if got, want := many.Restore("[用户A1] 与 [用户A]"), string(rune('甲'+26))+"某 与 甲某"; got != want {
		t.Fatalf("长代号应优先还原：%s", got)
	}
}

func TestChatToolCallsAndErrors(t *testing.T) {
	var got chatReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-test" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"message":"bad key"}}`))
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","type":"function","function":{"name":"stats","arguments":"{\"days\":7}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/v1/", "deepseek-chat", "sk-test")
	if err != nil {
		t.Fatal(err)
	}
	m, u, err := c.Chat(context.Background(), []Message{{Role: "user", Content: "hi"}}, Options{Tools: []Tool{NewTool("stats", "统计", nil)}, JSON: true})
	if err != nil || len(m.ToolCalls) != 1 || m.ToolCalls[0].Function.Name != "stats" || u.Total != 15 {
		t.Fatalf("工具调用解析错误：%+v %v", m, err)
	}
	if got.Model != "deepseek-chat" || len(got.Tools) != 1 || got.ResponseFormat["type"] != "json_object" || got.Stream {
		t.Fatalf("请求格式错误：%+v", got)
	}
	bad, _ := New(srv.URL+"/v1", "m", "wrong")
	if _, _, err := bad.Chat(context.Background(), nil, Options{}); err == nil || !strings.Contains(err.Error(), "API Key") {
		t.Fatalf("认证失败应返回明确错误：%v", err)
	}
	if _, err := New("ftp://x", "m", ""); err == nil {
		t.Fatal("非 http(s) 地址应拒绝")
	}
	var v struct{ Risk string }
	if ExtractJSON("分析如下：\n```json\n{\"risk\":\"高\"}\n```", &v) != nil || v.Risk != "高" {
		t.Fatal("应能从代码块中提取 JSON")
	}
}
