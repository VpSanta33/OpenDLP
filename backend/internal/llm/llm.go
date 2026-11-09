// Package llm 对接 OpenAI 兼容的 Chat Completions 接口（DeepSeek、通义千问、智谱、Kimi，
// 以及内网部署的 vLLM / Ollama / Xinference 等），供 AI 研判、报表摘要与安全助手使用。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Message 对话消息（OpenAI Chat Completions 格式）。
type Message struct {
	Role       string     `json:"role"` // system | user | assistant | tool
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Tool 可供模型调用的函数。
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// NewTool 构造函数工具定义。
func NewTool(name, desc string, params map[string]any) Tool {
	if params == nil {
		params = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return Tool{Type: "function", Function: ToolFunction{Name: name, Description: desc, Parameters: params}}
}

// Usage token 用量。
type Usage struct {
	Prompt     int `json:"prompt_tokens"`
	Completion int `json:"completion_tokens"`
	Total      int `json:"total_tokens"`
}

// Client OpenAI 兼容接口客户端。
type Client struct {
	BaseURL string // 例如 https://api.deepseek.com/v1、http://10.0.0.5:11434/v1
	Model   string
	APIKey  string // 本地部署可为空
	HTTP    *http.Client
}

// Config 校验配置并返回客户端。
func New(baseURL, model, apiKey string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if baseURL == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("接口地址须为 http(s) 地址，例如 https://api.deepseek.com/v1")
	}
	if strings.TrimSpace(model) == "" {
		return nil, errors.New("请填写模型名称")
	}
	return &Client{BaseURL: baseURL, Model: strings.TrimSpace(model), APIKey: strings.TrimSpace(apiKey), HTTP: &http.Client{Timeout: 180 * time.Second}}, nil
}

// Options 单次请求参数。
type Options struct {
	Tools       []Tool
	JSON        bool    // 要求返回 JSON 对象（response_format: json_object）
	Temperature float64 // 0 表示使用 0.2
	MaxTokens   int
}

type chatReq struct {
	Model          string         `json:"model"`
	Messages       []Message      `json:"messages"`
	Tools          []Tool         `json:"tools,omitempty"`
	Temperature    float64        `json:"temperature"`
	MaxTokens      int            `json:"max_tokens,omitempty"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
	Stream         bool           `json:"stream"`
}

type chatResp struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Error 模型服务返回的错误。
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "模型服务认证失败，请检查 API Key"
	case http.StatusTooManyRequests:
		return "模型服务限流或额度不足，请稍后再试"
	case http.StatusNotFound:
		return "模型或接口不存在，请检查接口地址与模型名称"
	}
	if e.Msg != "" {
		return fmt.Sprintf("模型服务错误（HTTP %d）：%s", e.Status, e.Msg)
	}
	return fmt.Sprintf("模型服务错误（HTTP %d）", e.Status)
}

// Chat 发送一次对话请求，返回模型回复（可能包含工具调用）。
func (c *Client) Chat(ctx context.Context, msgs []Message, o Options) (Message, Usage, error) {
	req := chatReq{Model: c.Model, Messages: msgs, Tools: o.Tools, Temperature: o.Temperature, MaxTokens: o.MaxTokens}
	if req.Temperature == 0 {
		req.Temperature = 0.2
	}
	if o.JSON {
		req.ResponseFormat = map[string]any{"type": "json_object"}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return Message{}, Usage{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Message{}, Usage{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		hr.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	res, err := c.HTTP.Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return Message{}, Usage{}, errors.New("模型响应超时")
		}
		return Message{}, Usage{}, fmt.Errorf("无法连接模型服务：%w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return Message{}, Usage{}, err
	}
	var out chatResp
	jerr := json.Unmarshal(raw, &out)
	if res.StatusCode >= 400 {
		e := &Error{Status: res.StatusCode}
		if jerr == nil && out.Error != nil {
			e.Msg = clip(out.Error.Message, 200)
		}
		return Message{}, Usage{}, e
	}
	if jerr != nil {
		return Message{}, Usage{}, errors.New("模型服务返回格式无法解析（需兼容 OpenAI Chat Completions）")
	}
	if len(out.Choices) == 0 {
		return Message{}, out.Usage, errors.New("模型未返回结果")
	}
	m := out.Choices[0].Message
	m.Role = "assistant"
	return m, out.Usage, nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ExtractJSON 从模型输出中取出 JSON 对象（兼容 ```json 代码块或前后带说明文字的情况）。
func ExtractJSON(s string, v any) error {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	return json.Unmarshal([]byte(s), v)
}
