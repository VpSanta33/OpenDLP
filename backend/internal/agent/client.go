package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"opendlp/internal/detect"
)

// ErrUnauthorized 凭据无效或已被吊销，需要重新注册。
var ErrUnauthorized = errors.New("终端凭据无效或已被吊销")

// HeartbeatReq 心跳 / 注册请求。
type HeartbeatReq struct {
	Host          string `json:"host"`
	User          string `json:"user,omitempty"`
	Dept          string `json:"dept,omitempty"`
	IP            string `json:"ip,omitempty"`
	OS            string `json:"os,omitempty"`
	OSKey         string `json:"osKey,omitempty"`
	Agent         string `json:"agent"`
	CPU           int    `json:"cpu"`
	Mem           int    `json:"mem"`
	Disk          int    `json:"disk"`
	Warning       bool   `json:"warning,omitempty"`
	PolicyVersion string `json:"policyVersion,omitempty"`
}

// Command 服务端下发的指令。
type Command struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

type HeartbeatResp struct {
	Commands      []Command `json:"commands"`
	PolicyVersion string    `json:"policyVersion"`
	Interval      int       `json:"interval"`
}

// Bundle 策略包（与服务端 api.Bundle 一致）。
type Bundle struct {
	Version   string            `json:"version"`
	Generated int64             `json:"generated"`
	Strict    bool              `json:"strict"`
	Policies  []detect.Policy   `json:"policies"`
	Rules     []detect.Rule     `json:"rules"`
	DataTypes map[string]string `json:"dataTypes"`
}

// Detection 上报的一条检测结果（与服务端 ingestItem 一致）。
type Detection struct {
	TS       int64    `json:"ts"`
	User     string   `json:"user"`
	Host     string   `json:"host"`
	IP       string   `json:"ip,omitempty"`
	Channel  string   `json:"channel"`
	Dest     string   `json:"dest"`
	DataType string   `json:"dataType"`
	File     string   `json:"file"`
	Size     string   `json:"size"`
	Matches  int      `json:"matches"`
	PolicyID string   `json:"policyId,omitempty"`
	Action   string   `json:"action"`
	Severity string   `json:"severity,omitempty"`
	RuleIDs  []string `json:"ruleIds,omitempty"`
}

// Client 与管理控制台通信。
type Client struct {
	Base   string
	HTTP   *http.Client
	ID     string
	Secret string
}

func NewClient(base, caFile string) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("读取 CA 证书失败: %w", err)
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA 证书格式无效")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &Client{Base: base, HTTP: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
}

// apiError 服务端返回的业务错误。
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Msg) }

func (c *Client) do(ctx context.Context, method, path, auth string, body any, hdr map[string]string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "opendlp-agent/"+Version)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		res.Body.Close()
		return nil, ErrUnauthorized
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		var e struct{ Error string }
		_ = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&e)
		return nil, &apiError{res.StatusCode, e.Error}
	}
	return res, nil
}

func (c *Client) cred() string { return "Agent " + c.ID + ":" + c.Secret }

func decode(res *http.Response, v any) error {
	defer res.Body.Close()
	return json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(v)
}

// Enroll 使用注册令牌换取终端凭据。
func (c *Client) Enroll(ctx context.Context, token string, hb HeartbeatReq) error {
	res, err := c.do(ctx, "POST", "/api/v1/agent/enroll", "Bearer "+token, hb, nil)
	if errors.Is(err, ErrUnauthorized) {
		return errors.New("注册令牌无效，请在控制台「终端管理 → 部署 Agent」中获取")
	}
	if err != nil {
		return err
	}
	var out struct{ AgentID, Secret string }
	if err := decode(res, &out); err != nil {
		return err
	}
	if out.AgentID == "" || out.Secret == "" {
		return errors.New("注册响应缺少凭据")
	}
	c.ID, c.Secret = out.AgentID, out.Secret
	return nil
}

func (c *Client) Heartbeat(ctx context.Context, hb HeartbeatReq) (HeartbeatResp, error) {
	var out HeartbeatResp
	res, err := c.do(ctx, "POST", "/api/v1/agent/heartbeat", c.cred(), hb, nil)
	if err != nil {
		return out, err
	}
	return out, decode(res, &out)
}

// Policy 拉取策略包；etag 与服务端一致时返回 (nil, nil)。
func (c *Client) Policy(ctx context.Context, version string) (*Bundle, error) {
	hdr := map[string]string{}
	if version != "" {
		hdr["If-None-Match"] = `"` + version + `"`
	}
	res, err := c.do(ctx, "GET", "/api/v1/agent/policy", c.cred(), nil, hdr)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotModified {
		res.Body.Close()
		return nil, nil
	}
	var b Bundle
	if err := decode(res, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (c *Client) Detections(ctx context.Context, list []Detection) error {
	res, err := c.do(ctx, "POST", "/api/v1/agent/detections", c.cred(), list, nil)
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

func (c *Client) CommandResult(ctx context.Context, id string, ok bool, msg string) error {
	res, err := c.do(ctx, "POST", "/api/v1/agent/commands/"+id+"/result", c.cred(), map[string]any{"ok": ok, "message": msg}, nil)
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

// retryable 网络错误或服务端 5xx 可稍后重试；4xx（除 401）为数据问题，不重试。
func retryable(err error) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests
	}
	return err != nil && !errors.Is(err, ErrUnauthorized)
}
