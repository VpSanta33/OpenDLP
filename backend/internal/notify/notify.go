// Package notify 实现告警外发通道：SMTP 邮件、企业微信群机器人、钉钉机器人、Syslog（CEF）。
// 仅依赖标准库；所有网络操作都有超时。
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Message 一条告警消息。
type Message struct {
	Title    string
	Text     string            // 正文（纯文本，多行）
	Severity string            // critical | high | medium | low | info
	Link     string            // 控制台内的相对链接，如 #/incidents?sev=critical
	CEF      map[string]string // 发往 SIEM 的扩展字段
	Event    string            // CEF 事件类别，如 incident / audit
	TS       time.Time
	Attach   *Attachment
}

type Attachment struct {
	Name, Mime string
	Data       []byte
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

/* ---------- SMTP ---------- */

// SMTP 邮件通道。Security: starttls（默认，587 端口）| tls（465）| none（仅限内网中继）。
type SMTP struct {
	Addr, From, User, Pass, Security string
	To                               []string
}

func (c SMTP) Send(ctx context.Context, m Message, base string) error {
	if c.Addr == "" || c.From == "" || len(c.To) == 0 {
		return errors.New("SMTP 配置不完整（服务器、发件人、收件人）")
	}
	host, _, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return fmt.Errorf("SMTP 服务器地址须为 host:port：%w", err)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if c.Security == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", c.Addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", c.Addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	cl, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.Security != "tls" && c.Security != "none" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("服务器不支持 STARTTLS；如确为内网中继，请将加密方式设为 none")
		}
		if err := cl.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if c.User != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.User, c.Pass, host)); err != nil {
			return fmt.Errorf("SMTP 认证失败：%w", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return err
	}
	for _, to := range c.To {
		if err := cl.Rcpt(to); err != nil {
			return fmt.Errorf("收件人 %s 被拒绝：%w", to, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(BuildMail(c.From, c.To, m, base)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// BuildMail 生成 MIME 邮件（UTF-8 正文 + 可选附件）。
func BuildMail(from string, to []string, m Message, base string) []byte {
	var b bytes.Buffer
	boundary := fmt.Sprintf("odlp-%d", time.Now().UnixNano())
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n",
		from, strings.Join(to, ", "), mime.BEncoding.Encode("UTF-8", "[OpenDLP] "+m.Title), time.Now().Format(time.RFC1123Z))
	body := m.Text
	if m.Link != "" && base != "" {
		body += "\n\n查看详情：" + strings.TrimRight(base, "/") + "/" + m.Link
	}
	enc := func(s string) string {
		raw := base64.StdEncoding.EncodeToString([]byte(s))
		var out strings.Builder
		for len(raw) > 76 {
			out.WriteString(raw[:76] + "\r\n")
			raw = raw[76:]
		}
		out.WriteString(raw)
		return out.String()
	}
	if m.Attach == nil {
		fmt.Fprintf(&b, "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", enc(body))
		return b.Bytes()
	}
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", boundary, enc(body))
	fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=%q\r\n\r\n%s\r\n",
		boundary, m.Attach.Mime, mime.BEncoding.Encode("UTF-8", m.Attach.Name), enc(string(m.Attach.Data)))
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

/* ---------- 企业微信 / 钉钉机器人 ---------- */

func markdown(m Message, base string) string {
	icon := map[string]string{"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[m.Severity]
	s := fmt.Sprintf("### %s %s\n%s", icon, m.Title, strings.ReplaceAll(m.Text, "\n", "\n\n"))
	if m.Link != "" && base != "" {
		s += fmt.Sprintf("\n\n[在控制台查看](%s/%s)", strings.TrimRight(base, "/"), m.Link)
	}
	return s
}

func postJSON(ctx context.Context, u string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(raw, &r) == nil && r.ErrCode != 0 {
		return fmt.Errorf("机器人返回错误 %d：%s", r.ErrCode, r.ErrMsg)
	}
	return nil
}

// CheckWebhook 只允许 https（或内网 http）地址。
func CheckWebhook(u string) error {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" || (p.Scheme != "https" && p.Scheme != "http") {
		return errors.New("Webhook 地址无效")
	}
	return nil
}

// WeCom 企业微信群机器人。
type WeCom struct{ Webhook string }

func (c WeCom) Send(ctx context.Context, m Message, base string) error {
	if err := CheckWebhook(c.Webhook); err != nil {
		return err
	}
	return postJSON(ctx, c.Webhook, map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": markdown(m, base)}})
}

// DingTalk 钉钉自定义机器人（可选加签）。
type DingTalk struct{ Webhook, Secret string }

func (c DingTalk) Send(ctx context.Context, m Message, base string) error {
	if err := CheckWebhook(c.Webhook); err != nil {
		return err
	}
	u := c.Webhook
	if c.Secret != "" {
		ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
		mac := hmac.New(sha256.New, []byte(c.Secret))
		mac.Write([]byte(ts + "\n" + c.Secret))
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + "timestamp=" + ts + "&sign=" + url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	return postJSON(ctx, u, map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": m.Title, "text": markdown(m, base)}})
}

/* ---------- Syslog / CEF ---------- */

// Syslog RFC 5424 报文 + CEF 负载，UDP 或 TCP（TCP 使用换行分帧）。
type Syslog struct{ Addr, Proto, Version string }

var cefSev = map[string]int{"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}

func cefEscHeader(s string) string { return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(s) }
func cefEscExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// FormatCEF 生成 RFC 5424 + CEF 格式的一行。
func FormatCEF(m Message, version string) string {
	host, _ := os.Hostname()
	sev := cefSev[m.Severity]
	pri := 8*10 + map[bool]int{true: 2, false: 5}[sev >= 8] // facility authpriv(10)，严重告警为 critical(2)，其余 notice(5)
	var ext []string
	keys := make([]string, 0, len(m.CEF))
	for k := range m.CEF {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		ext = append(ext, k+"="+cefEscExt(m.CEF[k]))
	}
	ts := m.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	cef := fmt.Sprintf("CEF:0|OpenDLP|OpenDLP|%s|%s|%s|%d|%s", cefEscHeader(version), cefEscHeader(m.Event), cefEscHeader(m.Title), sev, strings.Join(ext, " "))
	return fmt.Sprintf("<%d>1 %s %s opendlp - - - %s", pri, ts.UTC().Format(time.RFC3339), host, cef)
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (c Syslog) Send(ctx context.Context, m Message, _ string) error {
	proto := strings.ToLower(c.Proto)
	if proto != "tcp" {
		proto = "udp"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, proto, c.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line := FormatCEF(m, c.Version)
	if proto == "tcp" {
		line += "\n"
	}
	_, err = conn.Write([]byte(line))
	return err
}
