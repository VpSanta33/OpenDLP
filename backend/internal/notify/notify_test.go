package notify

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var msg = Message{Title: "严重事件：张伟 通过USB外发 core.zip", Severity: "critical", Text: "事件编号：INC-1\n用户：张伟", Link: "#/incidents", Event: "incident",
	CEF: map[string]string{"suser": "张伟", "fname": "a=b|c.zip"}}

func TestWeComAndDingTalk(t *testing.T) {
	var got map[string]any
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		query = r.URL.RawQuery
		w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()
	if err := (WeCom{Webhook: srv.URL + "/send?key=k"}).Send(context.Background(), msg, "https://dlp.corp.example"); err != nil {
		t.Fatal(err)
	}
	content := got["markdown"].(map[string]any)["content"].(string)
	if got["msgtype"] != "markdown" || !strings.Contains(content, "张伟") || !strings.Contains(content, "https://dlp.corp.example/#/incidents") {
		t.Fatalf("企业微信消息错误：%v", got)
	}
	if err := (DingTalk{Webhook: srv.URL + "/robot/send?access_token=t", Secret: "SEC123"}).Send(context.Background(), msg, ""); err != nil {
		t.Fatal(err)
	}
	q, _ := urlParse(query)
	mac := hmac.New(sha256.New, []byte("SEC123"))
	mac.Write([]byte(q["timestamp"] + "\nSEC123"))
	if q["sign"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || q["access_token"] != "t" {
		t.Fatalf("钉钉加签错误：%s", query)
	}
	// 机器人返回业务错误码应视为失败
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook"}`))
	}))
	defer bad.Close()
	if err := (WeCom{Webhook: bad.URL}).Send(context.Background(), msg, ""); err == nil || !strings.Contains(err.Error(), "93000") {
		t.Fatalf("应返回机器人错误：%v", err)
	}
	if err := (WeCom{Webhook: "ftp://x"}).Send(context.Background(), msg, ""); err == nil {
		t.Fatal("非 http(s) 地址应被拒绝")
	}
}

func urlParse(q string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range strings.Split(q, "&") {
		k, v, _ := strings.Cut(kv, "=")
		v = strings.NewReplacer("%2B", "+", "%2F", "/", "%3D", "=").Replace(v)
		out[k] = v
	}
	return out, nil
}

func TestSyslogCEF(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if err := (Syslog{Addr: pc.LocalAddr().String(), Version: "3.3.0"}).Send(context.Background(), msg, ""); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	line := string(buf[:n])
	if !strings.HasPrefix(line, "<82>1 ") || !strings.Contains(line, "CEF:0|OpenDLP|OpenDLP|3.3.0|incident|") || !strings.Contains(line, `fname=a\=b|c.zip`) || !strings.Contains(line, "|10|") {
		t.Fatalf("CEF 格式错误：%s", line)
	}
}

// 最小化的 SMTP 服务器（不支持 TLS），用于验证 security=none 时的完整投递流程。
func fakeSMTP(t *testing.T) (string, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		defer ln.Close()
		r := bufio.NewReader(c)
		w := func(s string) { c.Write([]byte(s + "\r\n")) }
		w("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				w("250 fake")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				w("250 OK")
			case cmd == "DATA":
				w("354 go ahead")
				for {
					l, _ := r.ReadString('\n')
					if strings.TrimRight(l, "\r\n") == "." {
						break
					}
					data.WriteString(l)
				}
				w("250 queued")
			case cmd == "QUIT":
				w("221 bye")
				out <- data.String()
				return
			default:
				w("250 OK")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestSMTP(t *testing.T) {
	addr, got := fakeSMTP(t)
	m := msg
	m.Attach = &Attachment{Name: "月报.html", Mime: "text/html; charset=utf-8", Data: []byte("<h1>报告</h1>")}
	c := SMTP{Addr: addr, From: "dlp@corp.example", To: []string{"sec@corp.example"}, Security: "none"}
	if err := c.Send(context.Background(), m, "https://dlp.corp.example"); err != nil {
		t.Fatal(err)
	}
	raw := <-got
	if !strings.Contains(raw, "Subject: =?UTF-8?b?") || !strings.Contains(raw, "multipart/mixed") || !strings.Contains(raw, "Content-Disposition: attachment") {
		t.Fatalf("邮件格式错误：%s", raw)
	}
	// 未开启 STARTTLS 的服务器默认应拒绝发送（避免明文传输口令）
	addr2, _ := fakeSMTP(t)
	if err := (SMTP{Addr: addr2, From: "a@b", To: []string{"c@d"}}).Send(context.Background(), msg, ""); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("应要求 STARTTLS：%v", err)
	}
}
