package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"opendlp/internal/notify"
	"opendlp/internal/store"
)

// sender 一个可用的告警通道。
type sender interface {
	Send(ctx context.Context, m notify.Message, base string) error
}

// 集成 key → 系统设置中的开关 key（「告警通知」卡片）。
var channelToggle = map[string]string{"smtp": "mail", "wecom": "wecom", "ding": "ding", "siem": "siem"}

// buildSender 根据集成配置构造通道（须在锁内调用）；未配置或配置不完整时返回 nil。
func buildSender(it *store.Integration, version string) sender {
	c := it.Config
	if it.St == "off" || c == nil {
		return nil
	}
	switch it.Key {
	case "smtp":
		var to []string
		for _, x := range strings.FieldsFunc(c["收件人"], func(r rune) bool { return r == ',' || r == ';' || r == '，' || r == ' ' }) {
			to = append(to, strings.TrimSpace(x))
		}
		return notify.SMTP{Addr: c["SMTP 服务器"], From: c["发件人"], User: c["用户名"], Pass: c["口令"], Security: c["加密方式"], To: to}
	case "wecom":
		if c["Webhook 地址"] != "" {
			return notify.WeCom{Webhook: c["Webhook 地址"]}
		}
	case "ding":
		if c["Webhook 地址"] != "" {
			return notify.DingTalk{Webhook: c["Webhook 地址"], Secret: c["加签密钥"]}
		}
	case "siem":
		addr := c["Syslog 地址"]
		if addr == "" {
			return nil
		}
		if !strings.Contains(addr, ":") && c["端口"] != "" {
			addr += ":" + c["端口"]
		} else if !strings.Contains(addr, ":") {
			addr += ":514"
		}
		return notify.Syslog{Addr: addr, Proto: c["协议"], Version: version}
	}
	return nil
}

// 告警意图的类别：人工通道 / SIEM / 事件（由分发协程按严重级别与汇总频率决定去向）。
const (
	toHuman = iota
	toSIEM
	toIncident
)

type alertIntent struct {
	kind int
	msg  notify.Message
}

// Alerts 告警分发器：异步队列 + 重试 + 投递统计 + 中低危汇总。
//
// 对外方法（Human / SIEM / Incident / Audit）只做非阻塞入队、不获取任何锁，
// 因此可在持有配置锁的代码路径中安全调用（例如 mutate 内写审计日志）。
// 通道选择与汇总判断在 Run 的分发协程中进行。
type Alerts struct {
	s      *Server
	ctx    context.Context
	in     chan alertIntent
	qs     map[string]chan notify.Message // 每个通道独立队列与投递协程，故障通道的重试不阻塞其他通道
	digest []notify.Message
	last   time.Time
}

func newAlerts(s *Server) *Alerts {
	return &Alerts{s: s, in: make(chan alertIntent, 4000), qs: map[string]chan notify.Message{}, last: time.Now()}
}

// targets 当前启用的通道；human=true 时为人工通知通道（邮件 / IM），否则为 SIEM。
func (al *Alerts) targets(human bool) []string {
	var keys []string
	al.s.St.Read(func(d *store.Data) {
		for _, it := range d.Integrations {
			tg, ok := channelToggle[it.Key]
			if !ok || (it.Key == "siem") == human {
				continue
			}
			if on, _ := d.Settings[tg].(bool); on && buildSender(it, al.s.Cfg.Version) != nil {
				keys = append(keys, it.Key)
			}
		}
	})
	return keys
}

func (al *Alerts) post(kind int, m notify.Message) {
	if m.TS.IsZero() {
		m.TS = time.Now()
	}
	select {
	case al.in <- alertIntent{kind, m}:
	default:
		slog.Warn("告警队列已满，丢弃消息", "title", m.Title)
	}
}

// Human 发送给人工通知通道（邮件 / 企业微信 / 钉钉）。
func (al *Alerts) Human(m notify.Message) { al.post(toHuman, m) }

// SIEM 转发给 SIEM（Syslog / CEF）。
func (al *Alerts) SIEM(m notify.Message) { al.post(toSIEM, m) }

// Incident 事件告警：全部转发 SIEM；严重 / 高危立即通知，中低危按「告警汇总频率」合并。
func (al *Alerts) Incident(inc store.Incident, chName, dtName string) {
	al.post(toIncident, notify.Message{
		Title: fmt.Sprintf("%s事件：%s 通过%s外发 %s", sevName[inc.Severity], inc.User, chName, inc.File), Severity: inc.Severity,
		Text: fmt.Sprintf("事件编号：%s\n用户：%s %s\n终端：%s %s\n外发渠道：%s → %s\n敏感数据：%s（命中 %d 处）\n命中策略：%s\n处置动作：%s",
			inc.ID, inc.User, inc.Dept, inc.Host, inc.IP, chName, inc.Dest, dtName, inc.Matches, inc.Policy, actName[inc.Action]),
		Link: "#/incidents", Event: "incident", TS: time.UnixMilli(inc.TS),
		CEF: map[string]string{"externalId": inc.ID, "suser": inc.User, "shost": inc.Host, "src": inc.IP, "fname": inc.File, "fsize": inc.Size,
			"act": inc.Action, "cs1Label": "policy", "cs1": inc.Policy, "cs2Label": "channel", "cs2": inc.Channel, "cs3Label": "dataType", "cs3": inc.DataType,
			"cn1Label": "matches", "cn1": fmt.Sprint(inc.Matches), "duser": inc.Dest, "rt": fmt.Sprint(inc.TS)},
	})
}

// Audit 审计日志转发 SIEM。
func (al *Alerts) Audit(e store.AuditEntry) {
	sev := "info"
	if !e.OK {
		sev = "medium"
	}
	al.SIEM(notify.Message{Title: e.Type + "：" + e.Detail, Severity: sev, Event: "audit", TS: time.UnixMilli(e.TS),
		CEF: map[string]string{"externalId": e.ID, "suser": e.Op, "src": e.IP, "outcome": map[bool]string{true: "success", false: "failure"}[e.OK],
			"reason": e.Reason, "cs1Label": "role", "cs1": e.Role, "cs2Label": "hash", "cs2": e.Hash, "rt": fmt.Sprint(e.TS)}})
}

// fanout 投递到各启用通道的队列（仅在分发协程中调用，qs 无需加锁）。
func (al *Alerts) fanout(human bool, m notify.Message) {
	for _, k := range al.targets(human) {
		q, ok := al.qs[k]
		if !ok {
			q = make(chan notify.Message, 500)
			al.qs[k] = q
			go al.deliver(al.ctx, k, q)
		}
		select {
		case q <- m:
		default:
			slog.Warn("告警发送队列已满，丢弃消息", "channel", k, "title", m.Title)
		}
	}
}

// dispatch 在分发协程中把告警意图展开到具体通道。
func (al *Alerts) dispatch(it alertIntent) {
	switch it.kind {
	case toHuman:
		al.fanout(true, it.msg)
	case toSIEM:
		al.fanout(false, it.msg)
	case toIncident:
		al.fanout(false, it.msg)
		freq, watched := "", false
		al.s.St.Read(func(d *store.Data) {
			freq, _ = d.Settings["freq"].(string)
			for _, u := range d.Watchlist {
				watched = watched || u == it.msg.CEF["suser"]
			}
		})
		if s := it.msg.Severity; s == "critical" || s == "high" || freq == "实时" || watched {
			al.fanout(true, it.msg)
		} else if len(al.digest) < 500 {
			al.digest = append(al.digest, it.msg)
		}
	}
}

var digestEvery = map[string]time.Duration{"每 15 分钟": 15 * time.Minute, "每小时": time.Hour, "每日汇总": 24 * time.Hour}

// flushDigest 到达汇总周期时合并发送中低危事件（仅在分发协程中调用）。
func (al *Alerts) flushDigest(now time.Time) {
	freq := ""
	al.s.St.Read(func(d *store.Data) { freq, _ = d.Settings["freq"].(string) })
	every := digestEvery[freq]
	if every == 0 {
		every = 15 * time.Minute
	}
	if now.Sub(al.last) < every || len(al.digest) == 0 {
		return
	}
	list := al.digest
	al.digest, al.last = nil, now
	var b strings.Builder
	for i, m := range list {
		if i >= 30 {
			fmt.Fprintf(&b, "… 另有 %d 起\n", len(list)-30)
			break
		}
		fmt.Fprintf(&b, "· %s %s\n", m.TS.In(al.s.St.Loc).Format("01-02 15:04"), m.Title)
	}
	al.fanout(true, notify.Message{Title: fmt.Sprintf("中低危事件汇总（%d 起）", len(list)), Severity: "medium", Text: b.String(), Link: "#/incidents", Event: "digest", TS: now})
}

// Run 启动分发协程与投递协程。投递失败重试 3 次（立即、5 秒、30 秒），并记录到集成的投递统计。
func (al *Alerts) Run(ctx context.Context) {
	al.ctx = ctx
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			al.flushDigest(now)
		case it := <-al.in:
			al.dispatch(it)
		}
	}
}

func (al *Alerts) deliver(ctx context.Context, key string, q <-chan notify.Message) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-q:
			for i, wait := range []time.Duration{0, 5 * time.Second, 30 * time.Second} {
				if wait > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(wait):
					}
				}
				err := al.sendNow(ctx, key, m)
				if err == nil {
					break
				}
				slog.Warn("告警发送失败", "channel", key, "attempt", i+1, "err", err)
			}
		}
	}
}

// Mail 通过「告警邮件 (SMTP)」集成发送给指定收件人（定时报表使用），同步返回结果并计入投递统计。
func (al *Alerts) Mail(ctx context.Context, to []string, m notify.Message) error {
	var sd notify.SMTP
	ok := false
	base := ""
	al.s.St.Read(func(d *store.Data) {
		for _, it := range d.Integrations {
			if it.Key == "smtp" {
				if x, isSMTP := buildSender(it, al.s.Cfg.Version).(notify.SMTP); isSMTP {
					sd, ok = x, true
				}
			}
		}
		base, _ = d.Settings["consoleUrl"].(string)
	})
	if !ok {
		return fmt.Errorf("未配置「告警邮件 (SMTP)」集成，报表已归档但未发送")
	}
	sd.To = to
	var err error
	if al.s.Cfg.Demo {
		slog.Debug("演示模式：模拟发送报表邮件", "to", to, "title", m.Title)
	} else {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		err = sd.Send(cctx, m, base)
	}
	al.record("smtp", err)
	return err
}

// record 记录一次投递结果到集成的投递统计。
func (al *Alerts) record(key string, err error) {
	al.s.St.Write(func(d *store.Data) {
		for _, it := range d.Integrations {
			if it.Key != key {
				continue
			}
			if it.Delivery == nil {
				it.Delivery = &store.Delivery{}
			}
			it.Delivery.LastAt = time.Now().UnixMilli()
			if err != nil {
				it.Delivery.Fail++
				it.Delivery.LastErr = clip(err.Error(), 200)
			} else {
				it.Delivery.OK++
				it.Delivery.LastErr = ""
			}
		}
	})
}

// sendNow 立即发送一条消息并记录投递统计。
func (al *Alerts) sendNow(ctx context.Context, key string, m notify.Message) error {
	var sd sender
	base := ""
	al.s.St.Read(func(d *store.Data) {
		for _, it := range d.Integrations {
			if it.Key == key {
				sd = buildSender(it, al.s.Cfg.Version)
			}
		}
		base, _ = d.Settings["consoleUrl"].(string)
	})
	if sd == nil {
		return fmt.Errorf("通道 %s 未配置", key)
	}
	var err error
	if al.s.Cfg.Demo {
		// 演示模式不访问外部网络：演示数据中的通道地址均为虚构，只模拟投递并计入统计
		slog.Debug("演示模式：模拟告警投递", "channel", key, "title", m.Title)
	} else {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		err = sd.Send(cctx, m, base)
	}
	al.record(key, err)
	return err
}
