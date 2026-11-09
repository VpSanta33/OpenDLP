package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"opendlp/internal/notify"
	"opendlp/internal/store"
)

/* ---------- 执行周期 ----------
支持的周期写法（与控制台下拉选项一致）：
	每日 08:00
	每周一 09:00（一 … 日 / 天）
	每月 1 日 08:00（1-28 日）
	每季度首日 09:00
*/

var (
	reDaily   = regexp.MustCompile(`^每日\s*(\d{1,2}):(\d{2})$`)
	reWeekly  = regexp.MustCompile(`^每周([一二三四五六日天])\s*(\d{1,2}):(\d{2})$`)
	reMonthly = regexp.MustCompile(`^每月\s*(\d{1,2})\s*日\s*(\d{1,2}):(\d{2})$`)
	reQuarter = regexp.MustCompile(`^每季度首日\s*(\d{1,2}):(\d{2})$`)
	weekdayCN = map[string]time.Weekday{"一": time.Monday, "二": time.Tuesday, "三": time.Wednesday, "四": time.Thursday, "五": time.Friday, "六": time.Saturday, "日": time.Sunday, "天": time.Sunday}
)

type cronSpec struct {
	kind         string // daily | weekly | monthly | quarterly
	hour, minute int
	weekday      time.Weekday
	day          int
}

func parseCron(label string) (cronSpec, error) {
	label = strings.TrimSpace(label)
	hm := func(h, m string) (int, int, error) {
		hh, _ := strconv.Atoi(h)
		mm, _ := strconv.Atoi(m)
		if hh > 23 || mm > 59 {
			return 0, 0, errors.New("时间无效")
		}
		return hh, mm, nil
	}
	var c cronSpec
	var err error
	switch {
	case reDaily.MatchString(label):
		m := reDaily.FindStringSubmatch(label)
		c.kind = "daily"
		c.hour, c.minute, err = hm(m[1], m[2])
	case reWeekly.MatchString(label):
		m := reWeekly.FindStringSubmatch(label)
		c.kind, c.weekday = "weekly", weekdayCN[m[1]]
		c.hour, c.minute, err = hm(m[2], m[3])
	case reMonthly.MatchString(label):
		m := reMonthly.FindStringSubmatch(label)
		c.kind = "monthly"
		c.day, _ = strconv.Atoi(m[1])
		if c.day < 1 || c.day > 28 {
			return c, errors.New("每月执行日须为 1-28 日")
		}
		c.hour, c.minute, err = hm(m[2], m[3])
	case reQuarter.MatchString(label):
		m := reQuarter.FindStringSubmatch(label)
		c.kind = "quarterly"
		c.hour, c.minute, err = hm(m[1], m[2])
	default:
		return c, errors.New("不支持的执行周期，示例：每日 08:00、每周一 09:00、每月 1 日 08:00、每季度首日 09:00")
	}
	return c, err
}

// next 返回严格晚于 after 的下一次执行时间。
func (c cronSpec) next(after time.Time, loc *time.Location) time.Time {
	t := after.In(loc)
	at := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, c.hour, c.minute, 0, 0, loc) }
	switch c.kind {
	case "daily":
		n := at(t.Year(), t.Month(), t.Day())
		if !n.After(t) {
			n = at(t.Year(), t.Month(), t.Day()+1)
		}
		return n
	case "weekly":
		n := at(t.Year(), t.Month(), t.Day()+(int(c.weekday)-int(t.Weekday())+7)%7)
		if !n.After(t) {
			n = n.AddDate(0, 0, 7)
		}
		return n
	case "monthly":
		n := at(t.Year(), t.Month(), c.day)
		if !n.After(t) {
			n = at(t.Year(), t.Month()+1, c.day)
		}
		return n
	default: // quarterly
		qm := time.Month((int(t.Month())-1)/3*3 + 1)
		n := at(t.Year(), qm, 1)
		if !n.After(t) {
			n = at(t.Year(), qm+3, 1)
		}
		return n
	}
}

// period 一次执行所覆盖的统计周期（执行时刻之前的完整周期）。
func (c cronSpec) period(run time.Time, loc *time.Location) (time.Time, time.Time, string) {
	t := run.In(loc)
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	switch c.kind {
	case "daily":
		f := day.AddDate(0, 0, -1)
		return f, day, f.Format("2006-01-02")
	case "weekly":
		f := day.AddDate(0, 0, -7)
		return f, day, f.Format("2006-01-02") + " 至 " + day.AddDate(0, 0, -1).Format("2006-01-02")
	case "monthly":
		f := time.Date(t.Year(), t.Month()-1, 1, 0, 0, 0, 0, loc)
		return f, f.AddDate(0, 1, 0), fmt.Sprintf("%d 年 %d 月", f.Year(), int(f.Month()))
	default:
		qm := time.Month((int(t.Month())-1)/3*3 + 1)
		end := time.Date(t.Year(), qm, 1, 0, 0, 0, 0, loc)
		f := end.AddDate(0, -3, 0)
		return f, end, fmt.Sprintf("%d Q%d", f.Year(), (int(f.Month())-1)/3+1)
	}
}

// parseRecipients 校验接收人邮箱（1-20 个）。
func parseRecipients(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		a, err := mail.ParseAddress(v)
		if err != nil || a.Name != "" || !strings.Contains(a.Address, ".") {
			return nil, fmt.Errorf("「%s」不是有效的邮箱地址", clip(v, 60))
		}
		if k := strings.ToLower(a.Address); !seen[k] {
			seen[k] = true
			out = append(out, a.Address)
		}
	}
	if len(out) == 0 || len(out) > 20 {
		return nil, errors.New("请填写 1-20 个接收人邮箱")
	}
	return out, nil
}

// normalizeSchedules 启动时按执行周期重新计算下次执行时间（升级或时区变更后保持一致）。
// 已过期的执行时间保留，以便启动后补执行一次。
func (s *Server) normalizeSchedules() {
	now := time.Now()
	s.St.Write(func(d *store.Data) {
		for _, sc := range d.ReportSchedules {
			c, err := parseCron(sc.Cron)
			if err != nil || (sc.Next != 0 && sc.Next <= now.UnixMilli()) {
				continue
			}
			sc.Next = c.next(now, s.St.Loc).UnixMilli()
		}
	})
}

/* ---------- 执行 ---------- */

// runDueSchedules 由维护协程每 30 秒调用：执行所有到期的定时报表。
func (s *Server) runDueSchedules(ctx context.Context, now time.Time) {
	var due []store.Schedule
	s.St.Write(func(d *store.Data) {
		for _, sc := range d.ReportSchedules {
			if !sc.On || sc.Next == 0 || sc.Next > now.UnixMilli() {
				continue
			}
			c, err := parseCron(sc.Cron)
			if err != nil {
				sc.On, sc.LastErr = false, "执行周期无效，已暂停："+err.Error()
				continue
			}
			due = append(due, *sc)
			// 先推进下次执行时间，避免重复执行；停机错过的周期只补执行一次
			sc.Next = c.next(now, s.St.Loc).UnixMilli()
		}
	})
	for _, sc := range due {
		run := time.UnixMilli(sc.Next).In(s.St.Loc)
		if _, _, _, _, err := s.runSchedule(ctx, sc.ID, run, "定时任务"); err != nil {
			slog.Warn("定时报表执行失败", "id", sc.ID, "err", err)
		}
	}
}

// runSchedule 生成一次定时报表：按周期统计 → 渲染 → 归档 → 邮件发送给接收人，并记录执行结果。
// 返回生成的文件以便「立即执行」时直接下载；邮件失败不影响文件返回，但会作为 err 返回并记录。
func (s *Server) runSchedule(ctx context.Context, id string, run time.Time, by string) (string, string, []byte, string, error) {
	var sc store.Schedule
	found := false
	s.St.Read(func(d *store.Data) {
		for _, x := range d.ReportSchedules {
			if x.ID == id {
				sc, found = *x, true
			}
		}
	})
	if !found {
		return "", "", nil, "", errors.New("定时报表不存在")
	}
	c, err := parseCron(sc.Cron)
	if err != nil {
		return "", "", nil, "", err
	}
	from, to, label := c.period(run, s.St.Loc)
	title := reportTpl[sc.Tpl]
	name := fmt.Sprintf("%s（%s）", title, label)
	rd, err := s.buildReport(ctx, name, "全集团", from, to, by)
	if err != nil {
		s.finishSchedule(id, err)
		return "", "", nil, "", err
	}
	rd.Period = label
	fn, mime, data, err := renderReport(rd, sc.Fmt)
	if err != nil {
		s.finishSchedule(id, err)
		return "", "", nil, "", err
	}
	s.St.Write(func(d *store.Data) {
		d.Reports = append([]*store.Report{{ID: fmt.Sprintf("RPT-%d", 1+store.NextSeq(d, "report")), Name: name, Tpl: sc.Tpl, Range: "schedule", Fmt: sc.Fmt,
			Size: humanSize(len(data)), TS: time.Now().UnixMilli(), By: by, From: from.UnixMilli(), To: to.UnixMilli()}}, d.Reports...)
		if len(d.Reports) > 500 {
			d.Reports = d.Reports[:500]
		}
	})
	s.Hub.Publish(Event{Name: "reports.changed", Module: "reports", Data: map[string]string{"name": name}})
	msg := notify.Message{
		Title: "定时报表：" + name, Severity: "info", Event: "report", TS: time.Now(), Link: "#/reports",
		Text:   fmt.Sprintf("报表：%s\n统计周期：%s\n外发检测 %d 次，阻断 %d 次，DLP 事件 %d 起（严重 %d 起），处置完成率 %d%%。\n完整报表见附件。", title, label, rd.Detections, rd.Blocked, rd.Incidents, rd.Critical, rd.ResolvedPct),
		Attach: &notify.Attachment{Name: fn, Mime: mime, Data: data},
	}
	var mailErr error
	if to, err := parseRecipients(sc.To); err != nil {
		mailErr = fmt.Errorf("接收人须为邮箱地址（%v），请删除后重新创建该定时报表", err)
	} else {
		mailErr = s.Alerts.Mail(ctx, to, msg)
	}
	s.finishSchedule(id, mailErr)
	_ = s.St.AppendAudit(context.Background(), store.AuditEntry{Op: "system", Role: "系统", Type: "数据导出",
		Detail: fmt.Sprintf("执行定时报表「%s」并发送至 %s", name, strings.Join(sc.To, "、")), IP: "-", OK: mailErr == nil, Reason: errText(mailErr)})
	if mailErr != nil {
		s.addNote("warning", "定时报表发送失败", fmt.Sprintf("「%s」：%s", name, clip(mailErr.Error(), 120)), "#/reports")
	}
	return fn, mime, data, name, mailErr
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return clip(err.Error(), 200)
}

func (s *Server) finishSchedule(id string, err error) {
	s.St.Write(func(d *store.Data) {
		for _, x := range d.ReportSchedules {
			if x.ID == id {
				x.LastAt, x.LastErr = time.Now().UnixMilli(), errText(err)
			}
		}
	})
	s.Hub.Publish(Event{Name: "reports.changed", Module: "reports", Data: map[string]string{"schedule": id}})
}
