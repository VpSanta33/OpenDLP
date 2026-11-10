package store

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

const hourMs = int64(time.Hour / time.Millisecond)

func actionCols(action string) (allowed, audited, encrypted, blocked int) {
	switch action {
	case "block":
		return 0, 0, 0, 1
	case "encrypt":
		return 0, 0, 1, 0
	case "audit":
		return 0, 1, 0, 0
	}
	return 1, 0, 0, 0
}

// AddDetection 记录一次外发检测（按小时 / 渠道 / 数据类型累加）。
func (s *Store) AddDetection(ctx context.Context, ts int64, ch, dt, action string) error {
	al, au, en, bl := actionCols(action)
	_, err := s.DB.Exec(ctx, `INSERT INTO detections_hourly (h, channel, data_type, total, allowed, audited, encrypted, blocked)
		VALUES ($1, $2, $3, 1, $4, $5, $6, $7)
		ON CONFLICT (h, channel, data_type) DO UPDATE SET total = detections_hourly.total + 1,
			allowed = detections_hourly.allowed + EXCLUDED.allowed, audited = detections_hourly.audited + EXCLUDED.audited,
			encrypted = detections_hourly.encrypted + EXCLUDED.encrypted, blocked = detections_hourly.blocked + EXCLUDED.blocked`,
		time.UnixMilli(ts-ts%hourMs), ch, dt, al, au, en, bl)
	return err
}

// DetectionKey / DetectionCount 用于批量导入检测量。
type DetectionKey struct {
	H      int64
	Ch, DT string
}
type DetectionCount struct{ Total, Allowed, Audited, Encrypted, Blocked int }

func (c *DetectionCount) Add(action string) {
	al, au, en, bl := actionCols(action)
	c.Total++
	c.Allowed += al
	c.Audited += au
	c.Encrypted += en
	c.Blocked += bl
}

// CopyDetections 批量写入检测量（演示数据初始化使用）。
func (s *Store) CopyDetections(ctx context.Context, m map[DetectionKey]*DetectionCount) error {
	rows := make([][]any, 0, len(m))
	for k, c := range m {
		rows = append(rows, []any{time.UnixMilli(k.H), k.Ch, k.DT, c.Total, c.Allowed, c.Audited, c.Encrypted, c.Blocked})
	}
	_, err := s.DB.CopyFrom(ctx, pgx.Identifier{"detections_hourly"}, []string{"h", "channel", "data_type", "total", "allowed", "audited", "encrypted", "blocked"}, pgx.CopyFromRows(rows))
	return err
}

// PurgeDetections 删除早于 before 的检测量聚合。
func (s *Store) PurgeDetections(ctx context.Context, before time.Time) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM detections_hourly WHERE h < $1`, before)
	return err
}

type KV struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

type KPI struct {
	Events   int                 `json:"events"`
	Blocked  int                 `json:"blocked"`
	Pending  int                 `json:"pending"`
	Online   int                 `json:"online"`
	Deployed int                 `json:"deployed"`
	Delta    map[string]*float64 `json:"delta"`
	Sparks   map[string][]int    `json:"sparks"`
}

type RiskFactor struct {
	Name  string `json:"name"`
	Pct   int    `json:"pct"`
	Label string `json:"label"`
	Tone  string `json:"tone"`
}

type Risk struct {
	Score   int          `json:"score"`
	Level   string       `json:"level"`
	Tone    string       `json:"tone"`
	Factors []RiskFactor `json:"factors"`
}

// Flow 今日检测在引擎中的流向统计。
type Flow struct {
	Total int `json:"total"`
	Allow int `json:"allow"`
	Audit int `json:"audit"`
	Block int `json:"block"`
	Rules int `json:"rules"`
}

type Dashboard struct {
	Range     string   `json:"range"`
	Labels    []string `json:"labels"`
	Alerts    []int    `json:"alerts"`
	Blocked   []int    `json:"blocked"`
	Prev      []int    `json:"prev"`
	KPI       KPI      `json:"kpi"`
	Channels  []KV     `json:"channels"`
	DataTypes []KV     `json:"dataTypes"`
	Heatmap   [][]int  `json:"heatmap"`
	Risk      Risk     `json:"risk"`
	Flow      Flow     `json:"flow"`
	Empty     bool     `json:"empty"`
}

type slot struct{ from, to int64 }

func slots(now time.Time, n int, hourly bool, loc *time.Location) []slot {
	now = now.In(loc)
	out := make([]slot, n)
	if hourly {
		cur := now.Truncate(time.Hour)
		for i := 0; i < n; i++ {
			s := cur.Add(-time.Duration(n-1-i) * time.Hour)
			out[i] = slot{s.UnixMilli(), s.Add(time.Hour).UnixMilli()}
		}
		return out
	}
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	for i := 0; i < n; i++ {
		s := day.AddDate(0, 0, -(n - 1 - i))
		out[i] = slot{s.UnixMilli(), s.AddDate(0, 0, 1).UnixMilli()}
	}
	return out
}

// delta 环比变化百分比；上周期样本过少（< 10）时不具备比较意义，返回 nil。
func delta(cur, prev int) *float64 {
	if prev < 10 {
		return nil
	}
	v := math.Round(float64(cur-prev)/float64(prev)*1000) / 10
	return &v
}

type hourAgg struct{ total, blocked int }

func sumHours(m map[int64]hourAgg, from, to int64, blocked bool) int {
	t := 0
	for h := from - from%hourMs; h < to; h += hourMs {
		if a, ok := m[h]; ok && h >= from {
			if blocked {
				t += a.blocked
			} else {
				t += a.total
			}
		}
	}
	return t
}

func pct(a, b int) int {
	if b == 0 {
		return 0
	}
	return a * 100 / b
}

// BuildDashboard 基于检测量聚合与事件数据计算总览数据。
func (s *Store) BuildDashboard(ctx context.Context, rangeKey string, now time.Time) (Dashboard, error) {
	loc := s.Loc
	n, hourly := 30, false
	switch rangeKey {
	case "today":
		n, hourly = 24, true
	case "7d":
		n = 7
	default:
		rangeKey = "30d"
	}
	// 配置快照
	var channels, dataTypes, leaving []string
	var polEnabled, polTotal, rules int
	var fleet Fleet
	s.Read(func(d *Data) {
		for _, c := range d.Channels {
			channels = append(channels, c.Key)
		}
		for _, t := range d.DataTypes {
			dataTypes = append(dataTypes, t.Key)
		}
		for _, e := range d.Employees {
			if e.Status == "leaving" {
				leaving = append(leaving, e.Name)
			}
		}
		for _, p := range d.Policies {
			polTotal++
			if p.Enabled {
				polEnabled++
			}
		}
		for _, r := range d.Rules {
			if r.Enabled {
				rules++
			}
		}
		fleet = d.Fleet(now)
	})

	cur := slots(now, n, hourly, loc)
	prev := slots(now, 2*n, hourly, loc)[:n]
	sp := slots(now, 16, hourly, loc)
	from, to := cur[0].from, cur[n-1].to
	pFrom, pTo := prev[0].from, prev[n-1].to
	heatFrom := now.Add(-7 * 24 * time.Hour).UnixMilli()
	qFrom := min(pFrom, sp[0].from, heatFrom)

	// 小时级检测量
	hours := map[int64]hourAgg{}
	rows, err := s.DB.Query(ctx, `SELECT (extract(epoch FROM h)*1000)::bigint, sum(total), sum(blocked) FROM detections_hourly WHERE h >= $1 AND h < $2 GROUP BY h`,
		time.UnixMilli(qFrom), time.UnixMilli(to))
	if err != nil {
		return Dashboard{}, err
	}
	for rows.Next() {
		var h int64
		var a hourAgg
		if err := rows.Scan(&h, &a.total, &a.blocked); err != nil {
			rows.Close()
			return Dashboard{}, err
		}
		hours[h] = a
	}
	rows.Close()
	var oldestBucket, oldestInc int64
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE((extract(epoch FROM min(h))*1000)::bigint, 0) FROM detections_hourly`).Scan(&oldestBucket); err != nil {
		return Dashboard{}, err
	}
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE((extract(epoch FROM min(ts))*1000)::bigint, 0) FROM incidents`).Scan(&oldestInc); err != nil {
		return Dashboard{}, err
	}

	db := Dashboard{Range: rangeKey}
	for i, sl := range cur {
		t := time.UnixMilli(sl.from).In(loc)
		if hourly {
			db.Labels = append(db.Labels, fmt.Sprintf("%02d:00", t.Hour()))
		} else {
			db.Labels = append(db.Labels, fmt.Sprintf("%d/%d", int(t.Month()), t.Day()))
		}
		db.Alerts = append(db.Alerts, sumHours(hours, sl.from, sl.to, false))
		db.Blocked = append(db.Blocked, sumHours(hours, sl.from, sl.to, true))
		db.Prev = append(db.Prev, sumHours(hours, prev[i].from, prev[i].to, false))
	}

	k := KPI{Delta: map[string]*float64{}, Sparks: map[string][]int{}, Online: fleet.Online, Deployed: fleet.Deployed}
	k.Events = sumHours(hours, from, to, false)
	k.Blocked = sumHours(hours, from, to, true)
	if oldestBucket > 0 && oldestBucket <= pFrom { // 数据完整覆盖上一周期才计算环比
		k.Delta["events"] = delta(k.Events, sumHours(hours, pFrom, pTo, false))
		k.Delta["blocked"] = delta(k.Blocked, sumHours(hours, pFrom, pTo, true))
	}
	var hiCur, hiPrev int
	if err := s.DB.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE status = 'pending'),
			count(*) FILTER (WHERE ts >= $1 AND ts < $2),
			count(*) FILTER (WHERE ts >= $3 AND ts < $4)
		FROM incidents WHERE severity IN ('critical', 'high')`,
		time.UnixMilli(from), time.UnixMilli(to), time.UnixMilli(pFrom), time.UnixMilli(pTo)).Scan(&k.Pending, &hiCur, &hiPrev); err != nil {
		return Dashboard{}, err
	}
	if oldestInc > 0 && oldestInc <= pFrom {
		k.Delta["pending"] = delta(hiCur, hiPrev)
	}
	hiTimes := []int64{}
	rows, err = s.DB.Query(ctx, `SELECT (extract(epoch FROM ts)*1000)::bigint FROM incidents WHERE severity IN ('critical', 'high') AND ts >= $1`, time.UnixMilli(sp[0].from))
	if err != nil {
		return Dashboard{}, err
	}
	for rows.Next() {
		var t int64
		if err := rows.Scan(&t); err == nil {
			hiTimes = append(hiTimes, t)
		}
	}
	rows.Close()
	for _, sl := range sp {
		k.Sparks["events"] = append(k.Sparks["events"], sumHours(hours, sl.from, sl.to, false))
		k.Sparks["blocked"] = append(k.Sparks["blocked"], sumHours(hours, sl.from, sl.to, true))
		c := 0
		for _, t := range hiTimes {
			if t >= sl.from && t < sl.to {
				c++
			}
		}
		k.Sparks["pending"] = append(k.Sparks["pending"], c)
	}
	db.KPI = k

	// 渠道与数据类型分布
	dist := func(col string, keys []string) ([]KV, error) {
		m := map[string]int{}
		rows, err := s.DB.Query(ctx, `SELECT `+col+`, sum(total) FROM detections_hourly WHERE h >= $1 AND h < $2 GROUP BY 1`, time.UnixMilli(from), time.UnixMilli(to))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			var v int
			if err := rows.Scan(&key, &v); err != nil {
				return nil, err
			}
			m[key] = v
		}
		out := make([]KV, 0, len(keys))
		for _, kk := range keys {
			out = append(out, KV{kk, m[kk]})
		}
		return out, rows.Err()
	}
	if db.Channels, err = dist("channel", channels); err != nil {
		return Dashboard{}, err
	}
	if db.DataTypes, err = dist("data_type", dataTypes); err != nil {
		return Dashboard{}, err
	}

	// 近 7 天热力图：行 = 周一..周日，列 = 0..23 时
	db.Heatmap = make([][]int, 7)
	for r := range db.Heatmap {
		db.Heatmap[r] = make([]int, 24)
	}
	for h, a := range hours {
		if h >= heatFrom {
			t := time.UnixMilli(h).In(loc)
			db.Heatmap[(int(t.Weekday())+6)%7][t.Hour()] += a.total
		}
	}

	// 今日流向
	nowL := now.In(loc)
	today := time.Date(nowL.Year(), nowL.Month(), nowL.Day(), 0, 0, 0, 0, loc)
	if err := s.DB.QueryRow(ctx, `SELECT COALESCE(sum(total),0), COALESCE(sum(allowed),0), COALESCE(sum(audited)+sum(encrypted),0), COALESCE(sum(blocked),0)
		FROM detections_hourly WHERE h >= $1`, today).Scan(&db.Flow.Total, &db.Flow.Allow, &db.Flow.Audit, &db.Flow.Block); err != nil {
		return Dashboard{}, err
	}
	db.Flow.Rules = rules

	// 综合风险
	var tot, hi, lv, usb int
	if err := s.DB.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE severity IN ('critical', 'high')),
			count(*) FILTER (WHERE user_name = ANY($2)),
			count(*) FILTER (WHERE channel = 'usb' AND action NOT IN ('block', 'encrypt'))
		FROM incidents WHERE ts >= $1`, now.Add(-30*24*time.Hour), leaving).Scan(&tot, &hi, &lv, &usb); err != nil {
		return Dashboard{}, err
	}
	db.Risk = buildRisk(tot, hi, lv, usb, polEnabled, polTotal)
	db.Empty = oldestBucket == 0 && oldestInc == 0
	return db, nil
}

func buildRisk(tot, hi, leaving, usb, polEnabled, polTotal int) Risk {
	hiPct := pct(hi, tot)
	cov := 0
	if polTotal > 0 {
		cov = polEnabled * 100 / polTotal
	}
	score := int(math.Round(float64(hiPct)*0.55 + math.Min(float64(leaving), 20)*1.0 + math.Min(float64(usb), 40)*0.3 + float64(100-cov)*0.4))
	score = max(0, min(99, score))
	if tot == 0 && polTotal == 0 {
		score = 0
	}
	r := Risk{Score: score}
	switch {
	case tot == 0 && polTotal == 0:
		r.Level, r.Tone = "暂无数据", "primary"
	case score >= 80:
		r.Level, r.Tone = "高风险", "danger"
	case score >= 55:
		r.Level, r.Tone = "中等风险", "warning"
	default:
		r.Level, r.Tone = "低风险", "success"
	}
	tone := func(bad bool) string {
		if bad {
			return "hot"
		}
		return "warm"
	}
	r.Factors = []RiskFactor{
		{"高危事件占比", hiPct, fmt.Sprintf("%d%%", hiPct), tone(hiPct > 40)},
		{"离职人员外发", min(100, leaving*5), fmt.Sprintf("%d 起", leaving), tone(leaving > 5)},
		{"U 盘外发未阻断", min(100, usb*2), fmt.Sprintf("%d 次", usb), tone(usb > 30)},
		{"策略启用率", cov, fmt.Sprintf("%d%%", cov), "ok"},
	}
	return r
}
