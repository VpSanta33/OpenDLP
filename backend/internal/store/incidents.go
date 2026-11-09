package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// IncidentFilter 事件查询条件（空值或 "all" 表示不限）。
type IncidentFilter struct {
	Q, Sev, Ch, St, User string
	Dept, DataType       string
	From, To             int64
}

func (f IncidentFilter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(c string, v any) { args = append(args, v); conds = append(conds, fmt.Sprintf(c, len(args))) }
	if f.Sev != "" && f.Sev != "all" {
		add("severity = $%d", f.Sev)
	}
	if f.Ch != "" && f.Ch != "all" {
		add("channel = $%d", f.Ch)
	}
	if f.St != "" && f.St != "all" {
		add("status = $%d", f.St)
	}
	if f.User != "" {
		add("user_name = $%d", f.User)
	}
	if f.Dept != "" {
		add("dept = $%d", f.Dept)
	}
	if f.DataType != "" {
		add("data_type = $%d", f.DataType)
	}
	if f.From > 0 {
		add("ts >= $%d", time.UnixMilli(f.From))
	}
	if f.To > 0 {
		add("ts < $%d", time.UnixMilli(f.To))
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		add("(id || user_name || file || dept || host) ILIKE $%d", "%"+escapeLike(q)+"%")
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

const incCols = `id, (extract(epoch FROM ts)*1000)::bigint, user_name, dept, host, ip, channel, dest, data_type, file, size, matches,
	severity, action, status, policy, policy_id, handler, COALESCE((extract(epoch FROM closed_at)*1000)::bigint, 0)`

func scanIncident(row pgx.Row) (*Incident, error) {
	var i Incident
	err := row.Scan(&i.ID, &i.TS, &i.User, &i.Dept, &i.Host, &i.IP, &i.Channel, &i.Dest, &i.DataType, &i.File, &i.Size, &i.Matches,
		&i.Severity, &i.Action, &i.Status, &i.Policy, &i.PolicyID, &i.Handler, &i.Closed)
	return &i, err
}

func collectIncidents(rows pgx.Rows) ([]*Incident, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Incident, error) { return scanIncident(r) })
}

// NextIncidentID 分配事件编号。
func (s *Store) NextIncidentID(ctx context.Context) (string, error) {
	var n int64
	err := s.DB.QueryRow(ctx, `SELECT nextval('incident_seq')`).Scan(&n)
	return fmt.Sprintf("INC-%d", n), err
}

func (s *Store) InsertIncident(ctx context.Context, i *Incident) error {
	var closed any
	if i.Closed > 0 {
		closed = time.UnixMilli(i.Closed)
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO incidents (id, ts, user_name, dept, host, ip, channel, dest, data_type, file, size, matches, severity, action, status, policy, policy_id, handler, closed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		i.ID, time.UnixMilli(i.TS), i.User, i.Dept, i.Host, i.IP, i.Channel, i.Dest, i.DataType, i.File, i.Size, i.Matches,
		i.Severity, i.Action, i.Status, i.Policy, i.PolicyID, i.Handler, closed)
	return err
}

// CopyIncidents 批量导入事件（演示数据初始化使用）。
func (s *Store) CopyIncidents(ctx context.Context, list []*Incident) error {
	rows := make([][]any, len(list))
	for k, i := range list {
		var closed any
		if i.Closed > 0 {
			closed = time.UnixMilli(i.Closed)
		}
		rows[k] = []any{i.ID, time.UnixMilli(i.TS), i.User, i.Dept, i.Host, i.IP, i.Channel, i.Dest, i.DataType, i.File, i.Size, i.Matches, i.Severity, i.Action, i.Status, i.Policy, i.PolicyID, i.Handler, closed}
	}
	_, err := s.DB.CopyFrom(ctx, pgx.Identifier{"incidents"},
		[]string{"id", "ts", "user_name", "dept", "host", "ip", "channel", "dest", "data_type", "file", "size", "matches", "severity", "action", "status", "policy", "policy_id", "handler", "closed_at"},
		pgx.CopyFromRows(rows))
	return err
}

func (s *Store) GetIncident(ctx context.Context, id string) (*Incident, error) {
	i, err := scanIncident(s.DB.QueryRow(ctx, `SELECT `+incCols+` FROM incidents WHERE id = $1`, id))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return i, err
}

// ListIncidents 按时间倒序分页查询。
func (s *Store) ListIncidents(ctx context.Context, f IncidentFilter, page, per int) ([]*Incident, int, error) {
	where, args := f.where()
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM incidents`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, per, (page-1)*per)
	rows, err := s.DB.Query(ctx, fmt.Sprintf(`SELECT %s FROM incidents%s ORDER BY ts DESC, id DESC LIMIT $%d OFFSET $%d`, incCols, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	list, err := collectIncidents(rows)
	return list, total, err
}

// EachIncident 遍历符合条件的事件（导出用，最多 10 万条）。
func (s *Store) EachIncident(ctx context.Context, f IncidentFilter, fn func(*Incident)) error {
	where, args := f.where()
	rows, err := s.DB.Query(ctx, `SELECT `+incCols+` FROM incidents`+where+` ORDER BY ts DESC LIMIT 100000`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return err
		}
		fn(i)
	}
	return rows.Err()
}

// SeverityCounts 各级别事件总数与待处置数。
func (s *Store) SeverityCounts(ctx context.Context) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	for _, k := range []string{"critical", "high", "medium", "low"} {
		out[k] = map[string]int{"total": 0, "pending": 0}
	}
	rows, err := s.DB.Query(ctx, `SELECT severity, count(*), count(*) FILTER (WHERE status = 'pending') FROM incidents GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var t, p int
		if err := rows.Scan(&sev, &t, &p); err != nil {
			return nil, err
		}
		out[sev] = map[string]int{"total": t, "pending": p}
	}
	return out, rows.Err()
}

// CloseIncidents 将仍处于待处置 / 处置中的事件关闭，返回实际被关闭的事件。
func (s *Store) CloseIncidents(ctx context.Context, ids []string, status, by string) ([]*Incident, error) {
	rows, err := s.DB.Query(ctx, `UPDATE incidents SET status = $2, handler = $3, closed_at = now()
		WHERE id = ANY($1) AND status IN ('pending', 'processing') RETURNING `+incCols, ids, status, by)
	if err != nil {
		return nil, err
	}
	return collectIncidents(rows)
}

// RecentIncidents 最近的事件（引导数据与 UEBA 使用）。
func (s *Store) RecentIncidents(ctx context.Context, since int64, limit int) ([]*Incident, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+incCols+` FROM incidents WHERE ts >= $1 ORDER BY ts DESC LIMIT $2`, time.UnixMilli(since), limit)
	if err != nil {
		return nil, err
	}
	return collectIncidents(rows)
}

// CountIncidents 统计符合条件的事件数。
func (s *Store) CountIncidents(ctx context.Context, f IncidentFilter) (int, error) {
	where, args := f.where()
	var n int
	err := s.DB.QueryRow(ctx, `SELECT count(*) FROM incidents`+where, args...).Scan(&n)
	return n, err
}

// PurgeIncidents 删除早于 before 的已关闭事件（数据保留策略）。
func (s *Store) PurgeIncidents(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM incidents WHERE ts < $1 AND status IN ('resolved', 'fp')`, before)
	return tag.RowsAffected(), err
}

// SetIncidentSeq 调整事件编号序列（批量导入后使用）。
func (s *Store) SetIncidentSeq(ctx context.Context, n int64) error {
	_, err := s.DB.Exec(ctx, `SELECT setval('incident_seq', GREATEST($1, (SELECT last_value FROM incident_seq)))`, n)
	return err
}

// GroupCount 一个分组的事件数。
type GroupCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// 允许分组的维度（白名单，防止 SQL 注入）。
var groupCols = map[string]string{"channel": "channel", "severity": "severity", "data_type": "data_type", "dept": "dept", "user": "user_name",
	"action": "action", "status": "status", "host": "host", "policy": "policy",
	"day": "to_char(ts AT TIME ZONE $TZ, 'YYYY-MM-DD')", "hour": "extract(hour FROM ts AT TIME ZONE $TZ)::int::text"}

// IncidentGroup 按维度统计事件数（降序，最多 limit 组；按天分组时按日期升序）。
func (s *Store) IncidentGroup(ctx context.Context, f IncidentFilter, by string, limit int) ([]GroupCount, int, error) {
	col, ok := groupCols[by]
	if !ok {
		return nil, 0, fmt.Errorf("不支持的分组维度 %q", by)
	}
	where, args := f.where()
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM incidents`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := "2 DESC, 1"
	if by == "day" || by == "hour" {
		order = "1"
	}
	if strings.Contains(col, "$TZ") {
		args = append(args, s.Loc.String())
		col = strings.ReplaceAll(col, "$TZ", fmt.Sprintf("$%d::text", len(args)))
	}
	args = append(args, limit)
	rows, err := s.DB.Query(ctx, fmt.Sprintf(`SELECT COALESCE(%s, '') AS k, count(*) FROM incidents%s GROUP BY 1 ORDER BY %s LIMIT $%d`, col, where, order, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (GroupCount, error) {
		var g GroupCount
		return g, r.Scan(&g.Key, &g.Count)
	})
	return out, total, err
}
