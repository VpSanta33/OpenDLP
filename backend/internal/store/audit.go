package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func auditHash(e *AuditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%s|%s|%s|%s|%s|%t|%s", e.Prev, e.ID, e.TS, e.Op, e.Role, e.Type, e.Detail, e.IP, e.OK, e.Reason)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendAudit 追加一条审计记录并接入哈希链。
// 事务内使用咨询锁串行化，保证多实例部署时链条顺序一致。失败时记录错误日志并返回错误。
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) error {
	err := s.appendAudit(ctx, &e)
	if err != nil {
		slog.Error("写入审计日志失败", "err", err, "type", e.Type, "detail", e.Detail)
	} else if s.OnAudit != nil {
		s.OnAudit(e)
	}
	return err
}

func (s *Store) appendAudit(ctx context.Context, e *AuditEntry) error {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7300002)`); err != nil {
		return err
	}
	var prev string
	if err := tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev); err != nil && err != pgx.ErrNoRows {
		return err
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT nextval('audit_seq')`).Scan(&seq); err != nil {
		return err
	}
	e.ID, e.Prev = "AUD-"+strconv.FormatInt(seq, 10), prev
	e.Hash = auditHash(e)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log (seq, id, ts, op, role, type, detail, ip, ok, reason, prev, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		seq, e.ID, time.UnixMilli(e.TS), e.Op, e.Role, e.Type, e.Detail, e.IP, e.OK, e.Reason, e.Prev, e.Hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AuditFilter 审计日志查询条件；Result 为 ok / fail / 空。
type AuditFilter struct{ Q, Type, Result string }

func (f AuditFilter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(c string, v any) { args = append(args, v); conds = append(conds, fmt.Sprintf(c, len(args))) }
	if f.Type != "" && f.Type != "all" {
		add("type = $%d", f.Type)
	}
	switch f.Result {
	case "ok":
		conds = append(conds, "ok")
	case "fail":
		conds = append(conds, "NOT ok")
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		add("(op || detail || ip || role) ILIKE $%d", "%"+escapeLike(q)+"%")
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

const auditCols = `id, (extract(epoch FROM ts)*1000)::bigint, op, role, type, detail, ip, ok, reason, prev, hash`

func scanAudit(row pgx.Row) (AuditEntry, error) {
	var e AuditEntry
	err := row.Scan(&e.ID, &e.TS, &e.Op, &e.Role, &e.Type, &e.Detail, &e.IP, &e.OK, &e.Reason, &e.Prev, &e.Hash)
	return e, err
}

// ListAudits 按时间倒序分页查询审计日志。
func (s *Store) ListAudits(ctx context.Context, f AuditFilter, page, per int) ([]AuditEntry, int, error) {
	where, args := f.where()
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, per, (page-1)*per)
	rows, err := s.DB.Query(ctx, fmt.Sprintf(`SELECT %s FROM audit_log%s ORDER BY seq DESC LIMIT $%d OFFSET $%d`, auditCols, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) { return scanAudit(r) })
	return out, total, err
}

// EachAudit 按时间倒序遍历符合条件的审计日志（导出用）。
func (s *Store) EachAudit(ctx context.Context, f AuditFilter, fn func(AuditEntry)) error {
	where, args := f.where()
	rows, err := s.DB.Query(ctx, `SELECT `+auditCols+` FROM audit_log`+where+` ORDER BY seq DESC LIMIT 100000`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return err
		}
		fn(e)
	}
	return rows.Err()
}

// VerifyAudit 从最早一条开始校验哈希链，返回校验条数与首个异常记录 ID（无异常为空）。
func (s *Store) VerifyAudit(ctx context.Context) (int, string, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	prev, n := "", 0
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return n, "", err
		}
		n++
		if e.Prev != prev || auditHash(&e) != e.Hash {
			return n, e.ID, nil
		}
		prev = e.Hash
	}
	return n, "", rows.Err()
}
