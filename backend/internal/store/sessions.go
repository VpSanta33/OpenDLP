package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"opendlp/internal/auth"
)

// Sessions 基于 PostgreSQL 的会话存储，服务重启或多实例部署时会话依然有效。
type Sessions struct{ s *Store }

func (s *Store) Sessions() auth.Backend { return Sessions{s} }

func (b Sessions) Put(ctx context.Context, k string, x auth.Session) error {
	_, err := b.s.DB.Exec(ctx, `INSERT INTO sessions (token_hash, acc, role, ip, created_at, last_seen) VALUES ($1,$2,$3,$4,$5,$6)`,
		k, x.Acc, x.Role, x.IP, x.Created, x.LastSeen)
	return err
}

func (b Sessions) Get(ctx context.Context, k string) (auth.Session, bool, error) {
	var x auth.Session
	err := b.s.DB.QueryRow(ctx, `SELECT acc, role, ip, created_at, last_seen FROM sessions WHERE token_hash = $1`, k).
		Scan(&x.Acc, &x.Role, &x.IP, &x.Created, &x.LastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return x, false, nil
	}
	return x, err == nil, err
}

func (b Sessions) Touch(ctx context.Context, k string, t time.Time) error {
	_, err := b.s.DB.Exec(ctx, `UPDATE sessions SET last_seen = $2 WHERE token_hash = $1`, k, t)
	return err
}

func (b Sessions) SetRole(ctx context.Context, k, role string) error {
	_, err := b.s.DB.Exec(ctx, `UPDATE sessions SET role = $2 WHERE token_hash = $1`, k, role)
	return err
}

func (b Sessions) Delete(ctx context.Context, k string) error {
	_, err := b.s.DB.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, k)
	return err
}

func (b Sessions) DeleteAccount(ctx context.Context, acc string) error {
	_, err := b.s.DB.Exec(ctx, `DELETE FROM sessions WHERE acc = $1`, acc)
	return err
}

func (b Sessions) Purge(ctx context.Context, idle, created time.Time) error {
	_, err := b.s.DB.Exec(ctx, `DELETE FROM sessions WHERE last_seen < $1 OR created_at < $2`, idle, created)
	return err
}
