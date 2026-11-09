// Package store 是平台的数据层（PostgreSQL）。
//
//   - 配置类数据（策略、规则、角色、管理员、审批单等）保存在内存工作集 Data 中，
//     通过 Read / Write 并发安全地访问，并以 JSONB 文档持久化到 documents 表；
//   - 事件、检测量、审计日志、会话数据量大，直接使用对应的数据表与 SQL 查询。
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const dataVersion = 2

//go:embed schema.sql
var schemaSQL string

// Store 数据存储。
type Store struct {
	mu      sync.RWMutex
	d       *Data
	DB      *pgxpool.Pool
	dirty   atomic.Bool
	auditMu sync.Mutex
	Loc     *time.Location
	// OnAudit 审计记录提交后的回调（用于转发 SIEM），可为 nil。
	OnAudit func(AuditEntry)
}

// Open 连接数据库、执行迁移并加载配置文档；数据库为空时调用 seed 生成初始配置。
// 返回值 created 表示本次为首次初始化。
func Open(ctx context.Context, dsn string, loc *time.Location, seed func() *Data) (*Store, bool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, false, fmt.Errorf("数据库连接串无效: %w", err)
	}
	cfg.MaxConns = max(cfg.MaxConns, 10)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, false, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, false, fmt.Errorf("无法连接数据库: %w", err)
	}
	s := &Store{DB: pool, Loc: loc}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, false, fmt.Errorf("数据库迁移失败: %w", err)
	}
	var raw []byte
	err = pool.QueryRow(ctx, `SELECT data FROM documents WHERE name = 'config'`).Scan(&raw)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		s.d = seed()
		s.d.Version = dataVersion
		if err := s.Save(ctx); err != nil {
			pool.Close()
			return nil, false, err
		}
		return s, true, nil
	case err != nil:
		pool.Close()
		return nil, false, err
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		pool.Close()
		return nil, false, fmt.Errorf("解析配置文档失败: %w", err)
	}
	if d.Version != dataVersion {
		pool.Close()
		return nil, false, fmt.Errorf("配置文档版本 %d 与程序版本 %d 不匹配", d.Version, dataVersion)
	}
	s.d = &d
	return s, false, nil
}

// migrate 在咨询锁保护下执行建表脚本（多实例同时启动时只有一个执行）。
func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7300001)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var applied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 1)`).Scan(&applied); err != nil {
		return err
	}
	if !applied {
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES (1)`); err != nil {
			return err
		}
		slog.Info("数据库迁移完成", "version", 1)
	}
	return tx.Commit(ctx)
}

func (s *Store) Close() { s.DB.Close() }

// Read 在读锁内执行 fn。fn 不得保留 d 中的指针到锁外修改。
func (s *Store) Read(fn func(d *Data)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(s.d)
}

// Write 在写锁内执行 fn，并标记配置文档待持久化。
func (s *Store) Write(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.d)
	s.dirty.Store(true)
}

// Save 将配置文档写入数据库。
func (s *Store) Save(ctx context.Context) error {
	s.mu.RLock()
	s.dirty.Store(false)
	b, err := json.Marshal(s.d)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO documents (name, data, updated_at) VALUES ('config', $1, now())
		ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, b)
	if err != nil {
		s.dirty.Store(true)
	}
	return err
}

// RunSaver 周期性持久化配置文档，ctx 结束时做最后一次保存。
func (s *Store) RunSaver(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := s.Save(sctx); err != nil {
				slog.Error("退出前保存配置失败", "err", err)
			}
			cancel()
			return
		case <-t.C:
			if s.dirty.Load() {
				if err := s.Save(ctx); err != nil {
					slog.Error("保存配置失败", "err", err)
				}
			}
		}
	}
}

// Ping 数据库健康检查，返回往返耗时。
func (s *Store) Ping(ctx context.Context) (time.Duration, error) {
	t := time.Now()
	err := s.DB.Ping(ctx)
	return time.Since(t), err
}

// NextSeq 递增并返回指定种类的序号（须在 Write 内调用）。
func NextSeq(d *Data, kind string) int {
	if d.Seq == nil {
		d.Seq = map[string]int{}
	}
	d.Seq[kind]++
	return d.Seq[kind]
}

// NewEndpointID 分配未被占用的终端编号（须在写锁内调用）。
func NewEndpointID(d *Data) string {
	used := make(map[string]bool, len(d.Endpoints))
	for _, e := range d.Endpoints {
		used[e.ID] = true
	}
	for {
		id := fmt.Sprintf("EP%d", NextSeq(d, "endpoint"))
		if !used[id] {
			return id
		}
	}
}

// RepairEndpointIDs 修复旧版本演示数据中重复的终端编号（须在写锁内调用）：
// 重复项重新编号，绑定该主机的 Agent 凭据随之迁移。返回修复数量。
func RepairEndpointIDs(d *Data) int {
	seen := map[string]bool{}
	fixed := 0
	for _, e := range d.Endpoints {
		if !seen[e.ID] {
			seen[e.ID] = true
			continue
		}
		old := e.ID
		var cred *AgentCred
		if c := d.AgentCreds[old]; c != nil && c.Host == e.Host {
			cred = c
			delete(d.AgentCreds, old)
		}
		e.ID = NewEndpointID(d)
		seen[e.ID] = true
		if cred != nil {
			d.AgentCreds[e.ID] = cred
		}
		fixed++
	}
	return fixed
}

/* ---------- 便捷查询（须在锁内调用） ---------- */

func (d *Data) Admin(acc string) *Admin {
	for _, a := range d.Admins {
		if a.Acc == acc {
			return a
		}
	}
	return nil
}

func (d *Data) Role(key string) *Role {
	for _, r := range d.Roles {
		if r.Key == key {
			return r
		}
	}
	return nil
}

func (d *Data) RoleName(key string) string {
	if r := d.Role(key); r != nil {
		return r.Name
	}
	return key
}

func (d *Data) Employee(name string) *Employee {
	for _, e := range d.Employees {
		if e.Name == name {
			return e
		}
	}
	return nil
}

func (d *Data) ChannelName(k string) string {
	for _, c := range d.Channels {
		if c.Key == k {
			return c.Name
		}
	}
	return k
}

func (d *Data) DataTypeName(k string) string {
	for _, t := range d.DataTypes {
		if t.Key == k {
			return t.Name
		}
	}
	return k
}

// Fleet 由终端心跳计算终端汇总：10 分钟内有心跳视为在线。
func (d *Data) Fleet(now time.Time) Fleet {
	f := Fleet{Deployed: len(d.Endpoints)}
	if n, ok := d.Settings["licenseSeats"].(float64); ok {
		f.Licensed = int(n)
	}
	cut := now.Add(-10 * time.Minute).UnixMilli()
	for _, e := range d.Endpoints {
		if e.Status != "offline" && e.LastSeen >= cut {
			f.Online++
		}
	}
	return f
}

// SetupRequired 尚未创建任何管理员时需要首次初始化。
func (d *Data) SetupRequired() bool { return len(d.Admins) == 0 }
