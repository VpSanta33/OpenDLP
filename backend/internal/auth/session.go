package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

// Session 已登录会话。Token 仅以 SHA-256 摘要作为索引保存。
type Session struct {
	Acc      string
	Role     string // 当前生效角色（开发模式下超级管理员可切换演示）
	Created  time.Time
	LastSeen time.Time
	IP       string
}

// Backend 会话持久化接口（生产环境使用 PostgreSQL，测试可使用内存实现）。
type Backend interface {
	Put(ctx context.Context, key string, s Session) error
	Get(ctx context.Context, key string) (Session, bool, error)
	Touch(ctx context.Context, key string, t time.Time) error
	SetRole(ctx context.Context, key, role string) error
	Delete(ctx context.Context, key string) error
	DeleteAccount(ctx context.Context, acc string) error
	Purge(ctx context.Context, idleBefore, createdBefore time.Time) error
}

// Challenge MFA 挑战（口令通过后、动态码校验前的中间状态）。
type Challenge struct {
	Acc      string
	Exp      time.Time
	Attempts int
}

// Manager 会话管理器。会话经 Backend 持久化；MFA 挑战与已用动态码保存在内存（5 分钟内有效）。
type Manager struct {
	B          Backend
	mu         sync.Mutex
	challenges map[string]*Challenge
	usedOTP    map[string]time.Time
	Idle       time.Duration
	Absolute   time.Duration
}

func NewManager(b Backend, idle, absolute time.Duration) *Manager {
	if b == nil {
		b = NewMemBackend()
	}
	return &Manager{B: b, challenges: map[string]*Challenge{}, usedOTP: map[string]time.Time{}, Idle: idle, Absolute: absolute}
}

func digest(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

func bg() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// Create 创建会话并返回明文 token（只出现在 Set-Cookie 中）。
func (m *Manager) Create(acc, role, ip string) (string, error) {
	tok := RandomToken(32)
	now := time.Now()
	ctx, cancel := bg()
	defer cancel()
	return tok, m.B.Put(ctx, digest(tok), Session{Acc: acc, Role: role, Created: now, LastSeen: now, IP: ip})
}

// Get 返回会话并刷新活跃时间（每分钟最多写一次）；超出空闲或绝对时限的会话会被删除。
func (m *Manager) Get(tok string) (Session, bool) {
	if tok == "" {
		return Session{}, false
	}
	k := digest(tok)
	ctx, cancel := bg()
	defer cancel()
	s, ok, err := m.B.Get(ctx, k)
	if err != nil {
		slog.Error("读取会话失败", "err", err)
		return Session{}, false
	}
	if !ok {
		return Session{}, false
	}
	now := time.Now()
	if now.Sub(s.LastSeen) > m.Idle || now.Sub(s.Created) > m.Absolute {
		_ = m.B.Delete(ctx, k)
		return Session{}, false
	}
	if now.Sub(s.LastSeen) > time.Minute {
		_ = m.B.Touch(ctx, k, now)
		s.LastSeen = now
	}
	return s, true
}

func (m *Manager) SetRole(tok, role string) error {
	ctx, cancel := bg()
	defer cancel()
	return m.B.SetRole(ctx, digest(tok), role)
}

func (m *Manager) Delete(tok string) {
	ctx, cancel := bg()
	defer cancel()
	_ = m.B.Delete(ctx, digest(tok))
}

// RevokeAccount 使某账号的全部会话失效（禁用账号、重置 MFA 时使用）。
func (m *Manager) RevokeAccount(acc string) {
	ctx, cancel := bg()
	defer cancel()
	if err := m.B.DeleteAccount(ctx, acc); err != nil {
		slog.Error("吊销会话失败", "acc", acc, "err", err)
	}
}

// Purge 清理过期会话与挑战。
func (m *Manager) Purge() {
	now := time.Now()
	ctx, cancel := bg()
	defer cancel()
	_ = m.B.Purge(ctx, now.Add(-m.Idle), now.Add(-m.Absolute))
	m.mu.Lock()
	for k, c := range m.challenges {
		if now.After(c.Exp) {
			delete(m.challenges, k)
		}
	}
	m.mu.Unlock()
}

// NewChallenge 创建 5 分钟有效的 MFA 挑战。
func (m *Manager) NewChallenge(acc string) string {
	tok := RandomToken(24)
	m.mu.Lock()
	m.challenges[digest(tok)] = &Challenge{Acc: acc, Exp: time.Now().Add(5 * time.Minute)}
	m.mu.Unlock()
	return tok
}

// UseChallenge 取出挑战并计一次尝试；超过 5 次尝试或过期即作废。
func (m *Manager) UseChallenge(tok string) (*Challenge, bool) {
	k := digest(tok)
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[k]
	if !ok || time.Now().After(c.Exp) || c.Attempts >= 5 {
		delete(m.challenges, k)
		return nil, false
	}
	c.Attempts++
	return c, true
}

func (m *Manager) DropChallenge(tok string) {
	m.mu.Lock()
	delete(m.challenges, digest(tok))
	m.mu.Unlock()
}

// MarkOTPUsed 记录已使用的动态码计数器，重复使用返回 false。
func (m *Manager) MarkOTPUsed(acc string, counter int64) bool {
	k := acc + "|" + time.Unix(counter*30, 0).UTC().Format(time.RFC3339)
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for kk, exp := range m.usedOTP {
		if now.After(exp) {
			delete(m.usedOTP, kk)
		}
	}
	if _, used := m.usedOTP[k]; used {
		return false
	}
	m.usedOTP[k] = now.Add(3 * time.Minute)
	return true
}

/* ---------- 内存实现（单元测试 / 无数据库场景） ---------- */

type memBackend struct {
	mu sync.Mutex
	m  map[string]Session
}

func NewMemBackend() Backend { return &memBackend{m: map[string]Session{}} }

func (b *memBackend) Put(_ context.Context, k string, s Session) error {
	b.mu.Lock()
	b.m[k] = s
	b.mu.Unlock()
	return nil
}
func (b *memBackend) Get(_ context.Context, k string) (Session, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.m[k]
	return s, ok, nil
}
func (b *memBackend) Touch(_ context.Context, k string, t time.Time) error {
	b.mu.Lock()
	if s, ok := b.m[k]; ok {
		s.LastSeen = t
		b.m[k] = s
	}
	b.mu.Unlock()
	return nil
}
func (b *memBackend) SetRole(_ context.Context, k, role string) error {
	b.mu.Lock()
	if s, ok := b.m[k]; ok {
		s.Role = role
		b.m[k] = s
	}
	b.mu.Unlock()
	return nil
}
func (b *memBackend) Delete(_ context.Context, k string) error {
	b.mu.Lock()
	delete(b.m, k)
	b.mu.Unlock()
	return nil
}
func (b *memBackend) DeleteAccount(_ context.Context, acc string) error {
	b.mu.Lock()
	for k, s := range b.m {
		if s.Acc == acc {
			delete(b.m, k)
		}
	}
	b.mu.Unlock()
	return nil
}
func (b *memBackend) Purge(_ context.Context, idle, created time.Time) error {
	b.mu.Lock()
	for k, s := range b.m {
		if s.LastSeen.Before(idle) || s.Created.Before(created) {
			delete(b.m, k)
		}
	}
	b.mu.Unlock()
	return nil
}
