package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"opendlp/internal/detect"
)

// Agent 终端 Agent 实例。
type Agent struct {
	cfg   *Config
	cli   *Client
	queue *Queue
	scan  *Scanner

	host, user, ip, osName, osKey string

	mu     sync.RWMutex
	eng    *detect.Engine
	bundle Bundle

	interval time.Duration
	lastErr  string // 最近一次异常（心跳中以 warning 上报）
}

func (a *Agent) statePath() string  { return filepath.Join(a.cfg.DataDir, "state.json") }
func (a *Agent) policyPath() string { return filepath.Join(a.cfg.DataDir, "policy.json") }

// New 创建 Agent（校验配置并准备数据目录）。
func New(cfg *Config) (*Agent, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	if err := os.MkdirAll(cfg.Quarantine, 0o700); err != nil {
		return nil, fmt.Errorf("创建隔离区失败: %w", err)
	}
	cli, err := NewClient(cfg.Server, cfg.CAFile)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, cli: cli, queue: NewQueue(filepath.Join(cfg.DataDir, "queue.jsonl")), host: hostname(), interval: time.Minute}
	a.user = cfg.User
	if a.user == "" {
		a.user = consoleUser()
	}
	a.osName, a.osKey = osInfo()
	a.scan = newScanner(a)
	return a, nil
}

func (a *Agent) engine() (*detect.Engine, Bundle) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.eng, a.bundle
}

func (a *Agent) dataTypeName(k string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if n := a.bundle.DataTypes[k]; n != "" {
		return n
	}
	return k
}

func (a *Agent) setBundle(b Bundle) {
	eng := detect.New(b.Rules, b.Policies)
	a.mu.Lock()
	a.eng, a.bundle = eng, b
	a.mu.Unlock()
}

func (a *Agent) heartbeatReq() HeartbeatReq {
	cpu, mem, disk := usage()
	_, b := a.engine()
	if ip := outboundIP(a.cfg.Server); ip != "" {
		a.ip = ip
	}
	return HeartbeatReq{Host: a.host, User: a.user, Dept: a.cfg.Dept, IP: a.ip, OS: a.osName, OSKey: a.osKey, Agent: Version,
		CPU: cpu, Mem: mem, Disk: disk, Warning: a.lastErr != "" || a.queue.Len() > 0, PolicyVersion: b.Version}
}

// Enroll 使用注册令牌注册（或在凭据失效后重新注册），并保存凭据。
func (a *Agent) Enroll(ctx context.Context) error {
	if a.cfg.EnrollToken == "" {
		return errors.New("尚未注册且未配置注册令牌 enrollToken")
	}
	if err := a.cli.Enroll(ctx, a.cfg.EnrollToken, a.heartbeatReq()); err != nil {
		return err
	}
	slog.Info("注册成功", "agentId", a.cli.ID, "host", a.host)
	return saveJSON(a.statePath(), State{Server: a.cfg.Server, Host: a.host, AgentID: a.cli.ID, Secret: a.cli.Secret})
}

// loadState 读取已保存的凭据与策略缓存。控制台地址或主机名变化时需要重新注册。
func (a *Agent) loadState() error {
	var st State
	ok, err := loadJSON(a.statePath(), &st)
	if err != nil {
		return fmt.Errorf("读取注册状态失败: %w", err)
	}
	if ok && st.Server == a.cfg.Server && st.Host == a.host {
		a.cli.ID, a.cli.Secret = st.AgentID, st.Secret
	}
	var b Bundle
	if ok, _ := loadJSON(a.policyPath(), &b); ok {
		a.setBundle(b)
		slog.Info("已加载本地策略缓存", "version", b.Version, "policies", len(b.Policies), "rules", len(b.Rules))
	}
	return nil
}

// SyncPolicy 拉取策略包（未变化时服务端返回 304），并缓存到本地供离线使用。
func (a *Agent) SyncPolicy(ctx context.Context) (bool, error) {
	_, cur := a.engine()
	b, err := a.cli.Policy(ctx, cur.Version)
	if err != nil || b == nil {
		return false, err
	}
	a.setBundle(*b)
	if err := saveJSON(a.policyPath(), b); err != nil {
		slog.Warn("缓存策略失败", "err", err)
	}
	slog.Info("策略已更新", "version", b.Version, "policies", len(b.Policies), "rules", len(b.Rules), "strict", b.Strict)
	return true, nil
}

// report 上报检测结果；失败时写入离线队列。
func (a *Agent) report(ctx context.Context, d Detection) {
	if a.cli.ID != "" {
		err := a.cli.Detections(ctx, []Detection{d})
		if err == nil {
			return
		}
		if !retryable(err) && !errors.Is(err, ErrUnauthorized) {
			slog.Warn("检测结果被服务端拒绝", "err", err, "file", d.File)
			return
		}
		slog.Warn("上报失败，写入离线队列", "err", err)
	}
	if err := a.queue.Push([]Detection{d}); err != nil {
		slog.Error("写入离线队列失败", "err", err)
	}
}

func (a *Agent) flushQueue(ctx context.Context) {
	n, err := a.queue.Flush(200, func(list []Detection) error { return a.cli.Detections(ctx, list) })
	if n > 0 {
		slog.Info("离线检测结果已补报", "count", n)
	}
	if err != nil {
		slog.Warn("补报失败，稍后重试", "err", err)
	}
}

// execute 执行一条服务端指令，返回是否成功与结果说明。
func (a *Agent) execute(ctx context.Context, c Command) (bool, string) {
	switch {
	case c.Action == "push":
		changed, err := a.SyncPolicy(ctx)
		if err != nil {
			return false, "同步策略失败：" + err.Error()
		}
		_, b := a.engine()
		return true, fmt.Sprintf("策略已同步（版本 %s，%d 条策略，%s）", b.Version, len(b.Policies), map[bool]string{true: "已更新", false: "无变化"}[changed])
	case c.Action == "scan":
		files, hits := a.scan.FullScan(ctx)
		return true, fmt.Sprintf("已扫描 %d 个文件，发现 %d 个含敏感数据", files, hits)
	case c.Action == "isolate", c.Action == "release":
		return false, "用户态 Agent 不支持网络隔离，请通过网络准入 (NAC) 或防火墙策略执行"
	case strings.HasPrefix(c.Action, "upgrade:"):
		return false, "当前版本 " + Version + "，请通过软件分发平台（SCCM / Jamf / 软件中心）升级至 " + strings.TrimPrefix(c.Action, "upgrade:")
	}
	return false, "不支持的指令：" + c.Action
}

// beat 一次心跳：上报状态、处理指令、按需同步策略、补报离线数据。
func (a *Agent) beat(ctx context.Context) error {
	resp, err := a.cli.Heartbeat(ctx, a.heartbeatReq())
	if errors.Is(err, ErrUnauthorized) {
		slog.Warn("终端凭据已失效，尝试重新注册")
		if err := a.Enroll(ctx); err != nil {
			return err
		}
		resp, err = a.cli.Heartbeat(ctx, a.heartbeatReq())
	}
	if err != nil {
		return err
	}
	if resp.Interval >= 10 {
		a.interval = time.Duration(resp.Interval) * time.Second
	}
	if _, b := a.engine(); resp.PolicyVersion != "" && resp.PolicyVersion != b.Version {
		if _, err := a.SyncPolicy(ctx); err != nil {
			slog.Warn("同步策略失败", "err", err)
		}
	}
	for _, c := range resp.Commands {
		ok, msg := a.execute(ctx, c)
		slog.Info("执行指令", "id", c.ID, "action", c.Action, "ok", ok, "result", msg)
		if err := a.cli.CommandResult(ctx, c.ID, ok, msg); err != nil {
			slog.Warn("回传指令结果失败", "id", c.ID, "err", err)
		}
	}
	a.flushQueue(ctx)
	return nil
}

// Run 启动 Agent：注册 → 同步策略 → 心跳与目录轮询，直到 ctx 结束。
func (a *Agent) Run(ctx context.Context) error {
	if err := a.loadState(); err != nil {
		return err
	}
	// 注册失败（网络不可用等）时按退避重试；已有本地策略缓存时离线也能检测与隔离
	for wait := 5 * time.Second; a.cli.ID == ""; wait = min(wait*2, 5*time.Minute) {
		err := a.Enroll(ctx)
		if err == nil {
			break
		}
		slog.Error("注册失败", "err", err, "retry", wait)
		if eng, _ := a.engine(); eng != nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	if a.cli.ID != "" {
		if _, err := a.SyncPolicy(ctx); err != nil {
			slog.Warn("同步策略失败，使用本地缓存", "err", err)
		}
		if err := a.beat(ctx); err != nil {
			slog.Warn("心跳失败", "err", err)
		}
	}
	if eng, _ := a.engine(); eng == nil {
		slog.Warn("尚无可用策略，检测将在首次同步成功后开始")
	}

	scanT := time.NewTicker(a.cfg.scanEvery())
	defer scanT.Stop()
	beatT := time.NewTimer(a.interval)
	defer beatT.Stop()
	a.scan.Poll(ctx) // 建立基线
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-scanT.C:
			a.scan.Poll(ctx)
		case <-beatT.C:
			if a.cli.ID == "" {
				if err := a.Enroll(ctx); err != nil {
					slog.Warn("注册失败", "err", err)
				}
			}
			if a.cli.ID != "" {
				if err := a.beat(ctx); err != nil {
					a.lastErr = err.Error()
					slog.Warn("心跳失败", "err", err)
				} else {
					a.lastErr = ""
				}
			}
			beatT.Reset(a.interval)
		}
	}
}

// Status 本地状态摘要（opendlp-agent status）。
func (a *Agent) Status() map[string]any {
	_ = a.loadState()
	_, b := a.engine()
	q, _ := QuarantineList(a.cfg.Quarantine)
	roots := []string{}
	for _, r := range a.scan.currentRoots() {
		roots = append(roots, r.Channel+": "+r.Path)
	}
	return map[string]any{"version": Version, "server": a.cfg.Server, "host": a.host, "user": a.user, "os": a.osName,
		"enrolled": a.cli.ID != "", "agentId": a.cli.ID, "policyVersion": b.Version, "policies": len(b.Policies), "rules": len(b.Rules), "strict": b.Strict,
		"queued": a.queue.Len(), "quarantined": len(q), "watching": roots}
}

// ScanOnce 同步策略后对所有监控目录执行一次全量检测（opendlp-agent scan）。
func (a *Agent) ScanOnce(ctx context.Context) (int, int, error) {
	if err := a.loadState(); err != nil {
		return 0, 0, err
	}
	if a.cli.ID == "" {
		if err := a.Enroll(ctx); err != nil {
			return 0, 0, err
		}
	}
	if _, err := a.SyncPolicy(ctx); err != nil {
		if eng, _ := a.engine(); eng == nil {
			return 0, 0, fmt.Errorf("无法获取策略: %w", err)
		}
		slog.Warn("同步策略失败，使用本地缓存", "err", err)
	}
	files, hits := a.scan.FullScan(ctx)
	a.flushQueue(ctx)
	return files, hits, nil
}
