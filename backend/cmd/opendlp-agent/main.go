// OpenDLP 终端 Agent（跨平台用户态）。
//
//	opendlp-agent [run]      前台运行（由 systemd / launchd / 计划任务托管）
//	opendlp-agent enroll     仅注册并保存凭据
//	opendlp-agent status     显示本地状态（注册、策略版本、离线队列、隔离区）
//	opendlp-agent scan       对所有监控目录执行一次全量检测后退出
//	opendlp-agent version
//
// 配置文件默认位于 /etc/opendlp/agent.json（Linux）、/Library/Application Support/OpenDLP/agent.json（macOS）、
// %ProgramData%\OpenDLP\agent.json（Windows），命令行参数优先。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"opendlp/internal/agent"
)

type watchFlag []agent.Watch

func (w *watchFlag) String() string { return fmt.Sprint(*w) }
func (w *watchFlag) Set(v string) error {
	ch, p, ok := strings.Cut(v, "=")
	if !ok || p == "" {
		return fmt.Errorf("格式应为 渠道=目录，例如 cloud=~/Library/CloudStorage")
	}
	*w = append(*w, agent.Watch{Channel: ch, Path: p})
	return nil
}

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("opendlp-agent", flag.ExitOnError)
	cfgPath := fs.String("config", agent.DefaultConfigPath(), "配置文件")
	server := fs.String("server", "", "管理控制台地址（覆盖配置文件）")
	token := fs.String("token", os.Getenv("OPENDLP_ENROLL_TOKEN"), "注册令牌 [OPENDLP_ENROLL_TOKEN]")
	dataDir := fs.String("data", "", "数据目录（凭据、策略缓存、离线队列、隔离区）")
	noUSB := fs.Bool("no-removable", false, "不监控可移动介质")
	scanSec := fs.Int("interval", 0, "目录轮询间隔（秒）")
	logJSON := fs.Bool("log-json", false, "JSON 格式日志")
	verbose := fs.Bool("v", false, "调试日志")
	var watches watchFlag
	fs.Var(&watches, "watch", "额外监控目录，可重复：渠道=目录（渠道 usb / cloud / im / email / web / print）")
	_ = fs.Parse(args)

	if cmd == "version" {
		fmt.Println("opendlp-agent", agent.Version)
		return
	}
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	}
	slog.SetDefault(slog.New(h))

	cfg, err := agent.LoadConfig(*cfgPath)
	if err != nil {
		fail(err)
	}
	if *server != "" {
		cfg.Server = *server
	}
	if *token != "" {
		cfg.EnrollToken = *token
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *noUSB {
		f := false
		cfg.Removable = &f
	}
	if *scanSec > 0 {
		cfg.ScanSeconds = *scanSec
	}
	cfg.Watch = append(cfg.Watch, watches...)

	a, err := agent.New(cfg)
	if err != nil {
		fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "run":
		slog.Info("OpenDLP Agent 启动", "version", agent.Version, "server", cfg.Server, "data", cfg.DataDir)
		if err := a.Run(ctx); err != nil && ctx.Err() == nil {
			fail(err)
		}
	case "enroll":
		if err := a.Enroll(ctx); err != nil {
			fail(err)
		}
		fmt.Println("注册成功")
	case "status":
		out, _ := json.MarshalIndent(a.Status(), "", "  ")
		fmt.Println(string(out))
	case "scan":
		files, hits, err := a.ScanOnce(ctx)
		if err != nil {
			fail(err)
		}
		fmt.Printf("已扫描 %d 个文件，发现 %d 个含敏感数据\n", files, hits)
	default:
		fail(fmt.Errorf("未知命令 %q（run / enroll / status / scan / version）", cmd))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}
