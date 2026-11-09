// OpenDLP 管理控制台后端。
//
// 所有参数均可通过同名环境变量配置（OPENDLP_ 前缀，见 README）：
//
//	OPENDLP_DATABASE_URL=postgres://… opendlp                 # 生产模式
//	opendlp -database-url postgres://… -dev -demo           # 本地开发 + 演示数据
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	_ "time/tzdata"

	"opendlp/internal/api"
	"opendlp/internal/auth"
	"opendlp/internal/seed"
	"opendlp/internal/sim"
	"opendlp/internal/store"
)

// version 构建时通过 -ldflags "-X main.version=…" 注入。
var version = "3.3.0-dev"

func env(k, def string) string {
	if v := os.Getenv("OPENDLP_" + k); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool { b, _ := strconv.ParseBool(os.Getenv("OPENDLP_" + k)); return b }

type options struct {
	addr, dsn, dataDir, static, tz, cert, key, logFormat string
	dev, demo, proxy                                     bool
}

// healthcheck 供容器健康检查使用：opendlp healthcheck（请求本机 /readyz）。
func healthcheck() int {
	_, port, err := net.SplitHostPort(env("ADDR", "127.0.0.1:8080"))
	if err != nil {
		port = "8080"
	}
	c := http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://127.0.0.1:" + port + "/readyz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "not ready:", res.Status)
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	var o options
	flag.StringVar(&o.addr, "addr", env("ADDR", "127.0.0.1:8080"), "监听地址 [OPENDLP_ADDR]")
	flag.StringVar(&o.dsn, "database-url", env("DATABASE_URL", ""), "PostgreSQL 连接串 [OPENDLP_DATABASE_URL]")
	flag.StringVar(&o.dataDir, "data", env("DATA_DIR", "data"), "本地数据目录（配置快照备份） [OPENDLP_DATA_DIR]")
	flag.StringVar(&o.static, "static", env("STATIC", "../frontend"), "前端目录，留空则只提供 API [OPENDLP_STATIC]")
	flag.StringVar(&o.tz, "tz", env("TZ", "Asia/Shanghai"), "统计报表时区 [OPENDLP_TZ]")
	flag.StringVar(&o.cert, "tls-cert", env("TLS_CERT", ""), "TLS 证书 [OPENDLP_TLS_CERT]")
	flag.StringVar(&o.key, "tls-key", env("TLS_KEY", ""), "TLS 私钥 [OPENDLP_TLS_KEY]")
	flag.StringVar(&o.logFormat, "log-format", env("LOG_FORMAT", "text"), "日志格式 text | json [OPENDLP_LOG_FORMAT]")
	flag.BoolVar(&o.dev, "dev", envBool("DEV"), "开发模式：动态码打印到日志、允许模拟 SSO / 扫码与角色切换 [OPENDLP_DEV]")
	flag.BoolVar(&o.demo, "demo", envBool("DEMO"), "演示模式：首次启动写入演示数据并运行检测模拟器 [OPENDLP_DEMO]")
	flag.BoolVar(&o.proxy, "trust-proxy", envBool("TRUST_PROXY"), "信任 X-Forwarded-For [OPENDLP_TRUST_PROXY]")
	showVersion := flag.Bool("version", false, "显示版本")
	flag.Parse()
	if *showVersion {
		fmt.Println("opendlp", version)
		return
	}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	if o.logFormat == "json" {
		h = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(h))
	if err := run(o); err != nil {
		slog.Error("启动失败", "err", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.dsn == "" {
		return errors.New("未配置数据库：请设置 OPENDLP_DATABASE_URL 或 -database-url（例如 postgres://opendlp:密码@127.0.0.1:5432/opendlp）")
	}
	loc, err := time.LoadLocation(o.tz)
	if err != nil {
		return fmt.Errorf("时区 %q 无效: %w", o.tz, err)
	}
	if o.static != "" {
		if fi, err := os.Stat(filepath.Join(o.static, "index.html")); err != nil || fi.IsDir() {
			return fmt.Errorf("前端目录 %s 中未找到 index.html（可用 -static 指定，或 -static= 仅提供 API）", o.static)
		}
	}
	if (o.cert == "") != (o.key == "") {
		return errors.New("-tls-cert 与 -tls-key 需同时提供")
	}
	if !o.dev && o.cert == "" && !o.proxy {
		slog.Warn("生产模式未启用 HTTPS：请配置 TLS 证书，或部署在 HTTPS 反向代理之后并开启 -trust-proxy")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, created, err := store.Open(ctx, o.dsn, loc, func() *store.Data { return seed.Reference(time.Now()) })
	if err != nil {
		return err
	}
	defer st.Close()
	if created {
		slog.Info("数据库已初始化基础数据（内置角色、识别规则、渠道字典）")
	}
	st.Write(seed.Upgrade) // 升级时补齐新增的集成项、修复历史数据
	if o.demo {
		n, err := st.CountIncidents(ctx, store.IncidentFilter{})
		if err != nil {
			return err
		}
		setup := false
		st.Read(func(d *store.Data) { setup = d.SetupRequired() })
		if n == 0 && setup {
			pw := env("DEMO_PASSWORD", "OpenDLP@2026!")
			if err := auth.CheckComplexity(pw); err != nil {
				return fmt.Errorf("演示口令不满足复杂度要求: %w", err)
			}
			slog.Info("演示模式：正在写入演示数据…")
			if err := seed.Demo(ctx, st, time.Now(), pw); err != nil {
				return fmt.Errorf("写入演示数据失败: %w", err)
			}
			slog.Warn("演示模式：已创建演示管理员账号（口令见 README），切勿用于生产环境")
		}
	}

	agentToken := os.Getenv("OPENDLP_AGENT_TOKEN")
	srv := api.New(st, api.Config{Dev: o.dev, Demo: o.demo, Version: version, Static: o.static, SecureCookie: o.cert != "" || o.proxy && !o.dev,
		AgentToken: agentToken, TrustProxy: o.proxy, DataDir: o.dataDir})

	setup := false
	st.Read(func(d *store.Data) { setup = d.SetupRequired() })
	if setup {
		tok := srv.SetupToken(os.Getenv("OPENDLP_SETUP_TOKEN"))
		fmt.Fprintf(os.Stderr, "\n  系统尚未初始化。请在浏览器中打开控制台，使用以下一次性初始化令牌创建超级管理员：\n\n      %s\n\n", tok)
	}

	saved := make(chan struct{})
	go func() { st.RunSaver(ctx, 2*time.Second); close(saved) }()
	go srv.RunMaintenance(ctx)
	go srv.Alerts.Run(ctx)
	if o.demo {
		go sim.Run(ctx, srv)
	}

	hs := &http.Server{
		Addr:              o.addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// 不设置 WriteTimeout：SSE 长连接需要持续写入；关闭时通过 BaseContext 结束长连接
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() {
		scheme := "http"
		if o.cert != "" {
			scheme = "https"
		}
		slog.Info("OpenDLP 已启动", "version", version, "url", scheme+"://"+o.addr, "env", map[bool]string{true: "demo", false: map[bool]string{true: "development", false: "production"}[o.dev]}[o.demo],
			"static", o.static, "ingest", agentToken != "")
		if o.cert != "" {
			errc <- hs.ListenAndServeTLS(o.cert, o.key)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			<-saved
			return err
		}
	case <-ctx.Done():
		slog.Info("正在关闭…")
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}
	<-saved
	return nil
}
