// Package sim 演示模式（-demo）下模拟终端与检测节点持续上报数据。生产环境不启用。
package sim

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"opendlp/internal/api"
	"opendlp/internal/seed"
	"opendlp/internal/store"
)

func clamp(v, lo, hi int) int { return max(lo, min(hi, v)) }

// Run 阻塞运行直到 ctx 结束。
func Run(ctx context.Context, srv *api.Server) {
	r := seed.NewRand(uint32(time.Now().UnixNano()))
	incT := time.NewTicker(3600 * time.Millisecond)
	metT := time.NewTicker(2 * time.Second)
	hbT := time.NewTicker(30 * time.Second)
	defer incT.Stop()
	defer metT.Stop()
	defer hbT.Stop()
	for i := 0; i < 20; i++ { // 预热指标曲线
		tickNodes(srv)
	}
	heartbeats(srv)
	for {
		select {
		case <-ctx.Done():
			return
		case <-incT.C:
			now := time.Now().UnixMilli()
			for k := rand.IntN(3); k > 0; k-- { // 同期放行的普通检测
				ch, dt, _ := seed.RandomDetection(r)
				_ = srv.St.AddDetection(ctx, now, ch, dt, "allow")
			}
			var inc *store.Incident
			srv.St.Read(func(d *store.Data) { inc = seed.NewIncident(d, r, "", now, true, now) })
			if inc != nil {
				if err := srv.RecordIncident(ctx, inc, nil); err != nil {
					slog.Error("模拟事件写入失败", "err", err)
				}
			}
		case <-metT.C:
			tickNodes(srv)
		case <-hbT.C:
			heartbeats(srv)
		}
	}
}

// tickNodes 模拟检测节点心跳。
func tickNodes(srv *api.Server) {
	now := time.Now().UnixMilli()
	srv.St.Write(func(d *store.Data) {
		for _, n := range d.Nodes {
			n.QPS = max(200, n.QPS+rand.IntN(161)-80)
			n.CPU = clamp(n.CPU+rand.IntN(9)-4, 8, 95)
			n.Mem = clamp(n.Mem+rand.IntN(5)-2, 20, 92)
			n.Latency = 62 + rand.IntN(30)
			n.LastSeen = now
			if n.Status == "offline" {
				n.Status = "online"
			}
		}
	})
	srv.PublishNodes()
}

// heartbeats 模拟在线终端的心跳（离线终端保持离线；已接入真实 Agent 的终端不模拟）。
func heartbeats(srv *api.Server) {
	now := time.Now().UnixMilli()
	srv.St.Write(func(d *store.Data) {
		for _, e := range d.Endpoints {
			if e.Status != "offline" && !e.Enrolled {
				e.LastSeen = now
				e.CPU = clamp(e.CPU+rand.IntN(11)-5, 2, 95)
			}
		}
	})
}
