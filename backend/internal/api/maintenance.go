package api

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"opendlp/internal/notify"
	"opendlp/internal/store"
)

// PublishNodes 供模拟器调用的节点指标推送。
func (s *Server) PublishNodes() { s.publishNodes() }

// RunMaintenance 后台维护任务（所有模式均运行）：
// 审批超时关闭、终端 / 节点离线判定、过期会话清理、按保留策略清理历史数据。
func (s *Server) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	lastPurge := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		expired, offline := 0, []string{}
		nodesChanged := false
		s.St.Write(func(d *store.Data) {
			for _, a := range d.Approvals {
				if a.Status == "pending" && now.UnixMilli() > a.Deadline {
					a.Status = "expired"
					expired++
				}
			}
			cut := now.Add(-10 * time.Minute).UnixMilli()
			for _, e := range d.Endpoints {
				if e.Status != "offline" && e.LastSeen < cut {
					e.Status, e.CPU, e.Mem = "offline", 0, 0
					offline = append(offline, e.Host)
				}
			}
			ncut := now.Add(-2 * time.Minute).UnixMilli()
			for _, n := range d.Nodes {
				if n.Status != "offline" && n.LastSeen < ncut {
					n.Status, n.QPS = "offline", 0
					nodesChanged = true
				}
			}
		})
		if expired > 0 {
			s.Hub.Publish(Event{Name: "approvals.changed", Module: "approvals", Data: map[string]int{"expired": expired}})
		}
		if len(offline) > 0 {
			s.Alerts.Human(notify.Message{Title: fmt.Sprintf("%d 台终端离线", len(offline)), Severity: "medium", Text: "超过 10 分钟无心跳：" + strings.Join(offline, "、"), Link: "#/endpoints", Event: "endpoint"})
			s.addNote("warning", "终端离线", strings.Join(offline[:min(3, len(offline))], "、")+map[bool]string{true: " 等 " + strconv.Itoa(len(offline)) + " 台终端", false: ""}[len(offline) > 3]+" 超过 10 分钟无心跳", "#/endpoints")
		}
		if nodesChanged {
			s.Alerts.Human(notify.Message{Title: "检测节点离线", Severity: "high", Text: "有检测节点超过 2 分钟未上报心跳，请检查集群状态", Link: "#/ops", Event: "node"})
			s.addNote("danger", "检测节点离线", "有检测节点超过 2 分钟未上报心跳，请检查集群状态", "#/ops")
			s.publishNodes()
		}
		var fleet store.Fleet
		s.St.Read(func(d *store.Data) { fleet = d.Fleet(now) })
		s.Hub.Publish(Event{Name: "fleet", Module: "dashboard", Data: fleet})
		s.Sess.Purge()

		if now.Sub(lastPurge) > 24*time.Hour {
			lastPurge = now
			s.purge(ctx, now)
		}
	}
}

// purge 按「系统设置 → 数据保留」清理已关闭的历史事件；检测量聚合保留 400 天。
func (s *Server) purge(ctx context.Context, now time.Time) {
	var ret string
	s.St.Read(func(d *store.Data) { ret, _ = d.Settings["ret1"].(string) })
	days := map[string]int{"90 天": 90, "180 天": 180, "365 天": 365}[ret]
	if days > 0 {
		n, err := s.St.PurgeIncidents(ctx, now.AddDate(0, 0, -days))
		if err != nil {
			slog.Error("清理历史事件失败", "err", err)
		} else if n > 0 {
			slog.Info("按保留策略清理历史事件", "count", n, "days", days)
		}
	}
	if err := s.St.PurgeDetections(ctx, now.AddDate(0, 0, -400)); err != nil {
		slog.Error("清理检测量失败", "err", err)
	}
}
