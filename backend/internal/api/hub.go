package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"opendlp/internal/store"
)

// Event 推送给前端的实时事件；Module 非空时仅推送给有该模块查看权限的订阅者。
type Event struct {
	Name   string
	Module string
	Data   any
}

type sub struct {
	ch    chan Event
	perms store.Matrix
}

// Hub SSE 订阅中心。
type Hub struct {
	mu   sync.Mutex
	subs map[*sub]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[*sub]struct{}{}} }

// Publish 非阻塞广播：慢订阅者会丢弃事件而不是拖慢发布方。
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if e.Module != "" && !s.perms[e.Module].View {
			continue
		}
		select {
		case s.ch <- e:
		default:
		}
	}
}

func (h *Hub) add(perms store.Matrix) *sub {
	s := &sub{ch: make(chan Event, 64), perms: perms}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *Hub) remove(s *sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

// Count 当前在线订阅数。
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// handleStream GET /api/v1/stream —— Server-Sent Events。
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, a *Actor) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	sub := s.Hub.add(a.Perms)
	defer s.Hub.remove(sub)
	fmt.Fprint(w, "retry: 3000\n\n")
	if err := rc.Flush(); err != nil {
		return
	}
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, ok := s.Sess.Get(a.Token); !ok { // 会话失效后关闭推送
				fmt.Fprint(w, "event: logout\ndata: {}\n\n")
				_ = rc.Flush()
				return
			}
			fmt.Fprint(w, ": ping\n\n")
		case e := <-sub.ch:
			b, err := json.Marshal(e.Data)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Name, b)
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

/* ---------- 集群指标环形缓冲 ---------- */

type Metrics struct {
	mu  sync.Mutex
	n   int
	QPS []int `json:"qps"`
	Lat []int `json:"lat"`
}

func NewMetrics(n int) *Metrics { return &Metrics{n: n} }

func (m *Metrics) Push(qps, lat int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.QPS = append(m.QPS, qps)
	m.Lat = append(m.Lat, lat)
	if len(m.QPS) > m.n {
		m.QPS, m.Lat = m.QPS[1:], m.Lat[1:]
	}
}

func (m *Metrics) Snapshot() map[string][]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string][]int{"qps": append([]int(nil), m.QPS...), "lat": append([]int(nil), m.Lat...)}
}
