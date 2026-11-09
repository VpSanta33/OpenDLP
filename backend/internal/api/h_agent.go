package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"opendlp/internal/auth"
	"opendlp/internal/detect"
	"opendlp/internal/store"
)

/*
终端 Agent 协议（独立凭据）

 1. 注册：POST /api/v1/agent/enroll，Authorization: Bearer <注册令牌 OPENDLP_AGENT_TOKEN>
    → 返回 agentId 与 secret（只返回一次，服务端仅保存摘要）。同一主机重新注册会轮换密钥。
 2. 之后所有请求使用 Authorization: Agent <agentId>:<secret>，主机名以凭据为准，无法冒充其他终端：
    POST /api/v1/agent/heartbeat             心跳 + 领取指令 + 获知最新策略包版本
    GET  /api/v1/agent/policy                拉取策略包（支持 If-None-Match / 304）
    POST /api/v1/agent/detections            上报检测结果
    POST /api/v1/agent/commands/{id}/result  回传指令执行结果
 3. 管理员可在控制台吊销凭据，Agent 收到 401 后需重新注册。
*/

// Bundle 下发给终端的策略包。
type Bundle struct {
	Version   string          `json:"version"`
	Generated int64           `json:"generated"`
	Strict    bool            `json:"strict"`
	Policies  []detect.Policy `json:"policies"`
	Rules     []detect.Rule   `json:"rules"`
}

// buildBundle 生成终端的策略包（须在锁内调用）。版本号为内容摘要，内容不变则版本不变。
func buildBundle(d *store.Data, e *store.Endpoint) Bundle {
	b := Bundle{Strict: e != nil && e.Strict, Policies: []detect.Policy{}, Rules: []detect.Rule{}}
	for _, p := range d.Policies {
		if p.Enabled {
			b.Policies = append(b.Policies, detect.Policy{ID: p.ID, Name: p.Name, Channels: p.Channels, DataTypes: p.DataTypes, Action: p.Action, Severity: p.Severity, Threshold: p.Threshold})
		}
	}
	for _, r := range d.Rules {
		if r.Enabled && (r.Type == "regex" || r.Type == "keyword" || r.Type == "file") {
			b.Rules = append(b.Rules, detectRule(r))
		}
	}
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	b.Version = hex.EncodeToString(sum[:8])
	return b
}

func secretHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// POST /api/v1/agent/enroll —— 使用注册令牌换取终端独立凭据。
func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("enroll:" + s.clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "注册过于频繁，请稍后再试")
		return
	}
	var hb heartbeatReq
	if !readJSON(w, r, &hb) {
		return
	}
	hb.Host = clip(hb.Host, 64)
	if hb.Host == "" {
		writeErr(w, http.StatusBadRequest, "缺少主机名")
		return
	}
	secret := auth.RandomToken(32)
	var id string
	rotated := false
	isNew := false
	s.St.Write(func(d *store.Data) {
		e := upsertEndpoint(d, hb.Host, time.Now().UnixMilli(), &isNew)
		if d.AgentCreds == nil {
			d.AgentCreds = map[string]*store.AgentCred{}
		}
		_, rotated = d.AgentCreds[e.ID]
		d.AgentCreds[e.ID] = &store.AgentCred{Host: e.Host, Hash: secretHash(secret), Created: time.Now().UnixMilli()}
		e.Enrolled = true
		id = e.ID
	})
	_ = s.St.Save(r.Context()) // 凭据立即落盘，避免进程重启后 Agent 凭据失效
	_ = s.St.AppendAudit(r.Context(), store.AuditEntry{Op: "agent:" + hb.Host, Role: "终端 Agent", Type: "终端操作",
		Detail: fmt.Sprintf("终端 %s %s（%s，Agent %s）", hb.Host, map[bool]string{true: "重新注册并轮换凭据", false: "注册"}[rotated], id, clip(hb.Agent, 20)), IP: s.clientIP(r), OK: true})
	hb.IP = clip(hb.IP, 45)
	s.heartbeat(hb)
	writeJSON(w, http.StatusOK, map[string]string{"agentId": id, "secret": secret})
}

// agentAuth 校验 Authorization: Agent <id>:<secret>，并把凭据绑定的主机名传给处理函数。
func (s *Server) agentAuth(h func(w http.ResponseWriter, r *http.Request, id, host string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Agent ")
		id, secret, ok2 := strings.Cut(v, ":")
		if !ok || !ok2 || id == "" || secret == "" {
			writeErr(w, http.StatusUnauthorized, "缺少终端凭据")
			return
		}
		var host string
		valid := false
		s.St.Read(func(d *store.Data) {
			if c := d.AgentCreds[id]; c != nil && subtle.ConstantTimeCompare([]byte(c.Hash), []byte(secretHash(secret))) == 1 {
				valid, host = true, c.Host
			}
		})
		if !valid {
			writeErr(w, http.StatusUnauthorized, "终端凭据无效或已被吊销，请重新注册")
			return
		}
		h(w, r, id, host)
	}
}

// POST /api/v1/agent/heartbeat
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request, id, host string) {
	var hb heartbeatReq
	if !readJSON(w, r, &hb) {
		return
	}
	hb.Host = host
	cmds, version := s.heartbeat(hb)
	writeJSON(w, http.StatusOK, map[string]any{"commands": cmds, "policyVersion": version, "interval": 60})
}

// GET /api/v1/agent/policy —— 策略包（ETag 为版本号，未变化返回 304）。
func (s *Server) handleAgentPolicy(w http.ResponseWriter, r *http.Request, id, host string) {
	var b Bundle
	s.St.Read(func(d *store.Data) {
		var ep *store.Endpoint
		for _, e := range d.Endpoints {
			if e.ID == id {
				ep = e
			}
		}
		b = buildBundle(d, ep)
	})
	b.Generated = time.Now().UnixMilli()
	etag := `"` + b.Version + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// POST /api/v1/agent/detections
func (s *Server) handleAgentDetections(w http.ResponseWriter, r *http.Request, id, host string) {
	s.ingestDetections(w, r, host)
}

// POST /api/v1/agent/commands/{id}/result {ok, message}
func (s *Server) handleAgentCommandResult(w http.ResponseWriter, r *http.Request, agentID, host string) {
	var req struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	cid := r.PathValue("id")
	var c store.Command
	found := false
	s.St.Write(func(d *store.Data) {
		for _, x := range d.Commands {
			if x.ID == cid && x.Host == host { // 只能回传发给自己的指令
				x.Status, x.Result, x.Finished = map[bool]string{true: "done", false: "failed"}[req.OK], clip(req.Message, 300), time.Now().UnixMilli()
				c, found = *x, true
			}
		}
	})
	if !found {
		writeErr(w, http.StatusNotFound, "指令不存在")
		return
	}
	if !req.OK {
		s.addNote("warning", "终端指令执行失败", fmt.Sprintf("%s 执行「%s」失败：%s", host, c.Action, c.Result), "#/endpoints")
	}
	writeJSON(w, http.StatusOK, c)
}

// GET /api/v1/endpoints/{id}/commands —— 最近 20 条指令及执行结果。
func (s *Server) handleEndpointCommands(w http.ResponseWriter, r *http.Request, a *Actor) {
	id := r.PathValue("id")
	s.respond(w, func(d *store.Data) any {
		host := ""
		for _, e := range d.Endpoints {
			if e.ID == id {
				host = e.Host
			}
		}
		out := []*store.Command{}
		for i := len(d.Commands) - 1; i >= 0 && len(out) < 20; i-- {
			if d.Commands[i].Host == host {
				out = append(out, d.Commands[i])
			}
		}
		return out
	})
}

// POST /api/v1/endpoints/{id}/revoke —— 吊销终端凭据（Agent 需重新注册）。
func (s *Server) handleEndpointRevoke(w http.ResponseWriter, r *http.Request, a *Actor) {
	id := r.PathValue("id")
	s.mutate(w, func(d *store.Data) (int, any) {
		for _, e := range d.Endpoints {
			if e.ID == id {
				delete(d.AgentCreds, id)
				e.Enrolled = false
				s.auditIn(d, a, "终端操作", "吊销终端 "+e.Host+" 的 Agent 凭据", true, "")
				return http.StatusOK, e
			}
		}
		return http.StatusNotFound, fail("终端不存在")
	})
}
