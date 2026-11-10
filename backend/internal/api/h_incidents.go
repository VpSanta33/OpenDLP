package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"opendlp/internal/store"
)

var sevName = map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
var actName = map[string]string{"block": "已阻断", "encrypt": "加密放行", "audit": "仅审计", "allow": "已放行"}
var stName = map[string]string{"pending": "待处置", "processing": "处置中", "resolved": "已处置", "fp": "误报"}

func atoiDef(s string, def, lo, hi int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return max(lo, min(hi, n))
}

func incFilter(q map[string]string) store.IncidentFilter {
	return store.IncidentFilter{Q: strings.TrimSpace(q["q"]), Sev: q["sev"], Ch: q["ch"], St: q["st"]}
}

// GET /api/v1/incidents?q=&sev=&ch=&st=&page=&per=
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request, a *Actor) {
	qs := r.URL.Query()
	f := incFilter(map[string]string{"q": qs.Get("q"), "sev": qs.Get("sev"), "ch": qs.Get("ch"), "st": qs.Get("st")})
	page, per := atoiDef(qs.Get("page"), 1, 1, 100000), atoiDef(qs.Get("per"), 10, 1, 100)
	items, total, err := s.St.ListIncidents(r.Context(), f, page, per)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "查询事件失败")
		return
	}
	counts, err := s.St.SeverityCounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "统计事件失败")
		return
	}
	if items == nil {
		items = []*store.Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "per": per, "counts": counts})
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request, a *Actor) {
	i, err := s.St.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "查询事件失败")
		return
	}
	if i == nil {
		writeErr(w, http.StatusNotFound, "事件不存在")
		return
	}
	writeJSON(w, http.StatusOK, i)
}

// POST /api/v1/incidents/{id}/resolve {status: resolved|fp}
func (s *Server) handleIncidentResolve(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ Status string }
	if !readJSON(w, r, &req) {
		return
	}
	if req.Status != "resolved" && req.Status != "fp" {
		writeErr(w, http.StatusBadRequest, "处置状态无效")
		return
	}
	id := r.PathValue("id")
	closed, err := s.St.CloseIncidents(r.Context(), []string{id}, req.Status, a.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "处置失败")
		return
	}
	if len(closed) == 0 {
		if i, _ := s.St.GetIncident(r.Context(), id); i == nil {
			writeErr(w, http.StatusNotFound, "事件不存在")
		} else {
			writeErr(w, http.StatusConflict, "事件已关闭，无需重复处置")
		}
		return
	}
	s.audit(a, "事件处置", fmt.Sprintf("将事件 %s 标记为%s", id, stName[req.Status]), true, "")
	s.Hub.Publish(Event{Name: "incidents.changed", Module: "incidents", Data: map[string]any{"ids": []string{id}}})
	writeJSON(w, http.StatusOK, closed[0])
}

// POST /api/v1/incidents/batch-resolve {ids}
func (s *Server) handleIncidentBatch(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct{ IDs []string }
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 200 {
		writeErr(w, http.StatusBadRequest, "请选择 1-200 个事件")
		return
	}
	closed, err := s.St.CloseIncidents(r.Context(), req.IDs, "resolved", a.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "处置失败")
		return
	}
	s.audit(a, "事件处置", fmt.Sprintf("批量处置 %d 个事件", len(closed)), true, "")
	s.Hub.Publish(Event{Name: "incidents.changed", Module: "incidents", Data: map[string]any{"ids": req.IDs}})
	writeJSON(w, http.StatusOK, map[string]int{"resolved": len(closed)})
}

/* ---------- 事件写入（上报接口与演示模拟器共用） ---------- */

// RecordIncident 入库一条事件：分配编号、写入事件表、累加检测量与策略命中、严重事件生成通知，然后实时推送。
// enrich 在配置读锁内补全事件字段（部门、策略名等），可为 nil。
func (s *Server) RecordIncident(ctx context.Context, inc *store.Incident, enrich func(d *store.Data, i *store.Incident)) error {
	if inc.ID == "" {
		id, err := s.St.NextIncidentID(ctx)
		if err != nil {
			return err
		}
		inc.ID = id
	}
	var chName, dtName string
	s.St.Write(func(d *store.Data) {
		if enrich != nil {
			enrich(d, inc)
		}
		for _, p := range d.Policies {
			if p.ID == inc.PolicyID {
				p.Hits++
				if inc.Policy == "" {
					inc.Policy = p.Name
				}
			}
		}
		chName, dtName = d.ChannelName(inc.Channel), d.DataTypeName(inc.DataType)
	})
	if err := s.St.InsertIncident(ctx, inc); err != nil {
		return err
	}
	if err := s.St.AddDetection(ctx, inc.TS, inc.Channel, inc.DataType, inc.Action); err != nil {
		slog.Error("累加检测量失败", "err", err)
	}
	s.Hub.Publish(Event{Name: "incident", Module: "dashboard", Data: *inc})
	s.Alerts.Incident(*inc, chName, dtName)
	if inc.Severity == "critical" {
		s.addNote("danger", "严重事件", fmt.Sprintf("%s 尝试通过%s外发 %s，处置：%s", inc.User, chName, inc.File, actName[inc.Action]), "#/incidents?sev=critical")
	}
	return nil
}

/* ---------- 导出 ---------- */

// csvSafe 防止 CSV 公式注入。
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func buildCSV(header []string, rows [][]string) []byte {
	var buf bytes.Buffer
	buf.WriteString("\xEF\xBB\xBF") // Excel 识别 UTF-8
	cw := csv.NewWriter(&buf)
	_ = cw.Write(header)
	for _, r := range rows {
		for i := range r {
			r[i] = csvSafe(r[i])
		}
		_ = cw.Write(r)
	}
	cw.Flush()
	return buf.Bytes()
}

func fmtTS(ms int64, loc *time.Location) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).In(loc).Format("2006-01-02 15:04:05")
}

// POST /api/v1/exports {kind, filter}
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, a *Actor) {
	var req struct {
		Kind   string            `json:"kind"`
		Filter map[string]string `json:"filter"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	module := map[string]string{"incidents": "incidents", "audit": "audit", "endpoints": "endpoints"}[req.Kind]
	if module == "" {
		writeErr(w, http.StatusBadRequest, "不支持的导出类型")
		return
	}
	if !allowed(a.Perms, module, "exp") {
		s.audit(a, "越权访问", "尝试导出 "+req.Kind, false, "权限不足")
		writeErr(w, http.StatusForbidden, "当前角色无导出权限")
		return
	}
	f := req.Filter
	if f == nil {
		f = map[string]string{}
	}
	loc := s.St.Loc
	day := time.Now().In(loc).Format("2006-01-02")
	var rows [][]string
	var name string
	var data []byte
	var err error
	switch req.Kind {
	case "incidents":
		chs, dts := map[string]string{}, map[string]string{}
		s.St.Read(func(d *store.Data) {
			for _, c := range d.Channels {
				chs[c.Key] = c.Name
			}
			for _, t := range d.DataTypes {
				dts[t.Key] = t.Name
			}
		})
		err = s.St.EachIncident(r.Context(), incFilter(f), func(i *store.Incident) {
			rows = append(rows, []string{i.ID, fmtTS(i.TS, loc), sevName[i.Severity], i.User, i.Dept, i.Host, i.IP, chs[i.Channel], i.Dest,
				dts[i.DataType], i.File, i.Size, strconv.Itoa(i.Matches), i.Policy, actName[i.Action], stName[i.Status], i.Handler})
		})
		name = fmt.Sprintf("DLP事件_%d条_%s.csv", len(rows), day)
		data = buildCSV([]string{"事件ID", "检测时间", "级别", "用户", "部门", "终端", "IP", "外发通道", "目的地", "数据类型", "文件", "大小", "命中数", "策略", "处置动作", "状态", "处置人"}, rows)
	case "audit":
		err = s.St.EachAudit(r.Context(), store.AuditFilter{Q: f["q"], Type: f["type"], Result: f["result"]}, func(e store.AuditEntry) {
			ok := "成功"
			if !e.OK {
				ok = "失败：" + e.Reason
			}
			rows = append(rows, []string{e.ID, fmtTS(e.TS, loc), e.Op, e.Role, e.Type, e.Detail, e.IP, ok, e.Hash})
		})
		name = fmt.Sprintf("审计日志_%d条_%s.csv", len(rows), day)
		data = buildCSV([]string{"日志ID", "时间", "操作人", "角色", "类型", "操作内容", "来源IP", "结果", "哈希（SHA-256 链）"}, rows)
	case "endpoints":
		s.St.Read(func(d *store.Data) {
			for _, e := range d.Endpoints {
				rows = append(rows, []string{e.ID, e.Host, e.User, e.Dept, e.IP, e.OS, e.Agent, e.Status, fmtTS(e.LastSeen, loc)})
			}
		})
		name = fmt.Sprintf("终端清单_%s.csv", day)
		data = buildCSV([]string{"终端ID", "主机名", "用户", "部门", "IP", "操作系统", "Agent 版本", "状态", "最近心跳"}, rows)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "导出失败")
		return
	}
	s.audit(a, "数据导出", fmt.Sprintf("导出%s（%d 条，CSV）", map[string]string{"incidents": "事件记录", "audit": "审计日志", "endpoints": "终端清单"}[req.Kind], len(rows)), true, "")
	job := s.Jobs.Start(a.Acc, "export", name, 600*time.Millisecond, func() (string, string, []byte, error) {
		return name, "text/csv; charset=utf-8", data, nil
	})
	writeJSON(w, http.StatusAccepted, job)
}
