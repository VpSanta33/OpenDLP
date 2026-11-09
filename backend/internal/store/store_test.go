package store_test

import (
	"context"
	"testing"
	"time"

	. "opendlp/internal/store"
	"opendlp/internal/storetest"
)

func emptyData() *Data {
	return &Data{Seq: map[string]int{}, Channels: []Channel{{Key: "usb"}, {Key: "email"}}, DataTypes: []DataType{{Key: "idcard"}}, Settings: map[string]any{}}
}

func TestAuditChainAppendOnly(t *testing.T) {
	st := storetest.Open(t, emptyData)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := st.AppendAudit(ctx, AuditEntry{Op: "admin", Type: "登录", Detail: "第 " + string(rune('1'+i)) + " 次", OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	if n, bad, err := st.VerifyAudit(ctx); err != nil || n != 5 || bad != "" {
		t.Fatalf("完整链校验失败：%d %q %v", n, bad, err)
	}
	for _, q := range []string{`UPDATE audit_log SET detail = 'x' WHERE seq = 2`, `DELETE FROM audit_log WHERE seq = 2`, `TRUNCATE audit_log`} {
		if _, err := st.DB.Exec(ctx, q); err == nil {
			t.Fatalf("数据库应拒绝：%s", q)
		}
	}
	// 绕过应用直接插入伪造记录：哈希链校验应能发现
	if _, err := st.DB.Exec(ctx, `INSERT INTO audit_log (seq, id, ts, op, role, type, detail, ip, ok, reason, prev, hash)
		VALUES (99, 'AUD-99', now(), 'attacker', '', '登录', '伪造', '', true, '', 'bogus', 'bogus')`); err != nil {
		t.Fatal(err)
	}
	if _, bad, _ := st.VerifyAudit(ctx); bad != "AUD-99" {
		t.Fatalf("应定位到伪造记录 AUD-99，实际 %q", bad)
	}
}

func TestIncidentsAndDashboard(t *testing.T) {
	st := storetest.Open(t, emptyData)
	ctx := context.Background()
	loc := st.Loc
	now := time.Date(2026, 11, 9, 12, 30, 0, 0, loc)
	for i := 0; i < 12; i++ { // 乱序写入检测量（模拟补报）
		ts := now.Add(-time.Duration(11-i) * time.Hour).UnixMilli()
		if i%2 == 0 {
			ts = now.Add(-time.Duration(i) * time.Hour).UnixMilli()
		}
		act := "allow"
		if i%3 == 0 {
			act = "block"
		}
		if err := st.AddDetection(ctx, ts, "usb", "idcard", act); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.AddDetection(ctx, now.AddDate(0, 0, -1).UnixMilli(), "email", "idcard", "allow")
	for i, sev := range []string{"critical", "high", "low"} {
		id, _ := st.NextIncidentID(ctx)
		if err := st.InsertIncident(ctx, &Incident{ID: id, TS: now.Add(-time.Duration(i) * time.Minute).UnixMilli(), User: "张三", Channel: "usb", DataType: "idcard", File: "a.xlsx", Severity: sev, Action: "block", Status: "pending"}); err != nil {
			t.Fatal(err)
		}
	}
	db, err := st.BuildDashboard(ctx, "today", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Labels) != 24 || db.Labels[23] != "12:00" || db.Empty {
		t.Fatalf("小时标签或空状态错误：%v %v", db.Labels, db.Empty)
	}
	if db.KPI.Pending != 2 || db.KPI.Delta["events"] != nil {
		t.Fatalf("KPI 错误：%+v", db.KPI)
	}
	week, _ := st.BuildDashboard(ctx, "7d", now)
	if week.KPI.Events != 13 || week.Channels[1].Value != 1 {
		t.Fatalf("7 天统计错误：events=%d channels=%v", week.KPI.Events, week.Channels)
	}
	list, total, err := st.ListIncidents(ctx, IncidentFilter{Sev: "critical"}, 1, 10)
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("筛选错误：%d %v", total, err)
	}
	closed, _ := st.CloseIncidents(ctx, []string{list[0].ID, "INC-NOPE"}, "resolved", "李华")
	again, _ := st.CloseIncidents(ctx, []string{list[0].ID}, "fp", "李华")
	if len(closed) != 1 || closed[0].Handler != "李华" || len(again) != 0 {
		t.Fatalf("关闭事件错误：%v %v", closed, again)
	}
	if n, _ := st.CountIncidents(ctx, IncidentFilter{Q: "a.xl"}); n != 3 {
		t.Fatalf("关键字搜索错误：%d", n)
	}
	empty := storetest.Open(t, emptyData)
	if e, err := empty.BuildDashboard(ctx, "30d", now); err != nil || !e.Empty || e.Risk.Level != "暂无数据" {
		t.Fatalf("空库看板错误：%+v %v", e.Risk, err)
	}
}

func TestConfigPersistence(t *testing.T) {
	st := storetest.Open(t, emptyData)
	st.Write(func(d *Data) { d.Policies = append(d.Policies, &Policy{ID: "POL-1", Name: "测试"}) })
	if err := st.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB.QueryRow(context.Background(), `SELECT jsonb_array_length(data->'policies') FROM documents WHERE name = 'config'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("配置未持久化：%d %v", n, err)
	}
}
