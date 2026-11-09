package agent

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opendlp/internal/api"
	"opendlp/internal/detect"
	"opendlp/internal/seed"
	"opendlp/internal/store"
	"opendlp/internal/storetest"
)

// idCard 生成校验位正确的 18 位身份证号。
func idCard(seq int) string {
	base := fmt.Sprintf("1101051990010%d%03d", 1+seq%9, seq%1000)
	w := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i, c := range base {
		sum += int(c-'0') * w[i]
	}
	id := base + string("10X98765432"[sum%11])
	if !detect.IDCardOK(id) {
		panic(id)
	}
	return id
}

type env struct {
	st             *store.Store
	srv            *api.Server
	a              *Agent
	usb, cloud, qd string
}

func setup(t *testing.T) *env {
	t.Helper()
	st := storetest.Open(t, func() *store.Data { return seed.Reference(time.Now()) })
	srv := api.New(st, api.Config{AgentToken: "enroll-token-for-tests", Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Alerts.Run(ctx)
	st.Write(func(d *store.Data) {
		d.Policies = append(d.Policies,
			&store.Policy{ID: "P-1", Name: "身份证号 U 盘拷贝阻断", Channels: []string{"usb"}, DataTypes: []string{"idcard"}, Action: "block", Severity: "critical", Enabled: true, Threshold: 2},
			&store.Policy{ID: "P-2", Name: "网盘手机号审计", Channels: []string{"cloud"}, DataTypes: []string{"phone"}, Action: "audit", Severity: "medium", Enabled: true})
	})
	e := &env{st: st, srv: srv, usb: t.TempDir(), cloud: t.TempDir()}
	data := t.TempDir()
	e.qd = filepath.Join(data, "quarantine")
	off := false
	cfg := &Config{Server: ts.URL, EnrollToken: "enroll-token-for-tests", DataDir: data, Removable: &off, Notify: &off, User: "张伟",
		Watch: []Watch{{Path: e.usb, Channel: "usb", Label: "测试U盘"}, {Path: e.cloud, Channel: "cloud"}}}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.a = a
	return e
}

func (e *env) incidents(t *testing.T) []*store.Incident {
	t.Helper()
	list, _, err := e.st.ListIncidents(context.Background(), store.IncidentFilter{}, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// settle 连续轮询两次：第一次发现新文件，第二次确认稳定后检测。
func (e *env) settle(ctx context.Context) {
	e.a.scan.Poll(ctx)
	e.a.scan.Poll(ctx)
}

func TestAgentEndToEnd(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.a.loadState(); err != nil {
		t.Fatal(err)
	}
	if err := e.a.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	if changed, err := e.a.SyncPolicy(ctx); err != nil || !changed {
		t.Fatalf("首次同步策略失败：%v %v", changed, err)
	}
	if changed, _ := e.a.SyncPolicy(ctx); changed {
		t.Fatal("策略未变化时应返回 304")
	}
	ids := idCard(1) + "\n" + idCard(2) + "\n" + idCard(3) + "\n"

	// 启动前已存在的文件只建立基线，不检测
	old := filepath.Join(e.usb, "历史文件.txt")
	os.WriteFile(old, []byte(ids), 0o644)
	e.a.scan.Poll(ctx)
	e.settle(ctx)
	if _, err := os.Stat(old); err != nil || len(e.incidents(t)) != 0 {
		t.Fatal("基线文件不应被检测或隔离")
	}

	// 新拷入 U 盘的含身份证号文件：隔离 + 说明文件 + 严重事件
	sub := filepath.Join(e.usb, "资料")
	os.MkdirAll(sub, 0o755)
	f := filepath.Join(sub, "员工信息表.csv")
	os.WriteFile(f, []byte("姓名,身份证号\n"+strings.ReplaceAll(ids, "\n", ",张三\n")), 0o644)
	e.settle(ctx)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("命中阻断策略的文件应被移出 U 盘")
	}
	notice, err := os.ReadFile(f + NoticeSuffix)
	if err != nil || !strings.Contains(string(notice), "身份证号") || !strings.Contains(string(notice), "身份证号 U 盘拷贝阻断") {
		t.Fatalf("应在原位置留下说明文件：%v %s", err, notice)
	}
	q, _ := QuarantineList(e.qd)
	if len(q) != 1 || q[0]["original"] != f {
		t.Fatalf("隔离区记录错误：%v", q)
	}
	if b, err := os.ReadFile(q[0]["file"].(string)); err != nil || !strings.Contains(string(b), idCard(1)) {
		t.Fatal("隔离文件内容应完整保留")
	}
	inc := e.incidents(t)
	if len(inc) != 1 || inc[0].Action != "block" || inc[0].Severity != "critical" || inc[0].Channel != "usb" || inc[0].Host != e.a.host || inc[0].User != "张伟" || inc[0].Matches != 3 || inc[0].PolicyID != "P-1" {
		t.Fatalf("事件记录错误：%+v", inc)
	}

	// 低于阈值（1 个身份证号）不触发阻断，仅计入检测量；无敏感内容不上报
	os.WriteFile(filepath.Join(e.usb, "单条.txt"), []byte(idCard(4)), 0o644)
	os.WriteFile(filepath.Join(e.usb, "普通.txt"), []byte("会议纪要：下周例会改到周三"), 0o644)
	// 网盘目录中的手机号：仅审计，文件保留
	phone := filepath.Join(e.cloud, "通讯录.txt")
	os.WriteFile(phone, []byte("13912345678 张三\n18611112222 李四"), 0o644)
	e.settle(ctx)
	if _, err := os.Stat(filepath.Join(e.usb, "单条.txt")); err != nil {
		t.Fatal("未达阈值的文件不应被隔离")
	}
	if _, err := os.Stat(phone); err != nil {
		t.Fatal("审计策略不应移动文件")
	}
	inc = e.incidents(t)
	if len(inc) != 2 || inc[0].Channel != "cloud" || inc[0].Action != "audit" || inc[0].DataType != "phone" {
		t.Fatalf("网盘审计事件错误：%+v", inc[0])
	}

	// 远程指令：扫描、策略推送成功；网络隔离与升级明确返回不支持
	e.st.Write(func(d *store.Data) {
		for _, a := range []string{"scan", "push", "isolate", "upgrade:3.4.0"} {
			d.Commands = append(d.Commands, &store.Command{ID: "CMD-" + a, Host: e.a.host, Action: a, Status: "pending"})
		}
	})
	if err := e.a.beat(ctx); err != nil {
		t.Fatal(err)
	}
	res := map[string]*store.Command{}
	e.st.Read(func(d *store.Data) {
		for _, c := range d.Commands {
			cp := *c
			res[c.Action] = &cp
		}
	})
	if c := res["scan"]; c.Status != "done" || !strings.Contains(c.Result, "已扫描") {
		t.Fatalf("扫描指令结果错误：%+v", c)
	}
	if res["push"].Status != "done" || res["isolate"].Status != "failed" || res["upgrade:3.4.0"].Status != "failed" {
		t.Fatalf("指令执行结果错误：%+v %+v %+v", res["push"], res["isolate"], res["upgrade:3.4.0"])
	}

	// 策略变更：心跳返回新版本后自动同步
	_, before := e.a.engine()
	e.st.Write(func(d *store.Data) { d.Policies[0].Threshold = 1 })
	e.a.beat(ctx)
	if _, after := e.a.engine(); after.Version == before.Version || after.Policies[0].Threshold != 1 {
		t.Fatal("策略变更后应在心跳时同步")
	}

	// 凭据被吊销：心跳收到 401 后使用注册令牌重新注册
	oldID := e.a.cli.Secret
	e.st.Write(func(d *store.Data) { d.AgentCreds = map[string]*store.AgentCred{} })
	if err := e.a.beat(ctx); err != nil {
		t.Fatalf("吊销后应自动重新注册：%v", err)
	}
	if e.a.cli.Secret == oldID {
		t.Fatal("重新注册应获得新凭据")
	}
	var st State
	if ok, _ := loadJSON(e.a.statePath(), &st); !ok || st.Secret != e.a.cli.Secret {
		t.Fatal("新凭据应保存到本地")
	}
	if fi, _ := os.Stat(e.a.statePath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("凭据文件权限应为 0600：%v", fi.Mode())
	}
}

func TestOfflineQueue(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.a.loadState()
	e.a.Enroll(ctx)
	e.a.SyncPolicy(ctx)
	e.a.scan.Poll(ctx)
	// 控制台不可达：检测与隔离照常进行，结果进入离线队列
	good := e.a.cli.Base
	e.a.cli.Base = "http://127.0.0.1:1"
	f := filepath.Join(e.usb, "名单.txt")
	os.WriteFile(f, []byte(idCard(5)+"\n"+idCard(6)), 0o644)
	e.settle(ctx)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("离线时仍应按本地策略隔离")
	}
	if e.a.queue.Len() != 1 || len(e.incidents(t)) != 0 {
		t.Fatalf("离线检测结果应进入队列：%d", e.a.queue.Len())
	}
	// 本地策略缓存：重启后无需联网即可加载
	a2, _ := New(e.a.cfg)
	a2.loadState()
	if eng, _ := a2.engine(); eng == nil {
		t.Fatal("重启后应加载本地策略缓存")
	}
	// 恢复连接后心跳时补报
	e.a.cli.Base = good
	if err := e.a.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if e.a.queue.Len() != 0 || len(e.incidents(t)) != 1 {
		t.Fatalf("恢复后应补报离线结果：队列 %d，事件 %d", e.a.queue.Len(), len(e.incidents(t)))
	}
}

func TestStrictMode(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.a.loadState()
	e.a.Enroll(ctx)
	e.st.Write(func(d *store.Data) {
		for _, x := range d.Endpoints {
			x.Strict = true
		}
	})
	e.a.SyncPolicy(ctx)
	if _, b := e.a.engine(); !b.Strict {
		t.Fatal("严格管控终端的策略包应带 strict 标记")
	}
	e.a.scan.Poll(ctx)
	// 网盘审计策略在严格管控下升级为阻断
	f := filepath.Join(e.cloud, "通讯录.txt")
	os.WriteFile(f, []byte("13912345678"), 0o644)
	e.settle(ctx)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("严格管控下审计应升级为阻断")
	}
	if inc := e.incidents(t); len(inc) != 1 || inc[0].Action != "block" {
		t.Fatalf("严格管控事件错误：%+v", inc)
	}
}

func TestHumanSize(t *testing.T) {
	if humanSize(1536) != "2 KB" || humanSize(3<<20) != "3.0 MB" || humanSize(512) != "512 B" {
		t.Fatal(humanSize(1536), humanSize(3<<20))
	}
}
