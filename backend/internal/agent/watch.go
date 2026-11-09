package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"opendlp/internal/detect"
)

// NoticeSuffix 隔离后在原位置留下的说明文件后缀。
const NoticeSuffix = ".DLP隔离说明.txt"

// root 一个被监控的根目录。
type root struct {
	Path    string
	Channel string
	Label   string
}

// mediaRoots 当前挂载的可移动介质。
func mediaRoots() []root {
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		es, _ := os.ReadDir("/Volumes")
		for _, e := range es {
			p := filepath.Join("/Volumes", e.Name())
			fi, err := os.Lstat(p)
			// 启动盘以符号链接形式出现在 /Volumes 中，跳过
			if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.Contains(e.Name(), "TimeMachine") {
				continue
			}
			paths = append(paths, p)
		}
	case "linux":
		f, err := os.Open("/proc/mounts")
		if err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				fs := strings.Fields(sc.Text())
				if len(fs) < 2 {
					continue
				}
				mp := strings.ReplaceAll(fs[1], `\040`, " ")
				if strings.HasPrefix(mp, "/media/") || strings.HasPrefix(mp, "/run/media/") {
					paths = append(paths, mp)
				}
			}
			f.Close()
		}
	case "windows":
		paths = removableDrives()
	}
	out := make([]root, 0, len(paths))
	for _, p := range paths {
		name := filepath.Base(strings.TrimRight(p, `\/`))
		if name == "" || name == "." || strings.HasSuffix(p, `:\`) {
			name = p
		}
		out = append(out, root{Path: p, Channel: "usb", Label: "可移动介质 " + name})
	}
	return out
}

// 不深入扫描的目录（系统 / 回收站 / 版本库 / 依赖缓存）。
var skipDirs = map[string]bool{".Trashes": true, ".Spotlight-V100": true, ".fseventsd": true, ".TemporaryItems": true, "$RECYCLE.BIN": true,
	"System Volume Information": true, ".git": true, "node_modules": true, ".DocumentRevisions-V100": true}

type fileSig struct {
	Size  int64
	MTime int64
}

// Scanner 轮询监控目录：新出现 / 被修改的文件在大小与修改时间稳定后进行检测。
type Scanner struct {
	a       *Agent
	known   map[string]fileSig // 已处理（或基线）的文件
	pending map[string]fileSig // 观察中、尚未稳定的文件
	roots   map[string]bool    // 已建立基线的根目录
}

func newScanner(a *Agent) *Scanner {
	return &Scanner{a: a, known: map[string]fileSig{}, pending: map[string]fileSig{}, roots: map[string]bool{}}
}

func (s *Scanner) currentRoots() []root {
	var rs []root
	if *s.a.cfg.Removable {
		rs = append(rs, mediaRoots()...)
	}
	for _, w := range s.a.cfg.Watch {
		label := w.Label
		if label == "" {
			label = filepath.Base(w.Path)
		}
		rs = append(rs, root{Path: w.Path, Channel: w.Channel, Label: label})
	}
	return rs
}

const maxWalk = 200000

// walk 遍历根目录下的普通文件。
func (s *Scanner) walk(r root, fn func(path string, sig fileSig)) {
	n := 0
	q := filepath.Clean(s.a.cfg.Quarantine)
	_ = filepath.WalkDir(r.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != r.Path && (skipDirs[d.Name()] || filepath.Clean(p) == q || strings.Count(strings.TrimPrefix(p, r.Path), string(filepath.Separator)) > 12) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasSuffix(p, NoticeSuffix) || strings.HasPrefix(d.Name(), "._") || d.Name() == ".DS_Store" {
			return nil
		}
		if n++; n > maxWalk {
			return fs.SkipAll
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		fn(p, fileSig{fi.Size(), fi.ModTime().UnixNano()})
		return nil
	})
}

// Poll 执行一轮轮询。根目录首次出现时（Agent 启动或介质插入）只建立基线，不检测已有文件；
// 之后新增或修改的文件在两轮之间保持不变即进行检测。
func (s *Scanner) Poll(ctx context.Context) {
	rs := s.currentRoots()
	present := map[string]bool{}
	for _, r := range rs {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Stat(r.Path); err != nil {
			continue
		}
		present[r.Path] = true
		if !s.roots[r.Path] {
			s.roots[r.Path] = true
			s.walk(r, func(p string, sig fileSig) { s.known[p] = sig })
			slog.Info("开始监控", "path", r.Path, "channel", r.Channel)
			continue
		}
		s.walk(r, func(p string, sig fileSig) {
			if k, ok := s.known[p]; ok && k == sig {
				return
			}
			if pd, ok := s.pending[p]; ok && pd == sig {
				delete(s.pending, p)
				s.known[p] = sig
				s.a.handleFile(ctx, r, p, sig.Size)
				return
			}
			s.pending[p] = sig
		})
	}
	// 介质拔出后清除其状态，重新插入时重新建立基线
	for p := range s.roots {
		if !present[p] {
			delete(s.roots, p)
			prefix := p + string(filepath.Separator)
			for k := range s.known {
				if strings.HasPrefix(k, prefix) {
					delete(s.known, k)
				}
			}
			for k := range s.pending {
				if strings.HasPrefix(k, prefix) {
					delete(s.pending, k)
				}
			}
			slog.Info("停止监控（介质已移除）", "path", p)
		}
	}
}

// FullScan 远程扫描指令：检测所有监控目录中的全部文件，返回文件数与命中数。
func (s *Scanner) FullScan(ctx context.Context) (files, hits int) {
	for _, r := range s.currentRoots() {
		s.walk(r, func(p string, sig fileSig) {
			if ctx.Err() != nil {
				return
			}
			files++
			if s.a.handleFile(ctx, r, p, sig.Size) {
				hits++
			}
			s.known[p] = sig
		})
	}
	return
}

/* ---------- 检测与处置 ---------- */

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// handleFile 检测单个文件并处置，返回是否命中敏感内容。
func (a *Agent) handleFile(ctx context.Context, r root, path string, size int64) bool {
	eng, bundle := a.engine()
	if eng == nil {
		return false
	}
	if size > detect.MaxFileBytes {
		slog.Debug("文件过大，跳过内容识别", "path", path, "size", size)
		return false
	}
	text, err := detect.ExtractFile(path)
	if err != nil {
		slog.Debug("读取文件失败", "path", path, "err", err)
		return false
	}
	name := filepath.Base(path)
	v := eng.Decide(eng.Scan(text), name, r.Channel)
	if v.Matches == 0 {
		return false
	}
	action, sev := v.Action, v.Severity
	// 严格管控（UEBA 高风险用户）：审计升级为阻断；未命中策略的敏感文件也生成事件
	if bundle.Strict {
		if action == "audit" {
			action = "block"
		}
		if !v.Hit {
			action, sev = "audit", "medium"
		}
	}
	dest := r.Label
	switch action {
	case "block":
		if qp, err := a.quarantine(path, v, r); err != nil {
			slog.Warn("隔离失败，降级为审计", "path", path, "err", err)
			action, dest = "audit", dest+"（隔离失败："+err.Error()+"）"
		} else {
			slog.Info("已隔离敏感文件", "path", path, "to", qp, "policy", v.Policy)
			if *a.cfg.Notify {
				desktopNotify("OpenDLP 数据防泄漏", fmt.Sprintf("「%s」含%s，违反策略「%s」，已被隔离", name, a.dataTypeName(v.DataType), v.Policy))
			}
		}
	case "encrypt":
		// 用户态 Agent 无法透明加密，按审计处理并在目的地中注明
		action, dest = "audit", dest+"（终端不支持加密放行，已记录）"
	}
	a.report(ctx, Detection{TS: time.Now().UnixMilli(), User: a.user, Host: a.host, IP: a.ip, Channel: r.Channel, Dest: clip(dest+" · "+path, 200),
		DataType: v.DataType, File: name, Size: humanSize(size), Matches: v.Matches, PolicyID: v.PolicyID, Action: action, Severity: sev, RuleIDs: v.RuleIDs})
	return true
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// quarantine 把文件移入隔离区，并在原位置写入说明文件。返回隔离后的路径。
func (a *Agent) quarantine(path string, v detect.Verdict, r root) (string, error) {
	day := time.Now().Format("2006-01-02")
	dir := filepath.Join(a.cfg.Quarantine, day)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(path + time.Now().String()))
	id := hex.EncodeToString(sum[:6])
	dst := filepath.Join(dir, id+"_"+filepath.Base(path))
	if err := moveFile(path, dst); err != nil {
		return "", err
	}
	meta := map[string]any{"original": path, "channel": r.Channel, "policy": v.Policy, "policyId": v.PolicyID, "dataType": v.DataType,
		"matches": v.Matches, "user": a.user, "host": a.host, "time": time.Now().Format(time.RFC3339)}
	_ = saveJSON(dst+".json", meta)
	notice := fmt.Sprintf("文件「%s」包含敏感数据（%s，命中 %d 处），违反数据防泄漏策略「%s」，已被移入隔离区。\r\n"+
		"隔离编号：%s　时间：%s\r\n如确有业务需要，请在 OpenDLP 中提交外发审批，或联系信息安全部门恢复。\r\n",
		filepath.Base(path), a.dataTypeName(v.DataType), v.Matches, v.Policy, id, time.Now().Format("2006-01-02 15:04:05"))
	_ = os.WriteFile(path+NoticeSuffix, []byte(notice), 0o644)
	return dst, nil
}

// moveFile 同一文件系统内直接重命名，跨设备（例如 U 盘 → 本机隔离区）时复制后删除原文件。
func moveFile(src, dst string) error {
	if sameDevice(src, filepath.Dir(dst)) {
		if err := os.Rename(src, dst); err == nil {
			return nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(out, in)
	in.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return err
	}
	if err := os.Remove(src); err != nil {
		os.Remove(dst)
		return fmt.Errorf("无法删除原文件（介质可能只读）: %w", err)
	}
	return nil
}

// QuarantineList 列出隔离区中的文件（本地运维使用）。
func QuarantineList(dir string) ([]map[string]any, error) {
	var out []map[string]any
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if strings.HasSuffix(p, ".json") {
			var m map[string]any
			if ok, _ := loadJSON(p, &m); ok {
				m["file"] = strings.TrimSuffix(p, ".json")
				out = append(out, m)
			}
		}
		return nil
	})
	return out, err
}
