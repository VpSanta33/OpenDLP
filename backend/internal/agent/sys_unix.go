//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func diskUsed(path string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0
	}
	return int(100 - float64(st.Bavail)/float64(st.Blocks)*100)
}

// sameDevice 两个路径是否位于同一文件系统（决定隔离时能否直接重命名）。
func sameDevice(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return false
	}
	x, ok1 := sa.Sys().(*syscall.Stat_t)
	y, ok2 := sb.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && x.Dev == y.Dev
}

// desktopNotify 尽力弹出桌面通知（以系统服务运行时可能无法显示，不影响处置）。
func desktopNotify(title, text string) {
	if _, err := exec.LookPath("osascript"); err == nil {
		q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		_ = exec.Command("osascript", "-e", "display notification "+q(text)+" with title "+q(title)).Start()
		return
	}
	if _, err := exec.LookPath("notify-send"); err == nil {
		_ = exec.Command("notify-send", "-u", "critical", title, text).Start()
	}
}

// removableDrives 仅 Windows 使用盘符枚举；其他平台通过挂载点识别可移动介质。
func removableDrives() []string { return nil }
