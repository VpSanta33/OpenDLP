//go:build windows

package agent

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procDiskFree     = kernel32.NewProc("GetDiskFreeSpaceExW")
	procDriveType    = kernel32.NewProc("GetDriveTypeW")
	procLogicalDrive = kernel32.NewProc("GetLogicalDrives")
)

func diskUsed(path string) int {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var free, total, totalFree uint64
	r, _, _ := procDiskFree.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 || total == 0 {
		return 0
	}
	return int(100 - float64(free)/float64(total)*100)
}

func sameDevice(a, b string) bool {
	return strings.EqualFold(filepath.VolumeName(a), filepath.VolumeName(b))
}

// removableDrives 返回类型为可移动磁盘（DRIVE_REMOVABLE）的盘符根目录。
func removableDrives() []string {
	mask, _, _ := procLogicalDrive.Call()
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := syscall.UTF16PtrFromString(root)
		if t, _, _ := procDriveType.Call(uintptr(unsafe.Pointer(p))); t == 2 { // DRIVE_REMOVABLE
			out = append(out, root)
		}
	}
	return out
}

// desktopNotify Windows 服务会话无法直接弹窗，结果以隔离说明文件告知用户。
func desktopNotify(title, text string) {}
