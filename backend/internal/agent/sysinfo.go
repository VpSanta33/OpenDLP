package agent

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Version Agent 版本，构建时通过 -ldflags "-X opendlp/internal/agent.Version=…" 注入。
var Version = "3.3.0"

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return strings.TrimSuffix(h, ".local")
}

func run(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// consoleUser 当前使用终端的用户（以系统服务运行时取控制台登录用户）。
func consoleUser() string {
	switch runtime.GOOS {
	case "darwin":
		if u := run("stat", "-f", "%Su", "/dev/console"); u != "" && u != "root" {
			return u
		}
	case "linux":
		for _, base := range []string{"/run/media", "/media"} {
			if es, err := os.ReadDir(base); err == nil {
				for _, e := range es {
					if e.IsDir() && e.Name() != "root" {
						if _, err := user.Lookup(e.Name()); err == nil {
							return e.Name()
						}
					}
				}
			}
		}
		if f := strings.Fields(run("who")); len(f) > 0 {
			return f[0]
		}
	case "windows":
		if u := os.Getenv("USERNAME"); u != "" && !strings.HasSuffix(u, "$") {
			return u
		}
	}
	if u, err := user.Current(); err == nil {
		name := u.Username
		if i := strings.LastIndexAny(name, `\/`); i >= 0 {
			name = name[i+1:]
		}
		return name
	}
	return ""
}

// outboundIP 访问控制台时使用的本机地址。
func outboundIP(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// osInfo 操作系统描述与控制台使用的分类（win / mac / linux / uos / kylin）。
func osInfo() (string, string) {
	switch runtime.GOOS {
	case "darwin":
		return strings.TrimSpace("macOS " + run("sw_vers", "-productVersion")), "mac"
	case "windows":
		v := run("cmd", "/c", "ver")
		if v == "" {
			v = "Windows"
		}
		return v, "win"
	case "linux":
		name, id := "Linux", ""
		if f, err := os.Open("/etc/os-release"); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				k, v, _ := strings.Cut(sc.Text(), "=")
				v = strings.Trim(v, `"`)
				switch k {
				case "PRETTY_NAME":
					name = v
				case "ID":
					id = strings.ToLower(v)
				}
			}
		}
		key := "linux"
		switch {
		case strings.Contains(id, "kylin"):
			key = "kylin"
		case strings.Contains(id, "uos"), strings.Contains(id, "deepin"):
			key = "uos"
		}
		return name, key
	}
	return runtime.GOOS, runtime.GOOS
}

// usage 返回 CPU / 内存 / 磁盘使用率（百分比，无法获取时为 0）。
func usage() (cpu, mem, disk int) {
	switch runtime.GOOS {
	case "linux":
		cpu = linuxCPU()
		if f, err := os.Open("/proc/meminfo"); err == nil {
			defer f.Close()
			var total, avail float64
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				fs := strings.Fields(sc.Text())
				if len(fs) < 2 {
					continue
				}
				v, _ := strconv.ParseFloat(fs[1], 64)
				switch fs[0] {
				case "MemTotal:":
					total = v
				case "MemAvailable:":
					avail = v
				}
			}
			if total > 0 {
				mem = int(100 - avail/total*100)
			}
		}
	case "darwin":
		var sum float64
		for _, l := range strings.Split(run("ps", "-A", "-o", "%cpu="), "\n") {
			v, _ := strconv.ParseFloat(strings.TrimSpace(l), 64)
			sum += v
		}
		cpu = int(sum / float64(runtime.NumCPU()))
		// System-wide memory free percentage: 63%
		out := run("memory_pressure", "-Q")
		if i := strings.LastIndex(out, ":"); i >= 0 {
			if v, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(out[i+1:]), "%")); err == nil {
				mem = 100 - v
			}
		}
	}
	root := "/"
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(os.Getenv("SystemRoot")) + `\`
	}
	disk = diskUsed(root)
	return min(100, max(0, cpu)), min(100, max(0, mem)), min(100, max(0, disk))
}

var lastCPU [2]float64

func linuxCPU() int {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fs := strings.Fields(line)
	if len(fs) < 5 {
		return 0
	}
	var total, idle float64
	for i, f := range fs[1:] {
		v, _ := strconv.ParseFloat(f, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	dt, di := total-lastCPU[0], idle-lastCPU[1]
	lastCPU = [2]float64{total, idle}
	if dt <= 0 {
		return 0
	}
	return int((dt - di) / dt * 100)
}
