// Package agent 实现 OpenDLP 跨平台用户态终端 Agent。
//
// 工作方式（事后检测 + 隔离，不依赖内核驱动）：
//   - 使用注册令牌换取终端独立凭据，定期心跳、领取指令、按版本同步策略包；
//   - 轮询可移动介质（U 盘 / 移动硬盘）与配置的同步目录（网盘、IM 文件夹等），
//     对新出现或被修改的文件做内容识别（与服务端共用 detect 引擎）；
//   - 命中「阻断」策略的文件移入本地隔离区并在原位置留下说明文件，所有命中上报控制台；
//   - 网络不可用时检测结果写入本地队列，恢复后补报。
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Watch 一个需要监控的目录及其外发渠道（usb / cloud / im / email / web / print）。
type Watch struct {
	Path    string `json:"path"`
	Channel string `json:"channel"`
	Label   string `json:"label,omitempty"` // 上报中的目的地描述，默认取目录名
}

// Config Agent 配置（JSON 文件，命令行参数可覆盖）。
type Config struct {
	Server      string  `json:"server"`      // 管理控制台地址，例如 https://dlp.corp.example
	EnrollToken string  `json:"enrollToken"` // 注册令牌（控制台「终端管理 → 部署 Agent」获取），注册成功后不再使用
	DataDir     string  `json:"dataDir"`     // 凭据、策略缓存、离线队列与隔离区
	CAFile      string  `json:"caFile,omitempty"`
	Removable   *bool   `json:"removable,omitempty"` // 是否监控可移动介质，默认 true
	Watch       []Watch `json:"watch,omitempty"`
	ScanSeconds int     `json:"scanSeconds,omitempty"` // 轮询间隔，默认 5 秒
	User        string  `json:"user,omitempty"`        // 终端使用人（默认取当前登录用户）
	Dept        string  `json:"dept,omitempty"`
	Quarantine  string  `json:"quarantine,omitempty"` // 隔离区目录，默认 <dataDir>/quarantine
	Notify      *bool   `json:"notify,omitempty"`     // 是否弹出桌面通知，默认 true
}

// DefaultConfigPath 各平台默认配置文件位置。
func DefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programData(), "OpenDLP", "agent.json")
	case "darwin":
		return "/Library/Application Support/OpenDLP/agent.json"
	default:
		return "/etc/opendlp/agent.json"
	}
}

func defaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programData(), "OpenDLP", "data")
	case "darwin":
		return "/Library/Application Support/OpenDLP/data"
	default:
		return "/var/lib/opendlp-agent"
	}
}

func programData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

// LoadConfig 读取配置文件；文件不存在时返回空配置（全部来自命令行参数）。
func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("配置文件 %s 格式错误: %w", path, err)
		}
	}
	return c, nil
}

var validChannels = map[string]bool{"usb": true, "cloud": true, "im": true, "email": true, "web": true, "print": true}

// Normalize 补齐默认值并校验。
func (c *Config) Normalize() error {
	c.Server = strings.TrimRight(strings.TrimSpace(c.Server), "/")
	u, err := url.Parse(c.Server)
	if c.Server == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("请配置管理控制台地址 server，例如 https://dlp.corp.example")
	}
	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	if c.Quarantine == "" {
		c.Quarantine = filepath.Join(c.DataDir, "quarantine")
	}
	if c.ScanSeconds <= 0 {
		c.ScanSeconds = 5
	}
	if c.Removable == nil {
		t := true
		c.Removable = &t
	}
	if c.Notify == nil {
		t := true
		c.Notify = &t
	}
	for i, w := range c.Watch {
		if w.Path == "" || !validChannels[w.Channel] {
			return fmt.Errorf("watch[%d]：须填写 path，channel 取值 usb / cloud / im / email / web / print", i)
		}
		if strings.HasPrefix(w.Path, "~") {
			if h, err := os.UserHomeDir(); err == nil {
				c.Watch[i].Path = filepath.Join(h, w.Path[1:])
			}
		}
	}
	return nil
}

func (c *Config) scanEvery() time.Duration { return time.Duration(c.ScanSeconds) * time.Second }
