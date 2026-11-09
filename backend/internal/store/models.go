// Package store 持有平台全部业务数据，提供并发安全的读写与 JSON 文件持久化。
package store

// 所有时间戳均为 Unix 毫秒，便于前端直接使用。

type Channel struct {
	Key  string   `json:"key"`
	Name string   `json:"name"`
	Icon string   `json:"icon"`
	Dest []string `json:"dest"`
}

type DataType struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Sample string `json:"sample"`
}

type Employee struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Dept   string `json:"dept"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Title  string `json:"title"`
	Status string `json:"status"` // active | leaving | left
	Email  string `json:"email"`
	Joined int64  `json:"joined"`
	Core   bool   `json:"core,omitempty"` // 核心监控样本用户（总览、UEBA 使用）
}

type Policy struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Desc      string   `json:"desc"`
	Channels  []string `json:"channels"`
	DataTypes []string `json:"dataTypes"`
	Action    string   `json:"action"`
	Severity  string   `json:"severity"`
	Enabled   bool     `json:"enabled"`
	Hits      int      `json:"hits"`
	Updated   int64    `json:"updated"`
	Owner     string   `json:"owner"`
	Threshold int      `json:"threshold,omitempty"`
	Scope     string   `json:"scope,omitempty"`
}

type Incident struct {
	ID       string `json:"id"`
	TS       int64  `json:"ts"`
	User     string `json:"user"`
	Dept     string `json:"dept"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Channel  string `json:"channel"`
	Dest     string `json:"dest"`
	DataType string `json:"dataType"`
	File     string `json:"file"`
	Size     string `json:"size"`
	Matches  int    `json:"matches"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Status   string `json:"status"` // pending | processing | resolved | fp
	Policy   string `json:"policy"`
	PolicyID string `json:"policyId"`
	Handler  string `json:"handler,omitempty"`
	Closed   int64  `json:"closed,omitempty"`
}

type Endpoint struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Dept     string `json:"dept"`
	IP       string `json:"ip"`
	OS       string `json:"os"`
	OSKey    string `json:"osKey"`
	OSShort  string `json:"osShort"`
	Status   string `json:"status"` // online | offline | warning
	Agent    string `json:"agent"`
	CPU      int    `json:"cpu"`
	Mem      int    `json:"mem"`
	Disk     int    `json:"disk"`
	LastSeen int64  `json:"lastSeen"`
	Isolated bool   `json:"isolated,omitempty"`
	First    int64  `json:"first,omitempty"`
	// 终端 Agent 状态
	Enrolled      bool   `json:"enrolled,omitempty"`      // 已使用独立凭据注册
	Strict        bool   `json:"strict,omitempty"`        // 严格管控：审计 / 加密动作升级为阻断
	PolicyVersion string `json:"policyVersion,omitempty"` // Agent 已应用的策略包版本
	PolicySynced  bool   `json:"policySynced,omitempty"`  // 是否为当前最新版本
}

// AgentCred 终端 Agent 的独立凭据（仅保存密钥的 SHA-256 摘要）。
type AgentCred struct {
	Host    string `json:"host"`
	Hash    string `json:"hash"`
	Created int64  `json:"created"`
}

// Command 下发给终端 Agent 的指令，由 Agent 心跳时领取。
type Command struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	Action    string `json:"action"`
	By        string `json:"by"`
	Created   int64  `json:"created"`
	Status    string `json:"status"` // pending | delivered | done | failed
	Delivered int64  `json:"delivered,omitempty"`
	Finished  int64  `json:"finished,omitempty"`
	Result    string `json:"result,omitempty"`
}

// Fleet 终端汇总（由终端心跳计算）。
type Fleet struct {
	Licensed int `json:"licensed"`
	Deployed int `json:"deployed"`
	Online   int `json:"online"`
}

type AuditEntry struct {
	ID     string `json:"id"`
	TS     int64  `json:"ts"`
	Op     string `json:"op"`
	Role   string `json:"role"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
	IP     string `json:"ip"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

type Repo struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Icon   string         `json:"icon"`
	Total  int            `json:"total"`
	Sens   int            `json:"sens"`
	Risk   int            `json:"risk"`
	Last   int64          `json:"last"`
	Levels map[string]int `json:"levels,omitempty"` // 绝密 / 机密 / 内部 / 公开 文件数
}

type Note struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Title  string `json:"title"`
	Text   string `json:"text"`
	TS     int64  `json:"ts"`
	Unread bool   `json:"unread"`
	Href   string `json:"href"`
}

type Approval struct {
	ID         string          `json:"id"`
	TS         int64           `json:"ts"`
	User       string          `json:"user"`
	Dept       string          `json:"dept"`
	Leader     string          `json:"leader"`
	File       string          `json:"file"`
	DataType   string          `json:"dataType"`
	Level      string          `json:"level"`
	Size       string          `json:"size"`
	Channel    string          `json:"channel"`
	To         string          `json:"to"`
	Reason     string          `json:"reason"`
	Urgent     bool            `json:"urgent"`
	Deadline   int64           `json:"deadline"`
	Matches    int             `json:"matches"`
	Risk       int             `json:"risk"`
	Status     string          `json:"status"` // pending | approved | rejected | expired
	Stage      int             `json:"stage"`
	Approver   string          `json:"approver,omitempty"`
	Comment    string          `json:"comment,omitempty"`
	DecidedAt  int64           `json:"decidedAt,omitempty"`
	Conditions *ReleaseOptions `json:"conditions,omitempty"`
}

type ReleaseOptions struct {
	Encrypt    bool   `json:"encrypt"`
	Watermark  bool   `json:"watermark"`
	NoPrint    bool   `json:"noPrint"`
	ExpireDays int    `json:"expireDays"`
	MaxOpens   int    `json:"maxOpens"` // 0 表示不限
	Note       string `json:"note,omitempty"`
}

type Rule struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Cat      string         `json:"cat"`
	Type     string         `json:"type"` // regex | keyword | edm | idm | ml | file
	DataType string         `json:"dataType"`
	Cfg      map[string]any `json:"cfg"`
	Desc     string         `json:"desc"`
	Builtin  bool           `json:"builtin"`
	Enabled  bool           `json:"enabled"`
	Hits     int            `json:"hits"`
	FP       float64        `json:"fp"`
	Updated  int64          `json:"updated"`
}

type Role struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	Builtin bool   `json:"builtin"`
	Color   string `json:"color"`
}

// Ops 某模块的四类权限。
type Ops struct {
	View bool `json:"view"`
	Op   bool `json:"op"`
	Cfg  bool `json:"cfg"`
	Exp  bool `json:"exp"`
}

// Matrix 模块 → 权限。
type Matrix map[string]Ops

type Admin struct {
	Acc         string `json:"acc"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	MFA         bool   `json:"mfa"`
	IP          string `json:"ip"`
	Status      string `json:"status"` // active | locked | disabled
	Last        int64  `json:"last"`
	Created     int64  `json:"created"`
	PwdHash     string `json:"pwdHash"`
	TOTPSecret  string `json:"totpSecret"`
	Failed      int    `json:"failed"`
	LockedUntil int64  `json:"lockedUntil"`
	PwdChanged  int64  `json:"pwdChanged"`
}

// AdminView 对外展示的管理员信息（不含任何凭据）。
type AdminView struct {
	Acc     string `json:"acc"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	MFA     bool   `json:"mfa"`
	IP      string `json:"ip"`
	Status  string `json:"status"`
	Last    int64  `json:"last"`
	Created int64  `json:"created"`
}

func (a *Admin) View() AdminView {
	st := a.Status
	if st == "disabled" {
		st = "locked"
	}
	return AdminView{a.Acc, a.Name, a.Role, a.MFA, a.IP, st, a.Last, a.Created}
}

type Node struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	IP       string `json:"ip"`
	Status   string `json:"status"` // online | warning | offline
	CPU      int    `json:"cpu"`
	Mem      int    `json:"mem"`
	QPS      int    `json:"qps"`
	Latency  int    `json:"latency"`
	Up       int    `json:"up"`
	Version  string `json:"version,omitempty"`
	LastSeen int64  `json:"lastSeen"`
}

type Integration struct {
	Key      string            `json:"key"`
	Name     string            `json:"name"`
	Cat      string            `json:"cat"`
	Icon     string            `json:"icon"`
	St       string            `json:"st"` // ok | warn | off
	Info     string            `json:"info"`
	Config   map[string]string `json:"config,omitempty"`
	Delivery *Delivery         `json:"delivery,omitempty"` // 告警通道的投递统计
}

// Delivery 告警通道投递统计。
type Delivery struct {
	OK      int    `json:"ok"`
	Fail    int    `json:"fail"`
	LastAt  int64  `json:"lastAt"`
	LastErr string `json:"lastErr,omitempty"`
}

type Schedule struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tpl  string   `json:"tpl"`
	Cron string   `json:"cron"`
	To   []string `json:"to"`
	Fmt  string   `json:"fmt"`
	On   bool     `json:"on"`
	Next int64    `json:"next"`
}

type Report struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Tpl   string `json:"tpl"`
	Range string `json:"range"`
	Fmt   string `json:"fmt"`
	Size  string `json:"size"`
	TS    int64  `json:"ts"`
	By    string `json:"by"`
	From  int64  `json:"from"`
	To    int64  `json:"to"`
}

// Data 为配置类数据的内存工作集，整体以 JSONB 持久化到 PostgreSQL（documents 表）。
// 事件、检测量、审计日志与会话数据量大，存放在独立的数据表中，不在此结构内。
type Data struct {
	Version         int                   `json:"version"`
	Seq             map[string]int        `json:"seq"`
	Channels        []Channel             `json:"channels"`
	DataTypes       []DataType            `json:"dataTypes"`
	Depts           []string              `json:"depts"`
	DeptLeaders     map[string]string     `json:"deptLeaders"`
	Employees       []*Employee           `json:"employees"`
	Policies        []*Policy             `json:"policies"`
	Endpoints       []*Endpoint           `json:"endpoints"`
	Commands        []*Command            `json:"commands"`
	Repos           []*Repo               `json:"repos"`
	Notes           []*Note               `json:"notes"`
	Approvals       []*Approval           `json:"approvals"`
	Rules           []*Rule               `json:"rules"`
	Roles           []*Role               `json:"roles"`
	Perms           map[string]Matrix     `json:"perms"`
	Admins          []*Admin              `json:"admins"`
	Nodes           []*Node               `json:"nodes"`
	Integrations    []*Integration        `json:"integrations"`
	ReportSchedules []*Schedule           `json:"reportSchedules"`
	Reports         []*Report             `json:"reports"`
	Settings        map[string]any        `json:"settings"`
	Watchlist       []string              `json:"watchlist"`
	AgentCreds      map[string]*AgentCred `json:"agentCreds"`
}

// Modules 平台功能模块（与前端路由一一对应）。
var Modules = []string{"dashboard", "incidents", "ueba", "policies", "rules", "discovery", "approvals", "endpoints", "reports", "audit", "iam", "ops", "settings"}
