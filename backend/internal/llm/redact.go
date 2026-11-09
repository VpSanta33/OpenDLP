package llm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Redactor 发送给模型前把个人与资产标识替换为代号，模型回复后在本地还原。
// 代号在同一次分析 / 会话内保持稳定，模型可以用代号继续调用工具。
type Redactor struct {
	Enabled bool
	mu      sync.Mutex
	fwd     map[string]string // 原值 → 代号
	rev     map[string]string // 代号 → 原值
	seq     map[string]int
	dict    map[string]string // 已知实体（原值 → 类别），出现在文本中时才分配代号
}

func NewRedactor(enabled bool) *Redactor {
	return &Redactor{Enabled: enabled, fwd: map[string]string{}, rev: map[string]string{}, seq: map[string]int{}, dict: map[string]string{}}
}

// Known 登记已知实体（员工姓名、主机名等），自由文本中出现时自动脱敏。
func (r *Redactor) Known(kind string, values ...string) {
	if !r.Enabled {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range values {
		if v = strings.TrimSpace(v); len([]rune(v)) >= 2 {
			r.dict[v] = kind
		}
	}
}

// 代号前缀：使用模型不易与普通文本混淆的形式。
var kindPrefix = map[string]string{"user": "用户", "host": "终端", "ip": "IP-", "file": "文件", "dest": "目的地", "email": "邮箱"}

// Mask 登记一个实体并返回其代号（未开启脱敏时原样返回）。
func (r *Redactor) Mask(kind, v string) string {
	v = strings.TrimSpace(v)
	if !r.Enabled || v == "" || v == "-" {
		return v
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.fwd[v]; ok {
		return t
	}
	r.seq[kind]++
	t := fmt.Sprintf("[%s%s]", kindPrefix[kind], code(r.seq[kind]))
	r.fwd[v], r.rev[t] = t, v
	return t
}

// code 1 → A，26 → Z，27 → A1 …
func code(n int) string {
	n--
	s := string(rune('A' + n%26))
	if n >= 26 {
		s += fmt.Sprint(n / 26)
	}
	return s
}

var (
	reIDCard = regexp.MustCompile(`\b\d{17}[\dXx]\b`)
	rePhone  = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// Text 对自由文本脱敏：已登记的实体替换为代号，并兜底遮盖身份证号、手机号、邮箱与 IP。
func (r *Redactor) Text(s string) string {
	if !r.Enabled || s == "" {
		return s
	}
	r.mu.Lock()
	var hit [][2]string
	for v, kind := range r.dict {
		if _, ok := r.fwd[v]; !ok && strings.Contains(s, v) {
			hit = append(hit, [2]string{kind, v})
		}
	}
	r.mu.Unlock()
	sort.Slice(hit, func(i, j int) bool { return strings.Index(s, hit[i][1]) < strings.Index(s, hit[j][1]) })
	for _, h := range hit {
		r.Mask(h[0], h[1])
	}
	r.mu.Lock()
	keys := make([]string, 0, len(r.fwd))
	for k := range r.fwd {
		keys = append(keys, k)
	}
	r.mu.Unlock()
	// 先替换长的，避免「张伟」误替换「张伟华」中的片段
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, r.fwd[k])
	}
	s = reIDCard.ReplaceAllString(s, "[身份证号]")
	s = rePhone.ReplaceAllString(s, "[手机号]")
	s = reEmail.ReplaceAllStringFunc(s, func(v string) string { return r.Mask("email", v) })
	s = reIPv4.ReplaceAllStringFunc(s, func(v string) string { return r.Mask("ip", v) })
	return s
}

// Restore 把模型输出中的代号还原为原值。
func (r *Redactor) Restore(s string) string {
	if !r.Enabled || s == "" {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	toks := make([]string, 0, len(r.rev))
	for t := range r.rev {
		toks = append(toks, t)
	}
	// 先还原长代号，避免「用户A」误替换「用户A1」
	sort.Slice(toks, func(i, j int) bool { return len(toks[i]) > len(toks[j]) })
	for _, t := range toks {
		s = strings.ReplaceAll(s, t, r.rev[t])
	}
	for _, t := range toks { // 模型有时会省略方括号
		s = strings.ReplaceAll(s, strings.Trim(t, "[]"), r.rev[t])
	}
	return s
}

// Lookup 工具参数中的代号 → 原值（不是代号时原样返回）。
func (r *Redactor) Lookup(s string) string {
	s = strings.TrimSpace(s)
	if !r.Enabled {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.rev[s]; ok {
		return v
	}
	if v, ok := r.rev["["+strings.Trim(s, "[]")+"]"]; ok {
		return v
	}
	return s
}

// Mapping 当前会话的代号表（代号 → 原值），用于多轮对话保持代号一致。
func (r *Redactor) Mapping() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.rev))
	for k, v := range r.rev {
		out[k] = v
	}
	return out
}
