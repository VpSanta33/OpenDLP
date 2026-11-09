// Package detect 是服务端与终端 Agent 共用的敏感内容检测引擎：
// 规则匹配（RE2 正则 / 关键词 / 文件类型）、校验算法（身份证 GB 11643、银行卡 Luhn）
// 以及基于策略的处置决策。服务端用于规则测试沙箱，Agent 用于本地实时检测，保证结果一致。
package detect

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Rule 识别规则（与策略包中的规则一一对应）。
type Rule struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Cat      string         `json:"cat"`
	Type     string         `json:"type"`     // regex | keyword | file（edm / idm / ml 由检测引擎组件执行，本引擎跳过）
	DataType string         `json:"dataType"` // 命中后计入的敏感数据类型，空表示仅用于提示
	Cfg      map[string]any `json:"cfg"`
}

// Policy 防泄漏策略。
type Policy struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Channels  []string `json:"channels"`
	DataTypes []string `json:"dataTypes"`
	Action    string   `json:"action"` // block | encrypt | audit
	Severity  string   `json:"severity"`
	Threshold int      `json:"threshold"` // 单次外发命中数阈值，0 视为 1
}

// Match 一处命中。S / E 为 UTF-16 偏移（便于浏览器直接切片），OK 表示通过校验算法。
type Match struct {
	S      int    `json:"s"`
	E      int    `json:"e"`
	V      string `json:"v"`
	RuleID string `json:"ruleId"`
	OK     bool   `json:"ok"`
	bs, be int
}

var idW = []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// IDCardOK 校验 18 位身份证号的 GB 11643 校验位。
func IDCardOK(s string) bool {
	if len(s) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		sum += int(s[i]-'0') * idW[i]
	}
	return "10X98765432"[sum%11] == strings.ToUpper(s[17:])[0]
}

// LuhnOK Luhn 算法校验银行卡号。
func LuhnOK(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n := int(s[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return len(s) > 0 && sum%10 == 0
}

type compiled struct {
	Rule
	re    *regexp.Regexp
	check string
	words []string
	exts  []string
}

// Engine 预编译后的规则集与策略，可并发使用。
type Engine struct {
	rules    []compiled
	policies []Policy
}

// New 编译规则；无法编译或本引擎不支持的规则会被跳过。
func New(rules []Rule, policies []Policy) *Engine {
	e := &Engine{policies: policies}
	for _, r := range rules {
		c := compiled{Rule: r}
		switch r.Type {
		case "regex":
			src, _ := r.Cfg["src"].(string)
			re, err := regexp.Compile(src)
			if err != nil {
				continue
			}
			c.re = re
			c.check, _ = r.Cfg["check"].(string)
		case "keyword":
			for _, w := range anyStrings(r.Cfg["words"]) {
				if w != "" {
					c.words = append(c.words, w)
				}
			}
		case "file":
			for _, x := range anyStrings(r.Cfg["exts"]) {
				c.exts = append(c.exts, strings.ToLower(x))
			}
		default:
			continue
		}
		e.rules = append(e.rules, c)
	}
	return e
}

func anyStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, i := range x {
			if s, ok := i.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Scan 扫描文本，返回去重叠后的命中（最多每条规则 500 处）。
func (e *Engine) Scan(text string) []Match {
	var out []Match
	for _, r := range e.rules {
		switch {
		case r.re != nil:
			for _, loc := range r.re.FindAllStringIndex(text, 500) {
				v := text[loc[0]:loc[1]]
				ok := true
				switch r.check {
				case "idcard":
					ok = IDCardOK(v)
				case "luhn":
					ok = LuhnOK(v)
				}
				out = append(out, Match{V: v, RuleID: r.ID, OK: ok, bs: loc[0], be: loc[1]})
			}
		case len(r.words) > 0:
			for _, w := range r.words {
				for i, n := 0, 0; n < 500; n++ {
					k := strings.Index(text[i:], w)
					if k < 0 {
						break
					}
					out = append(out, Match{V: w, RuleID: r.ID, OK: true, bs: i + k, be: i + k + len(w)})
					i += k + len(w)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].bs != out[j].bs {
			return out[i].bs < out[j].bs
		}
		return out[i].be-out[i].bs > out[j].be-out[j].bs
	})
	conv := utf16Index(text)
	res := []Match{}
	end := -1
	for _, m := range out {
		if m.bs >= end {
			m.S, m.E = conv(m.bs), conv(m.be)
			res = append(res, m)
			end = m.be
		}
	}
	return res
}

// utf16Index 把字节偏移转换为 UTF-16 码元偏移。
func utf16Index(text string) func(int) int {
	idx := make([]int, len(text)+1)
	u := 0
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		for k := 0; k < size; k++ {
			idx[i+k] = u
		}
		u += len(utf16.Encode([]rune{r}))
		i += size
	}
	idx[len(text)] = u
	return func(b int) int { return idx[b] }
}

// Verdict 对一次外发的检测结论。
type Verdict struct {
	Hit      bool           `json:"hit"`
	PolicyID string         `json:"policyId"`
	Policy   string         `json:"policy"`
	Action   string         `json:"action"`   // block | encrypt | audit | allow
	Severity string         `json:"severity"` // 未命中策略时为空
	DataType string         `json:"dataType"` // 命中最多的数据类型
	Matches  int            `json:"matches"`
	Counts   map[string]int `json:"counts"`  // 数据类型 → 有效命中数
	RuleIDs  []string       `json:"ruleIds"` // 产生有效命中的规则
}

var actionRank = map[string]int{"allow": 0, "audit": 1, "encrypt": 2, "block": 3}
var sevRank = map[string]int{"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Decide 汇总命中并按策略决策：同时命中多条策略时取最严格的动作（其次取最高级别）。
// fileName 用于文件类型规则，channel 为外发渠道（email / usb / cloud / im / web / print）。
func (e *Engine) Decide(matches []Match, fileName, channel string) Verdict {
	v := Verdict{Action: "allow", Counts: map[string]int{}}
	ruleType := map[string]string{}
	for _, r := range e.rules {
		ruleType[r.ID] = r.DataType
	}
	seen := map[string]bool{}
	for _, m := range matches {
		if !m.OK {
			continue
		}
		if dt := ruleType[m.RuleID]; dt != "" {
			v.Counts[dt]++
		}
		if !seen[m.RuleID] {
			seen[m.RuleID] = true
			v.RuleIDs = append(v.RuleIDs, m.RuleID)
		}
	}
	ext := strings.ToLower(filepath.Ext(fileName))
	for _, r := range e.rules {
		for _, x := range r.exts {
			if ext != "" && ext == x && r.DataType != "" {
				v.Counts[r.DataType]++
				if !seen[r.ID] {
					seen[r.ID] = true
					v.RuleIDs = append(v.RuleIDs, r.ID)
				}
			}
		}
	}
	best := 0
	for dt, n := range v.Counts {
		v.Matches += n
		if n > best || n == best && dt < v.DataType {
			best, v.DataType = n, dt
		}
	}
	for _, p := range e.policies {
		if !contains(p.Channels, channel) {
			continue
		}
		n := 0
		for _, dt := range p.DataTypes {
			n += v.Counts[dt]
		}
		th := max(1, p.Threshold)
		if n < th {
			continue
		}
		better := actionRank[p.Action] > actionRank[v.Action] ||
			actionRank[p.Action] == actionRank[v.Action] && sevRank[p.Severity] > sevRank[v.Severity]
		if !v.Hit || better {
			v.Hit, v.PolicyID, v.Policy, v.Action, v.Severity = true, p.ID, p.Name, p.Action, p.Severity
			// 以该策略关注的数据类型作为事件的数据类型
			top := 0
			for _, dt := range p.DataTypes {
				if v.Counts[dt] > top {
					top, v.DataType = v.Counts[dt], dt
				}
			}
		}
	}
	return v
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
