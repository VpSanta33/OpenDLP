package detect

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

var testRules = []Rule{
	{ID: "R-101", Type: "regex", DataType: "idcard", Cfg: map[string]any{"src": `\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`, "check": "idcard"}},
	{ID: "R-102", Type: "regex", DataType: "phone", Cfg: map[string]any{"src": `\b1[3-9]\d{9}\b`}},
	{ID: "R-107", Type: "regex", DataType: "bankcard", Cfg: map[string]any{"src": `\b(?:62|4\d|5[1-5])\d{14,17}\b`, "check": "luhn"}},
	{ID: "R-114", Type: "keyword", DataType: "contract", Cfg: map[string]any{"words": []any{"机密", "未经授权不得外传"}}},
	{ID: "R-120", Type: "file", DataType: "design", Cfg: map[string]any{"exts": []any{".dwg", ".psd"}}},
	{ID: "R-bad", Type: "regex", Cfg: map[string]any{"src": "(?<!x)"}}, // 非 RE2，应被跳过
	{ID: "R-edm", Type: "edm", DataType: "customer"},                   // 本引擎不执行
}

var testPolicies = []Policy{
	{ID: "P-1", Name: "身份证号外发拦截", Channels: []string{"usb", "email"}, DataTypes: []string{"idcard"}, Action: "block", Severity: "critical", Threshold: 2},
	{ID: "P-2", Name: "个人信息审计", Channels: []string{"usb", "email", "cloud"}, DataTypes: []string{"idcard", "phone"}, Action: "audit", Severity: "medium"},
	{ID: "P-3", Name: "图纸加密", Channels: []string{"usb"}, DataTypes: []string{"design"}, Action: "encrypt", Severity: "high"},
}

func TestValidators(t *testing.T) {
	if !IDCardOK("110105199003072311") || IDCardOK("110105199003072310") || IDCardOK("11010519900307231") {
		t.Fatal("身份证校验错误")
	}
	if !LuhnOK("6222020200112348848") || LuhnOK("6222020200112348849") || LuhnOK("") {
		t.Fatal("Luhn 校验错误")
	}
}

func TestScanAndDecide(t *testing.T) {
	e := New(testRules, testPolicies)
	text := "名单：110105199003072311、11010519900307231X（错误），手机 13912340912，本文件机密"
	ms := e.Scan(text)
	for _, m := range ms {
		if string([]rune(text)[m.S:m.E]) != m.V {
			t.Fatalf("UTF-16 偏移错误：%q", m.V)
		}
	}
	// 1 个有效身份证：未达到 P-1 阈值 2，应命中 P-2（审计）
	v := e.Decide(ms, "名单.txt", "usb")
	if !v.Hit || v.PolicyID != "P-2" || v.Action != "audit" || v.Counts["idcard"] != 1 || v.Counts["phone"] != 1 {
		t.Fatalf("决策错误：%+v", v)
	}
	// 2 个有效身份证：命中 P-1 阻断（比审计严格）
	v = e.Decide(e.Scan(text+" 110105199003072311"), "名单.txt", "usb")
	if v.PolicyID != "P-1" || v.Action != "block" || v.DataType != "idcard" {
		t.Fatalf("应命中阻断策略：%+v", v)
	}
	// 渠道不在策略范围内：不命中
	if v := e.Decide(ms, "名单.txt", "print"); v.Hit || v.Action != "allow" {
		t.Fatalf("打印渠道不应命中：%+v", v)
	}
	// 文件类型规则
	if v := e.Decide(nil, "结构图.DWG", "usb"); v.PolicyID != "P-3" || v.Action != "encrypt" {
		t.Fatalf("文件类型规则未生效：%+v", v)
	}
}

func makeZip(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(c))
	}
	zw.Close()
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	docx := makeZip(t, map[string]string{"word/document.xml": `<w:document><w:body><w:p><w:r><w:t>身份证</w:t></w:r></w:p><w:p><w:r><w:t>110105199003072311</w:t></w:r></w:p><w:p><w:t>13912340912</w:t></w:p></w:body></w:document>`})
	got := Extract("名单.docx", docx)
	if !strings.Contains(got, "110105199003072311") || strings.Contains(got, "11010519900307231113912340912") {
		t.Fatalf("docx 提取错误：%q", got)
	}
	xlsx := makeZip(t, map[string]string{"xl/sharedStrings.xml": `<sst><si><t>6222020200112348848</t></si><si><t>李四</t></si></sst>`})
	if !strings.Contains(Extract("a.xlsx", xlsx), "6222020200112348848") {
		t.Fatal("xlsx 提取错误")
	}
	nested := makeZip(t, map[string]string{"inner/a.txt": "机密资料", "inner/b.docx": string(docx), "deep.zip": string(makeZip(t, map[string]string{"x.txt": "13800000000"}))})
	z := Extract("pkg.zip", nested)
	if !strings.Contains(z, "机密资料") || !strings.Contains(z, "110105199003072311") {
		t.Fatalf("zip 提取错误：%q", z)
	}
	bin := append([]byte{0, 1, 2, 3, 0xff}, []byte("hidden 13912340912 text")...)
	if !strings.Contains(Extract("a.bin", bin), "13912340912") {
		t.Fatal("二进制可读片段提取错误")
	}
	gbk := []byte{0xc9, 0xed, 0xb7, 0xdd, 0xd6, 0xa4} // 非 UTF-8 文本不应崩溃
	_ = Extract("a.txt", gbk)
}
