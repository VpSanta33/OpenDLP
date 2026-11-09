package detect

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// 提取限制：避免超大文件拖垮终端。
const (
	MaxFileBytes = 50 << 20 // 超过该大小的文件只按文件类型规则判断
	MaxTextBytes = 8 << 20  // 单个文件提取文本上限
	maxZipEntry  = 200      // 压缩包最多检查的条目数
)

var ErrTooLarge = errors.New("文件超过内容检测上限")

var textExts = map[string]bool{
	".txt": true, ".csv": true, ".tsv": true, ".md": true, ".json": true, ".xml": true, ".html": true, ".htm": true,
	".log": true, ".sql": true, ".yaml": true, ".yml": true, ".ini": true, ".conf": true, ".cfg": true, ".properties": true,
	".env": true, ".pem": true, ".key": true, ".go": true, ".java": true, ".py": true, ".js": true, ".ts": true, ".c": true,
	".h": true, ".cpp": true, ".hpp": true, ".cs": true, ".php": true, ".rb": true, ".rs": true, ".kt": true, ".swift": true,
	".sh": true, ".ps1": true, ".bat": true, ".vue": true, ".jsx": true, ".tsx": true,
}

// ExtractFile 读取文件并提取可检测的文本。
func ExtractFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Size() > MaxFileBytes {
		return "", ErrTooLarge
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Extract(filepath.Base(path), b), nil
}

// Extract 根据文件名与内容提取文本：纯文本直接读取，Office Open XML 解析正文，
// zip 压缩包逐项提取，其余二进制文件提取其中可读的 UTF-8 片段。
func Extract(name string, b []byte) string { return extract(name, b, 0) }

func extract(name string, b []byte, depth int) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case textExts[ext]:
		return limit(toUTF8(b))
	case ext == ".docx" || ext == ".xlsx" || ext == ".pptx":
		if t, ok := officeText(b, ext); ok {
			return limit(t)
		}
	case (ext == ".zip" || ext == ".jar") && depth == 0: // 只展开一层，防止嵌套压缩包炸弹
		if t, ok := zipText(b, depth); ok {
			return limit(t)
		}
	}
	if utf8.Valid(b) && !bytes.Contains(b[:min(len(b), 8000)], []byte{0}) {
		return limit(string(b))
	}
	return limit(printable(b))
}

func limit(s string) string {
	if len(s) <= MaxTextBytes {
		return s
	}
	s = s[:MaxTextBytes]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// toUTF8 处理 UTF-8 BOM；非 UTF-8 文本退化为可读片段提取。
func toUTF8(b []byte) string {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if utf8.Valid(b) {
		return string(b)
	}
	return printable(b)
}

// printable 从二进制内容中提取长度 ≥ 4 的可读 UTF-8 片段。
func printable(b []byte) string {
	var sb strings.Builder
	var run []rune
	flush := func() {
		if len(run) >= 4 {
			sb.WriteString(string(run))
			sb.WriteByte('\n')
		}
		run = run[:0]
	}
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r == utf8.RuneError || r < 0x20 && r != '\t' {
			flush()
			continue
		}
		run = append(run, r)
		if sb.Len() > MaxTextBytes {
			break
		}
	}
	flush()
	return sb.String()
}

var xmlTag = regexp.MustCompile(`<[^>]+>`)

// xmlText 去除 XML 标签；段落 / 单元格边界替换为换行以免相邻数字被拼接成误报。
func xmlText(b []byte) string {
	s := string(b)
	s = strings.NewReplacer("</w:p>", "\n", "</a:p>", "\n", "</c>", "\n", "</si>", "\n", "</t>", " ", "<w:tab/>", " ").Replace(s)
	s = xmlTag.ReplaceAllString(s, "")
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(s)
}

func officeText(b []byte, ext string) (string, bool) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return "", false
	}
	var names []string
	for _, f := range zr.File {
		n := f.Name
		switch ext {
		case ".docx":
			if n == "word/document.xml" || strings.HasPrefix(n, "word/header") || strings.HasPrefix(n, "word/footer") {
				names = append(names, n)
			}
		case ".xlsx":
			if n == "xl/sharedStrings.xml" || strings.HasPrefix(n, "xl/worksheets/sheet") {
				names = append(names, n)
			}
		case ".pptx":
			if strings.HasPrefix(n, "ppt/slides/slide") {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, f := range zr.File {
		if !containsStr(names, f.Name) || f.UncompressedSize64 > MaxTextBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, MaxTextBytes))
		rc.Close()
		sb.WriteString(xmlText(data))
		sb.WriteByte('\n')
	}
	return sb.String(), len(names) > 0
}

func zipText(b []byte, depth int) (string, bool) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return "", false
	}
	var sb strings.Builder
	for i, f := range zr.File {
		if i >= maxZipEntry || sb.Len() > MaxTextBytes {
			break
		}
		if f.FileInfo().IsDir() || f.UncompressedSize64 > MaxTextBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, MaxTextBytes))
		rc.Close()
		sb.WriteString(f.Name)
		sb.WriteByte('\n')
		sb.WriteString(extract(f.Name, data, depth+1)) // 内部的 docx / 文本同样解析
		sb.WriteByte('\n')
	}
	return sb.String(), true
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
