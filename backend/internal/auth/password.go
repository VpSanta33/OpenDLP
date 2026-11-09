// Package auth 提供口令哈希、TOTP 双因素认证与会话管理。
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// PBKDF2-HMAC-SHA256 迭代次数（OWASP 2023 建议 ≥ 600,000；此处兼顾演示环境启动速度）。
const pbkdf2Iter = 210_000

var b64 = base64.RawStdEncoding

// HashPassword 生成格式为 pbkdf2-sha256$迭代次数$盐$摘要 的口令哈希。
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// CheckPassword 常量时间比较口令。
func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 10_000 {
		return false
	}
	salt, err1 := b64.DecodeString(parts[2])
	want, err2 := b64.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// CheckComplexity 口令复杂度：≥ 12 位，且包含大写、小写、数字、符号。
func CheckComplexity(pw string) error {
	if len([]rune(pw)) < 12 {
		return fmt.Errorf("口令长度至少 12 位")
	}
	var up, lo, di, sy bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			up = true
		case unicode.IsLower(r):
			lo = true
		case unicode.IsDigit(r):
			di = true
		default:
			sy = true
		}
	}
	if !(up && lo && di && sy) {
		return fmt.Errorf("口令需同时包含大写字母、小写字母、数字与符号")
	}
	return nil
}

// RandomToken 生成 n 字节随机数的 URL 安全编码。
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // 系统随机源不可用时无法安全运行
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
