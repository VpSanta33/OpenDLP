package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret 生成 160 位随机 TOTP 密钥（Base32）。
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// totpAt 按 RFC 6238（HMAC-SHA1、30 秒步长、6 位）计算指定计数器的动态码。
func totpAt(secret string, counter int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}

// TOTPCode 返回 t 时刻的动态码。
func TOTPCode(secret string, t time.Time) (string, error) {
	return totpAt(secret, t.Unix()/30)
}

// VerifyTOTP 校验动态码，允许 ±1 个时间步的时钟偏差；返回匹配的计数器（用于防重放）。
func VerifyTOTP(secret, code string, t time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	c := t.Unix() / 30
	for _, d := range []int64{0, -1, 1} {
		want, err := totpAt(secret, c+d)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return c + d, true
		}
	}
	return 0, false
}

// OTPAuthURI 生成可导入身份验证器 App 的 otpauth:// URI。
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
