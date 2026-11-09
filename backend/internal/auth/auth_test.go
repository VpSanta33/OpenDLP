package auth

import (
	"testing"
	"time"
)

// RFC 6238 附录 B 测试向量（SHA1，密钥 "12345678901234567890"），取后 6 位。
func TestTOTPVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		got, err := TOTPCode(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("T=%d: got %s, want %s (err %v)", ts, got, want, err)
		}
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	s := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	prev, _ := TOTPCode(s, now.Add(-30*time.Second))
	if _, ok := VerifyTOTP(s, prev, now); !ok {
		t.Fatal("上一个时间步的动态码应在容差窗口内")
	}
	old, _ := TOTPCode(s, now.Add(-90*time.Second))
	if _, ok := VerifyTOTP(s, old, now); ok {
		t.Fatal("3 个时间步之前的动态码不应通过")
	}
	if _, ok := VerifyTOTP(s, "12345", now); ok {
		t.Fatal("位数不足的动态码不应通过")
	}
}

func TestPassword(t *testing.T) {
	h, err := HashPassword("Correct-Horse-9")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "Correct-Horse-9") || CheckPassword(h, "correct-horse-9") {
		t.Fatal("口令校验结果错误")
	}
	if CheckPassword("plain$text", "x") || CheckPassword("pbkdf2-sha256$10$AA$AA", "x") {
		t.Fatal("格式错误或迭代次数过低的哈希应校验失败")
	}
	if CheckComplexity("short1!A") == nil || CheckComplexity("alllowercase123!") == nil || CheckComplexity("Good-Pass-2026") != nil {
		t.Fatal("复杂度校验结果错误")
	}
}

func TestSessionsAndOTPReplay(t *testing.T) {
	m := NewManager(nil, time.Minute, time.Hour)
	tok, err := m.Create("admin", "super", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := m.Get(tok); !ok || s.Acc != "admin" {
		t.Fatal("会话应有效")
	}
	m.RevokeAccount("admin")
	if _, ok := m.Get(tok); ok {
		t.Fatal("吊销后会话应失效")
	}
	if !m.MarkOTPUsed("admin", 42) || m.MarkOTPUsed("admin", 42) {
		t.Fatal("同一动态码只能使用一次")
	}
	ch := m.NewChallenge("admin")
	for i := 0; i < 5; i++ {
		if _, ok := m.UseChallenge(ch); !ok {
			t.Fatalf("第 %d 次尝试应允许", i+1)
		}
	}
	if _, ok := m.UseChallenge(ch); ok {
		t.Fatal("超过 5 次尝试后挑战应作废")
	}
}
