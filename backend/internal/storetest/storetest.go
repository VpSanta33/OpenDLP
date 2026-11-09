// Package storetest 提供基于真实 PostgreSQL 的测试存储（每个测试独立 schema）。
package storetest

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"opendlp/internal/store"
)

// OpenTest 为测试创建独立 schema 并打开存储，测试结束后删除 schema。
// 需要环境变量 OPENDLP_TEST_DATABASE_URL，未设置时跳过测试。
func Open(t testing.TB, seed func() *store.Data) *store.Store {
	t.Helper()
	base := os.Getenv("OPENDLP_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("未设置 OPENDLP_TEST_DATABASE_URL，跳过数据库测试")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("t_%d_%d", time.Now().UnixNano(), rand.IntN(1e6))
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	loc, _ := time.LoadLocation("Asia/Shanghai")
	st, _, err := store.Open(ctx, u.String(), loc, seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.Close()
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			c.Close(context.Background())
		}
	})
	return st
}
