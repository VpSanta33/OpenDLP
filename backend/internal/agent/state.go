package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// State 持久化的注册状态（文件权限 0600）。
type State struct {
	Server  string `json:"server"`
	Host    string `json:"host"`
	AgentID string `json:"agentId"`
	Secret  string `json:"secret"`
}

// writeFileAtomic 先写临时文件再重命名，避免断电导致文件损坏。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadJSON(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

// Queue 离线上报队列（JSON Lines），网络恢复后按批补报。
type Queue struct {
	mu   sync.Mutex
	path string
	max  int
}

func NewQueue(path string) *Queue { return &Queue{path: path, max: 20000} }

// Push 追加检测结果；超过上限时丢弃最旧的记录。
func (q *Queue) Push(items []Detection) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	all, err := q.readLocked()
	if err != nil {
		return err
	}
	all = append(all, items...)
	if len(all) > q.max {
		all = all[len(all)-q.max:]
	}
	return q.writeLocked(all)
}

// Len 队列长度。
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	all, _ := q.readLocked()
	return len(all)
}

// Flush 按批取出并发送，send 失败时保留剩余记录。
func (q *Queue) Flush(batch int, send func([]Detection) error) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	all, err := q.readLocked()
	if err != nil || len(all) == 0 {
		return 0, err
	}
	sent := 0
	for len(all) > 0 {
		n := min(batch, len(all))
		if err := send(all[:n]); err != nil {
			_ = q.writeLocked(all)
			return sent, err
		}
		all, sent = all[n:], sent+n
	}
	return sent, q.writeLocked(nil)
}

func (q *Queue) readLocked() ([]Detection, error) {
	f, err := os.Open(q.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Detection
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var d Detection
		if json.Unmarshal(sc.Bytes(), &d) == nil {
			out = append(out, d)
		}
	}
	return out, sc.Err()
}

func (q *Queue) writeLocked(all []Detection) error {
	if len(all) == 0 {
		err := os.Remove(q.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var buf []byte
	for _, d := range all {
		b, _ := json.Marshal(d)
		buf = append(append(buf, b...), '\n')
	}
	return writeFileAtomic(q.path, buf, 0o600)
}
