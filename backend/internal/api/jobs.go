package api

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"opendlp/internal/auth"
)

// Job 异步任务（导出、报表生成、规则库更新等），文件仅保存在内存中 7 天。
type Job struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Owner    string `json:"-"`
	Status   string `json:"status"` // run | done | failed
	Progress int    `json:"progress"`
	Created  int64  `json:"created"`
	Done     int64  `json:"done,omitempty"`
	Size     string `json:"size,omitempty"`
	Error    string `json:"error,omitempty"`
	Download bool   `json:"download"`
	fileName string
	mime     string
	data     []byte
}

type Jobs struct {
	mu sync.Mutex
	m  map[string]*Job
}

func NewJobs() *Jobs { return &Jobs{m: map[string]*Job{}} }

type genFn func() (fileName, mime string, data []byte, err error)

// Start 创建任务：dur 为模拟的处理耗时（用于展示进度），结束时执行 gen 生成文件。
func (j *Jobs) Start(owner, kind, name string, dur time.Duration, gen genFn) Job {
	job := &Job{ID: "J" + auth.RandomToken(9), Kind: kind, Name: name, Owner: owner, Status: "run", Created: time.Now().UnixMilli()}
	j.mu.Lock()
	j.gc()
	j.m[job.ID] = job
	snap := *job
	j.mu.Unlock()
	go func() {
		steps := 10
		for i := 1; i < steps; i++ {
			time.Sleep(dur / time.Duration(steps))
			j.mu.Lock()
			job.Progress = i * 100 / steps
			j.mu.Unlock()
		}
		fn, mime, data, err := gen()
		j.mu.Lock()
		defer j.mu.Unlock()
		job.Done = time.Now().UnixMilli()
		if err != nil {
			job.Status, job.Error = "failed", err.Error()
			return
		}
		job.Status, job.Progress = "done", 100
		job.fileName, job.mime, job.data = fn, mime, data
		job.Download = data != nil
		job.Size = humanSize(len(data))
	}()
	return snap
}

func (j *Jobs) gc() {
	cut := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	for id, x := range j.m {
		if x.Created < cut {
			delete(j.m, id)
		}
	}
}

func (j *Jobs) get(id, owner string) (Job, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	x, ok := j.m[id]
	if !ok || x.Owner != owner {
		return Job{}, false
	}
	return *x, true
}

func (j *Jobs) list(owner string) []Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := []Job{}
	for _, x := range j.m {
		if x.Owner == owner {
			out = append(out, *x)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Created > out[b].Created })
	return out
}

func (j *Jobs) remove(owner string, onlyDone bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for id, x := range j.m {
		if x.Owner == owner && (!onlyDone || x.Status != "run") {
			delete(j.m, id)
		}
	}
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// sendFile 以附件方式返回文件（文件名使用 RFC 5987 编码以支持中文）。
func sendFile(w http.ResponseWriter, name, mime string, data []byte) {
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", "attachment; filename=\"download\"; filename*=UTF-8''"+url.PathEscape(name))
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	_, _ = w.Write(data)
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request, a *Actor) {
	writeJSON(w, http.StatusOK, s.Jobs.list(a.Acc))
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request, a *Actor) {
	j, ok := s.Jobs.get(r.PathValue("id"), a.Acc)
	if !ok {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	writeJSON(w, http.StatusOK, j)
}

func (s *Server) handleJobDownload(w http.ResponseWriter, r *http.Request, a *Actor) {
	s.Jobs.mu.Lock()
	x, ok := s.Jobs.m[r.PathValue("id")]
	var name, mime string
	var data []byte
	if ok && x.Owner == a.Acc && x.Status == "done" {
		name, mime, data = x.fileName, x.mime, x.data
	}
	s.Jobs.mu.Unlock()
	if data == nil {
		writeErr(w, http.StatusNotFound, "文件不存在或尚未生成")
		return
	}
	s.audit(a, "数据导出", "下载文件「"+name+"」", true, "")
	sendFile(w, name, mime, data)
}

func (s *Server) handleJobsClear(w http.ResponseWriter, r *http.Request, a *Actor) {
	s.Jobs.remove(a.Acc, true)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (j *Jobs) count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.m)
}
