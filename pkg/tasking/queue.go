package tasking

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type Queue struct {
	mu      sync.Mutex
	pending map[string][]*Task
	all     map[string]*Task
	results []*Result
}

func NewQueue() *Queue {
	return &Queue{
		pending: make(map[string][]*Task),
		all:     make(map[string]*Task),
	}
}

func newTaskID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("t-%s", hex.EncodeToString(b))
}

func (q *Queue) Enqueue(sid string, t *Task) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if t == nil {
		return fmt.Errorf("tasking: nil task")
	}
	if t.ID == "" {
		t.ID = newTaskID()
	}
	if t.SessionID == "" {
		t.SessionID = sid
	}
	if t.IssuedAt.IsZero() {
		t.IssuedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = StatusQueued
	}
	q.all[t.ID] = t
	q.pending[sid] = append(q.pending[sid], t)
	return nil
}

func (q *Queue) Pending(sid string) []*Task {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*Task, 0, len(q.pending[sid]))
	for _, t := range q.pending[sid] {
		out = append(out, t)
	}
	return out
}

func (q *Queue) Next(sid string) *Task {
	q.mu.Lock()
	defer q.mu.Unlock()
	list := q.pending[sid]
	if len(list) == 0 {
		return nil
	}
	t := list[0]
	q.pending[sid] = list[1:]
	return t
}

func (q *Queue) Ack(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.all[id]
	if !ok {
		return false
	}
	t.Status = StatusDelivered
	return true
}

func (q *Queue) Result(r *Result) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if r.CompletedAt.IsZero() {
		r.CompletedAt = time.Now().UTC()
	}
	q.results = append(q.results, r)
	if t, ok := q.all[r.TaskID]; ok {
		if r.Error != "" {
			t.Status = StatusError
		} else {
			t.Status = StatusComplete
		}
	}
}

func (q *Queue) Task(id string) (*Task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.all[id]
	return t, ok
}

func (q *Queue) Tasks() []*Task {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*Task, 0, len(q.all))
	for _, t := range q.all {
		out = append(out, t)
	}
	return out
}

func (q *Queue) Results() []*Result {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*Result, 0, len(q.results))
	for _, r := range q.results {
		out = append(out, r)
	}
	return out
}

func (q *Queue) DropSession(sid string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, t := range q.pending[sid] {
		t.Status = StatusExpired
	}
	delete(q.pending, sid)
}
