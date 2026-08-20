package tasking

import (
	"encoding/json"
	"testing"
	"time"
)

func TestQueueEnqueuePendingNext(t *testing.T) {
	q := NewQueue()
	t1 := &Task{Type: "shell", Payload: []byte(`{"cmd":"whoami"}`)}
	t2 := &Task{Type: "sleep", Payload: []byte(`{"seconds":5}`)}
	if err := q.Enqueue("s1", t1); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := q.Enqueue("s1", t2); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if t1.ID == "" || t2.ID == "" {
		t.Fatal("enqueue must assign ids")
	}
	if t1.SessionID != "s1" || t1.Status != StatusQueued {
		t.Fatalf("enqueue must set session/status: %+v", t1)
	}
	p := q.Pending("s1")
	if len(p) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(p))
	}
	next := q.Next("s1")
	if next != t1 {
		t.Fatal("Next must return FIFO")
	}
	p = q.Pending("s1")
	if len(p) != 1 || p[0] != t2 {
		t.Fatalf("after Next expected [t2], got %+v", p)
	}
	if q.Next("nobody") != nil {
		t.Fatal("Next on unknown session must be nil")
	}
}

func TestQueueAck(t *testing.T) {
	q := NewQueue()
	tt := &Task{Type: "shell"}
	q.Enqueue("s1", tt)
	if !q.Ack(tt.ID) {
		t.Fatal("ack failed")
	}
	if tt.Status != StatusDelivered {
		t.Fatalf("expected delivered, got %s", tt.Status)
	}
	if q.Ack("nope") {
		t.Fatal("ack of unknown id must fail")
	}
}

func TestQueueResultUpdatesStatus(t *testing.T) {
	q := NewQueue()
	tt := &Task{Type: "shell"}
	q.Enqueue("s1", tt)
	q.Result(&Result{TaskID: tt.ID, SessionID: "s1", Output: []byte("ok"), CompletedAt: time.Now().UTC()})
	got, _ := q.Task(tt.ID)
	if got.Status != StatusComplete {
		t.Fatalf("expected complete, got %s", got.Status)
	}
	rs := q.Results()
	if len(rs) != 1 || string(rs[0].Output) != "ok" {
		t.Fatalf("result not stored: %+v", rs)
	}

	q.Result(&Result{TaskID: tt.ID, SessionID: "s1", Error: "boom"})
	got, _ = q.Task(tt.ID)
	if got.Status != StatusError {
		t.Fatalf("expected error, got %s", got.Status)
	}
}

func TestQueueDropSessionExpires(t *testing.T) {
	q := NewQueue()
	tt := &Task{Type: "shell"}
	q.Enqueue("s1", tt)
	q.DropSession("s1")
	if tt.Status != StatusExpired {
		t.Fatalf("expected expired, got %s", tt.Status)
	}
	if len(q.Pending("s1")) != 0 {
		t.Fatal("pending must be cleared")
	}
}

func TestQueueTaskJSONWithStatus(t *testing.T) {
	in := Task{ID: "t-1", SessionID: "s1", Type: "exec", Status: StatusQueued}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Task
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SessionID != "s1" || out.Status != StatusQueued {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}
