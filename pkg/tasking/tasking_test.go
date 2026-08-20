package tasking

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTaskJSONRoundTrip(t *testing.T) {
	in := Task{
		ID:       "task-1",
		OpID:     "op-7",
		Type:     "recon",
		Payload:  []byte(`{"cmd":"hostname"}`),
		SignedBy: "operator-a",
		IssuedAt: time.Now().UTC().Truncate(time.Second),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Task
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ID != in.ID || out.OpID != in.OpID || out.Type != in.Type || out.SignedBy != in.SignedBy {
		t.Fatalf("round trip mismatch: %+v vs %+v", in, out)
	}
	if string(out.Payload) != string(in.Payload) {
		t.Fatalf("payload mismatch: %q vs %q", out.Payload, in.Payload)
	}
	if !out.IssuedAt.Equal(in.IssuedAt) {
		t.Fatalf("time mismatch: %v vs %v", out.IssuedAt, in.IssuedAt)
	}
}
