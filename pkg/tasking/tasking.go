package tasking

import "time"

type Status string

const (
	StatusQueued    Status = "queued"
	StatusDelivered Status = "delivered"
	StatusRunning   Status = "running"
	StatusComplete  Status = "complete"
	StatusError     Status = "error"
	StatusExpired   Status = "expired"
)

type Task struct {
	ID        string    `json:"id"`
	OpID      string    `json:"op_id"`
	SessionID string    `json:"session_id"`
	Type      string    `json:"type"`
	Payload   []byte    `json:"payload,omitempty"`
	SignedBy  string    `json:"signed_by,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	Status    Status    `json:"status,omitempty"`
}

type Result struct {
	TaskID      string    `json:"task_id"`
	SessionID   string    `json:"session_id"`
	Output      []byte    `json:"output,omitempty"`
	Error       string    `json:"error,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}
