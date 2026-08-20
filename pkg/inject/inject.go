package inject

type Result struct {
	Mode     string `json:"mode"`
	Bytes    int    `json:"bytes"`
	PID      uint32 `json:"pid,omitempty"`
	ExitCode uint32 `json:"exit_code,omitempty"`
}
