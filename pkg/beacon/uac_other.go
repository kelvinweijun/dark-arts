//go:build !windows

package beacon

import "darkarts/pkg/tasking"

func (e *Executor) runUac(payload []byte, res *tasking.Result) {
	res.Error = "beacon: uac bypass is only supported on windows"
}
