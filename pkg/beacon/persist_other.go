//go:build !windows

package beacon

import "darkarts/pkg/tasking"

func (e *Executor) runPersist(payload []byte, res *tasking.Result) {
	res.Error = "beacon: persistence is only supported on windows"
}

func (e *Executor) runUnpersist(payload []byte, res *tasking.Result) {
	res.Error = "beacon: persistence is only supported on windows"
}
