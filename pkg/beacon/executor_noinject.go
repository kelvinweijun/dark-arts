//go:build !inject

package beacon

import "dark-arts/pkg/tasking"

func (e *Executor) runInject(payload []byte, res *tasking.Result) {
	res.Error = "beacon: inject support not compiled in"
}

func (e *Executor) runDll(payload []byte, res *tasking.Result) {
	res.Error = "beacon: reflective dll support not compiled in"
}
