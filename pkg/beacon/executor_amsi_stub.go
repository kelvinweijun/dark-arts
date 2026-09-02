//go:build !windows || !amd64

package beacon

import "dark-arts/pkg/tasking"

func (e *Executor) runAMSI(payload []byte, res *tasking.Result) {
	res.Error = "beacon: amsi support requires Windows AMD64"
}

func (e *Executor) runETW(payload []byte, res *tasking.Result) {
	res.Error = "beacon: etw support requires Windows AMD64"
}
