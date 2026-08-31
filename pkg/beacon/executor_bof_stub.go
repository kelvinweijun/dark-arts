//go:build !windows || !amd64

package beacon

import "dark-arts/pkg/tasking"

func (e *Executor) runBOF(payload []byte, res *tasking.Result) {
	res.Error = "beacon: bof support requires Windows AMD64"
}
