//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func main() {
	out := filepath.Join(os.Getenv("TEMP"), "uac-ieinstal.out")
	marker := filepath.Join(os.Getenv("TEMP"), "uac-ieinstal.marker")
	cmd := exec.Command("cmd", "/c", "whoami /groups")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	data, err := cmd.CombinedOutput()
	if err != nil {
		os.WriteFile(marker, []byte("err: "+err.Error()), 0644)
		return
	}
	os.WriteFile(out, data, 0644)
	os.WriteFile(marker, []byte("ran"), 0644)
}