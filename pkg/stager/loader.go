package stager

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

var ErrUnsupported = errors.New("stager: loader not supported on this platform")

type Loader interface {
	Load(ctx context.Context, kind string, blob []byte) error
}

type MemoryLoader struct {
	Kind string
	Blob []byte
}

func (l *MemoryLoader) Load(ctx context.Context, kind string, blob []byte) error {
	if kind == "" {
		return errors.New("stager: stage kind required")
	}
	cp := make([]byte, len(blob))
	copy(cp, blob)
	l.Kind = kind
	l.Blob = cp
	return nil
}

type ChildLoader struct {
	Stdout io.Writer
	Stderr io.Writer
	Args   []string
}

func (l *ChildLoader) Load(ctx context.Context, kind string, blob []byte) error {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	f, err := os.CreateTemp("", "darkarts-stage-*"+ext)
	if err != nil {
		return err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	if err := os.WriteFile(path, blob, 0o700); err != nil {
		os.Remove(path)
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, path, l.Args...)
	if l.Stdout != nil {
		cmd.Stdout = l.Stdout
	}
	if l.Stderr != nil {
		cmd.Stderr = l.Stderr
	}
	err = cmd.Run()
	os.Remove(path)
	return err
}
