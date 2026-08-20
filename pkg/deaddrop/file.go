package deaddrop

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
)

type File struct {
	dir string
	mu  sync.Mutex
}

func NewFile(dir string) *File {
	return &File{dir: dir}
}

func (f *File) path(ref string) string {
	return filepath.Join(f.dir, ref)
}

func (f *File) Publish(ctx context.Context, ref string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return os.WriteFile(f.path(ref), []byte(base64.StdEncoding.EncodeToString(payload)), 0o600)
}

func (f *File) Resolve(ctx context.Context, ref string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path(ref))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(b))
}

func (f *File) Retire(ctx context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := os.Remove(f.path(ref))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
