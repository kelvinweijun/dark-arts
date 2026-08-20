package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	root string
}

func NewFile(root string) *File {
	return &File{root: root}
}

func (f *File) Root() string {
	return f.root
}

func (f *File) path(key string) (string, error) {
	if !ValidateKey(key) {
		return "", errors.New("store: invalid key")
	}
	return filepath.Join(f.root, filepath.FromSlash(key)), nil
}

func (f *File) Put(ctx context.Context, key string, data []byte) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func (f *File) Get(ctx context.Context, key string) ([]byte, error) {
	p, err := f.path(key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

func (f *File) Delete(ctx context.Context, key string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (f *File) List(ctx context.Context, prefix string) ([]string, error) {
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed != "" && !ValidateKey(trimmed) {
		return nil, errors.New("store: invalid prefix")
	}
	base := filepath.Join(f.root, filepath.FromSlash(trimmed))
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var keys []string
	for _, e := range entries {
		if !e.IsDir() {
			keys = append(keys, prefix+e.Name())
		}
	}
	return keys, nil
}
