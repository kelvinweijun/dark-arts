package store

import (
	"context"
	"errors"
	"regexp"
)

var ErrNotFound = errors.New("store: not found")

var keyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)

func ValidateKey(key string) bool {
	return keyRe.MatchString(key)
}

type Store interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}
