package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestFileStoreRoundTrip(t *testing.T) {
	f := NewFile(t.TempDir())
	ctx := context.Background()
	key := "sess-1/0000000000000007"
	data := []byte("ciphertext-blob")

	if err := f.Put(ctx, key, data); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := f.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}
	if err := f.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFileStoreListAndPrefix(t *testing.T) {
	f := NewFile(t.TempDir())
	ctx := context.Background()
	for _, k := range []string{"a/1", "a/2", "b/1"} {
		if err := f.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	keys, err := f.List(ctx, "a/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys under a/, got %v", keys)
	}
	none, err := f.List(ctx, "c/")
	if err != nil || len(none) != 0 {
		t.Fatalf("expected empty list for missing prefix, got %v err %v", none, err)
	}
}

func TestFileStoreRejectsTraversal(t *testing.T) {
	f := NewFile(t.TempDir())
	ctx := context.Background()
	for _, bad := range []string{"../escape", "a/../../x", "a\\..\\x", "a/../x", "..", "a//b"} {
		if err := f.Put(ctx, bad, []byte("x")); err == nil {
			t.Fatalf("put with key %q must fail", bad)
		}
		if _, err := f.Get(ctx, bad); err == nil {
			t.Fatalf("get with key %q must fail", bad)
		}
	}
}

func TestFileStoreMissingReturnsNotFound(t *testing.T) {
	f := NewFile(t.TempDir())
	if _, err := f.Get(context.Background(), "ghost/0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
