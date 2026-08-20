package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

func TestMinIOStoreIntegration(t *testing.T) {
	endpoint := os.Getenv("DARKARTS_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("DARKARTS_S3_ENDPOINT not set; requires running MinIO (docker lab)")
	}
	access := os.Getenv("DARKARTS_S3_ACCESS_KEY")
	secret := os.Getenv("DARKARTS_S3_SECRET_KEY")
	bucket := os.Getenv("DARKARTS_S3_BUCKET")
	if access == "" || secret == "" || bucket == "" {
		t.Fatal("DARKARTS_S3_ACCESS_KEY, DARKARTS_S3_SECRET_KEY, DARKARTS_S3_BUCKET required")
	}

	m, err := NewMinIO(endpoint, access, secret, bucket, false)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()
	if err := m.EnsureBucket(ctx); err != nil {
		t.Fatalf("bucket: %v", err)
	}
	key := "test-session/0000000000000099"
	data := bytes.Repeat([]byte("blob"), 100)
	if err := m.Put(ctx, key, data); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := m.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}
	keys, err := m.List(ctx, "test-session/")
	if err != nil || len(keys) != 1 {
		t.Fatalf("list: %v %v", keys, err)
	}
	if err := m.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
