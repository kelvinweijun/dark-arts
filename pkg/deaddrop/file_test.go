package deaddrop

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestFileResolverRoundTrip(t *testing.T) {
	f := NewFile(t.TempDir())
	ctx := context.Background()
	payload := bytes.Repeat([]byte{0xde, 0xad}, 1024)

	ref := KeyOf(payload)
	if err := f.Publish(ctx, ref, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := f.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}

	if err := f.Retire(ctx, ref); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := f.Resolve(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after retire, got %v", err)
	}
}

func TestFileResolverMissingAndIdempotentRetire(t *testing.T) {
	f := NewFile(t.TempDir())
	ctx := context.Background()
	if _, err := f.Resolve(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := f.Retire(ctx, "ghost"); err != nil {
		t.Fatalf("retire of missing drop must be idempotent: %v", err)
	}
}
