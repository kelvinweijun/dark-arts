package deaddrop

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeResolver struct {
	store   map[string][]byte
	failAll bool
	slow    time.Duration
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{store: make(map[string][]byte)}
}

func (f *fakeResolver) Publish(ctx context.Context, ref string, payload []byte) error {
	if f.failAll {
		return ErrUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(f.slow):
	}
	f.store[ref] = payload
	return nil
}

func (f *fakeResolver) Resolve(ctx context.Context, ref string) ([]byte, error) {
	if f.failAll {
		return nil, ErrUnavailable
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(f.slow):
	}
	b, ok := f.store[ref]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (f *fakeResolver) Retire(ctx context.Context, ref string) error {
	if f.failAll {
		return ErrUnavailable
	}
	delete(f.store, ref)
	return nil
}

func TestKeyOfDeterministic(t *testing.T) {
	p1 := []byte("payload-one")
	p2 := []byte("payload-two")
	if KeyOf(p1) != KeyOf(p1) {
		t.Fatal("KeyOf not deterministic")
	}
	if KeyOf(p1) == KeyOf(p2) {
		t.Fatal("distinct payloads must have distinct keys")
	}
}

func TestManagerLifecycle(t *testing.T) {
	r := newFakeResolver()
	m := NewManager(r)
	ctx := context.Background()

	ref, err := m.Publish(ctx, []byte("stage-1"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if ref != KeyOf([]byte("stage-1")) {
		t.Fatalf("ref mismatch: %s", ref)
	}

	b, err := m.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if string(b) != "stage-1" {
		t.Fatalf("payload mismatch: %q", b)
	}

	m.Quarantine(ref)
	b, err = m.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("quarantined drop must stay resolvable: %v", err)
	}
	_ = b

	if err := m.Retire(ctx, ref); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := m.Resolve(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retired drop must be unresolvable, got %v", err)
	}
	if _, err := m.Resolve(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second resolve after retire: got %v", err)
	}
}

func TestManagerResolveMissing(t *testing.T) {
	m := NewManager(newFakeResolver())
	if _, err := m.Resolve(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestManagerUnavailable(t *testing.T) {
	r := newFakeResolver()
	r.failAll = true
	m := NewManager(r)
	if _, err := m.Publish(context.Background(), []byte("x")); err == nil {
		t.Fatal("publish must fail when resolver unavailable")
	}
	if _, err := m.Resolve(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestManagerResolverFallback(t *testing.T) {
	bad := newFakeResolver()
	bad.failAll = true
	good := newFakeResolver()
	m := NewManager(bad, good)
	ctx := context.Background()

	ref, err := m.Publish(ctx, []byte("via-good"))
	if err != nil {
		t.Fatalf("publish via fallback: %v", err)
	}
	b, err := m.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve via fallback: %v", err)
	}
	if string(b) != "via-good" {
		t.Fatalf("payload mismatch: %q", b)
	}
}

func TestManagerContextCancel(t *testing.T) {
	r := newFakeResolver()
	r.slow = time.Hour
	m := NewManager(r)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := m.Publish(ctx, []byte("x"))
	if err == nil {
		t.Fatal("publish must fail on context cancel")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel must be prompt")
	}
}
