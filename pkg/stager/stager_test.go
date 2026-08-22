package stager

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/deaddrop"
	"dark-arts/pkg/store"
)

func newEnv(t *testing.T) (*crypto.OperatorKeys, deaddrop.Resolver, store.Store, context.Context) {
	t.Helper()
	op, err := crypto.NewOperatorKeys()
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	dd := deaddrop.NewFile(t.TempDir())
	st := store.NewFile(t.TempDir())
	return op, dd, st, context.Background()
}

func TestPackFetchRoundTrip(t *testing.T) {
	op, dd, st, ctx := newEnv(t)
	blob := bytes.Repeat([]byte("stage-one-beacon-blob"), 100)

	m, ref, err := PackAndPublish(ctx, op, "go-beacon", blob, dd, st)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if m.SHA256 == "" || m.Ref == "" || m.Size != int64(len(blob)) {
		t.Fatalf("manifest incomplete: %+v", m)
	}

	s, err := New(Options{
		Resolver: dd, Store: st, OperatorPub: op.Public,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	res, err := s.Fetch(ctx, ref)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(res.Blob, blob) {
		t.Fatal("fetched blob mismatch")
	}
	if res.Manifest.Kind != "go-beacon" {
		t.Fatalf("kind mismatch: %s", res.Manifest.Kind)
	}
}

func TestFetchWithoutStoreUsesResolver(t *testing.T) {
	op, dd, _, ctx := newEnv(t)
	blob := []byte("small-stage")
	m, ref, err := PackAndPublish(ctx, op, "tiny", blob, dd, nil)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	_ = m
	s, err := New(Options{Resolver: dd, OperatorPub: op.Public})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	res, err := s.Fetch(ctx, ref)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(res.Blob, blob) {
		t.Fatal("fetched blob mismatch")
	}
}

func TestManifestTamperRejected(t *testing.T) {
	op, dd, st, ctx := newEnv(t)
	blob := []byte("blob-data")
	m, ref, err := PackAndPublish(ctx, op, "x", blob, dd, st)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	m.Ref = "deadbeef"
	if err := m.Verify(op.Public); err == nil {
		t.Fatal("tampered manifest must fail verification")
	}
	_ = ref
}

func TestBlobTamperRejected(t *testing.T) {
	op, dd, st, ctx := newEnv(t)
	blob := []byte("original-blob")
	m, ref, err := PackAndPublish(ctx, op, "x", blob, dd, st)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	evil := []byte("evil-blob-with-same-ref-prefix")
	st.Put(ctx, m.Ref, evil)

	s, _ := New(Options{Resolver: dd, Store: st, OperatorPub: op.Public})
	if _, err := s.Fetch(ctx, ref); !errors.Is(err, ErrSizeMismatch) && !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestWrongOperatorRejected(t *testing.T) {
	op, dd, st, ctx := newEnv(t)
	other, _ := crypto.NewOperatorKeys()
	blob := []byte("blob")
	m, ref, _ := PackAndPublish(ctx, op, "x", blob, dd, st)
	if err := m.Verify(other.Public); !errors.Is(err, ErrBadOperator) {
		t.Fatalf("expected ErrBadOperator, got %v", err)
	}
	s, _ := New(Options{Resolver: dd, Store: st, OperatorPub: other.Public})
	if _, err := s.Fetch(ctx, ref); !errors.Is(err, ErrBadOperator) {
		t.Fatalf("expected ErrBadOperator on fetch, got %v", err)
	}
}

func TestSignatureForgeryRejected(t *testing.T) {
	op, _, _, _ := newEnv(t)
	blob := []byte("blob")
	m, err := SignStage(op, "x", blob)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig, _ := hex.DecodeString(m.Signature)
	sig[len(sig)-1] ^= 0xff
	m.Signature = hex.EncodeToString(sig)
	if err := m.Verify(op.Public); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestBlobTooLarge(t *testing.T) {
	op, dd, st, ctx := newEnv(t)
	blob := make([]byte, 4096)
	_, ref, _ := PackAndPublish(ctx, op, "x", blob, dd, st)
	s, _ := New(Options{Resolver: dd, Store: st, OperatorPub: op.Public, MaxSize: 1024})
	if _, err := s.Fetch(ctx, ref); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("expected ErrBlobTooLarge, got %v", err)
	}
}

func TestMissingManifest(t *testing.T) {
	op, dd, _, ctx := newEnv(t)
	s, _ := New(Options{Resolver: dd, OperatorPub: op.Public})
	if _, err := s.Fetch(ctx, "deadbeefdeadbeef"); !errors.Is(err, deaddrop.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGarbageManifestRejected(t *testing.T) {
	op, dd, _, ctx := newEnv(t)
	dd.Publish(ctx, "aaaaaaaaaaaaaaaa", []byte("not a manifest"))
	s, _ := New(Options{Resolver: dd, OperatorPub: op.Public})
	if _, err := s.Fetch(ctx, "aaaaaaaaaaaaaaaa"); !errors.Is(err, ErrBadManifest) {
		t.Fatalf("expected ErrBadManifest, got %v", err)
	}
}

func TestNewRequiresConfig(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without resolver must fail")
	}
	op, _, _, _ := newEnv(t)
	if _, err := New(Options{Resolver: deaddrop.NewFile(t.TempDir())}); err == nil {
		t.Fatal("New without operator pub must fail")
	}
	_ = op
}

func TestMemoryLoaderHoldsBytes(t *testing.T) {
	blob := []byte("raw-stage-bytes")
	l := &MemoryLoader{}
	if err := l.Load(context.Background(), "beacon", blob); err != nil {
		t.Fatalf("load: %v", err)
	}
	if l.Kind != "beacon" || !bytes.Equal(l.Blob, blob) {
		t.Fatal("memory loader did not retain stage")
	}
	if &l.Blob[0] == &blob[0] {
		t.Fatal("memory loader must copy, not alias")
	}
}

func TestFetchAndLoadMemory(t *testing.T) {
	op, dd, st, ctx := newEnv(t)
	blob := bytes.Repeat([]byte("loaded-blob"), 10)
	_, ref, _ := PackAndPublish(ctx, op, "go-beacon", blob, dd, st)
	s, _ := New(Options{Resolver: dd, Store: st, OperatorPub: op.Public})
	l := &MemoryLoader{}
	if _, err := s.FetchAndLoad(ctx, ref, l); err != nil {
		t.Fatalf("fetch+load: %v", err)
	}
	if !bytes.Equal(l.Blob, blob) {
		t.Fatal("loaded blob mismatch")
	}
}

func TestManifestJSONRoundTrip(t *testing.T) {
	op, _, _, _ := newEnv(t)
	m, _ := SignStage(op, "x", []byte("blob"))
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Manifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SHA256 != m.SHA256 || out.Signature != m.Signature {
		t.Fatal("manifest round trip mismatch")
	}
	if err := out.Verify(op.Public); err != nil {
		t.Fatalf("verify after round trip: %v", err)
	}
}
