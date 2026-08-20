package crypto

import (
	"bytes"
	"testing"
)

func TestOperatorKeysFromSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	a, err := OperatorKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	b, err := OperatorKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	if !bytes.Equal(a.Public, b.Public) {
		t.Fatal("same seed must yield same public key")
	}
	if !bytes.Equal(a.Private, b.Private) {
		t.Fatal("same seed must yield same private key")
	}
}

func TestOperatorKeysFromSeedBadLength(t *testing.T) {
	if _, err := OperatorKeysFromSeed([]byte("short")); err == nil {
		t.Fatal("short seed must fail")
	}
}

func TestOperatorKeysFromSeedSignVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, 32)
	op, err := OperatorKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	msg := []byte("sign me")
	sig := op.Sign(msg)
	if !VerifyOperatorSignature(op.Public, msg, sig) {
		t.Fatal("signature must verify")
	}
	if VerifyOperatorSignature(op.Public, append(msg, '!'), sig) {
		t.Fatal("tampered message must not verify")
	}
}
