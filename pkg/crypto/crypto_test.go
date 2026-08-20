package crypto

import (
	"bytes"
	"testing"
)

func TestEnvelopeMarshalRoundTrip(t *testing.T) {
	env := &MessageEnvelope{
		Version:    sessionVersion,
		SessionID:  "s-42",
		Nonce:      bytes.Repeat([]byte{1}, nonceSize),
		Ciphertext: []byte("cipher"),
	}
	b, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := UnmarshalEnvelope(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SessionID != env.SessionID || !bytes.Equal(out.Nonce, env.Nonce) || !bytes.Equal(out.Ciphertext, env.Ciphertext) {
		t.Fatalf("round trip mismatch: %+v vs %+v", env, out)
	}
}

func TestUnmarshalEnvelopeGarbage(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		[]byte("not json"),
		[]byte(`{"v":"x"}`),
		[]byte(`{"v":1,"sid":1}`),
		[]byte(`[]`),
		[]byte(`null`),
	}
	for _, in := range inputs {
		if _, err := UnmarshalEnvelope(in); err != ErrMalformed {
			t.Fatalf("input %q: expected ErrMalformed, got %v", in, err)
		}
	}
}

func TestOperatorSigning(t *testing.T) {
	ok, err := NewOperatorKeys()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	data := []byte("drop-payload-v1")
	sig := ok.Sign(data)
	if !VerifyOperatorSignature(ok.Public, data, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyOperatorSignature(ok.Public, append(data, 0), sig) {
		t.Fatal("tampered data accepted")
	}
	sig[0] ^= 0xff
	if VerifyOperatorSignature(ok.Public, data, sig) {
		t.Fatal("tampered signature accepted")
	}
}
