package crypto

import (
	"bytes"
	"testing"
)

func fuzzSession(t *testing.T) *Session {
	t.Helper()
	agent := fixedIdentity(t, 0xaa)
	server := fixedIdentity(t, 0xbb)
	s, err := NewSession(server, agent.Public(), "fuzz", RoleServer)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return s
}

func buildValidEnvelope() []byte {
	agent, err := IdentityFromSeed(bytes.Repeat([]byte{0xaa}, keySize))
	if err != nil {
		panic(err)
	}
	server, err := IdentityFromSeed(bytes.Repeat([]byte{0xbb}, keySize))
	if err != nil {
		panic(err)
	}
	a, err := NewSession(agent, server.Public(), "fuzz", RoleAgent)
	if err != nil {
		panic(err)
	}
	env, err := a.Encrypt([]byte("hello"))
	if err != nil {
		panic(err)
	}
	b, err := env.Marshal()
	if err != nil {
		panic(err)
	}
	return b
}

func FuzzDecrypt(f *testing.F) {
	f.Add(buildValidEnvelope())
	f.Add([]byte{})
	f.Add([]byte("garbage"))
	f.Add([]byte(`{"v":1,"sid":"fuzz","nonce":"AAAA","data":"AA=="}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add(bytes.Repeat([]byte{0x41}, 512))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := fuzzSession(t)
		env, err := UnmarshalEnvelope(data)
		if err != nil {
			return
		}
		_, _ = s.Decrypt(env)
	})
}
