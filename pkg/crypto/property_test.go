package crypto

import (
	"bytes"
	"testing"
)

func TestPropertyRandomEnvelopesDecryptOnlyWithCorrectKey(t *testing.T) {
	agent := fixedIdentity(t, 0x0a)
	server := fixedIdentity(t, 0x0b)
	a, _ := NewSession(agent, server.Public(), "prop", RoleAgent)
	s, _ := NewSession(server, agent.Public(), "prop", RoleServer)
	o, _ := NewSession(fixedIdentity(t, 0x0c), agent.Public(), "prop", RoleServer)

	const n = 10_000
	for i := 0; i < n; i++ {
		payload := make([]byte, i%257)
		for j := range payload {
			payload[j] = byte(i * 31)
		}
		env, err := a.Encrypt(payload)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		pt, err := s.Decrypt(env)
		if err != nil {
			t.Fatalf("correct key decrypt %d: %v", i, err)
		}
		if !bytes.Equal(pt, payload) {
			t.Fatalf("payload mismatch at %d", i)
		}
		if _, err := o.Decrypt(env); err != ErrAuth {
			t.Fatalf("wrong key accepted at %d: %v", i, err)
		}
	}
}
