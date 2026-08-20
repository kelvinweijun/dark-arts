package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func fixedIdentity(t *testing.T, seed byte) *Identity {
	t.Helper()
	id, err := IdentityFromSeed(bytes.Repeat([]byte{seed}, keySize))
	if err != nil {
		t.Fatalf("identity from seed: %v", err)
	}
	return id
}

func testPair(t *testing.T) (*Session, *Session, *MessageEnvelope) {
	t.Helper()
	agent := fixedIdentity(t, 0xaa)
	server := fixedIdentity(t, 0xbb)
	a, err := NewSession(agent, server.Public(), "sess-1", RoleAgent)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	s, err := NewSession(server, agent.Public(), "sess-1", RoleServer)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	env, err := a.Encrypt([]byte("task: hostname"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return a, s, env
}

func TestSkipSendRestoresCounter(t *testing.T) {
	agent := fixedIdentity(t, 0x77)
	server := fixedIdentity(t, 0x88)
	a1, err := NewSession(agent, server.Public(), "restart-sess", RoleAgent)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	a1.SkipSend(5)
	if a1.SendPos() != 5 {
		t.Fatalf("send pos after skip: %d", a1.SendPos())
	}
	env, err := a1.Encrypt([]byte("after-restart"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	counter := binary.BigEndian.Uint64(env.Nonce[:8])
	if counter != 5 {
		t.Fatalf("expected counter 5, got %d", counter)
	}

	a2, err := NewSession(agent, server.Public(), "restart-sess", RoleAgent)
	if err != nil {
		t.Fatalf("agent session 2: %v", err)
	}
	a2.SkipSend(5)
	env2, err := a2.Encrypt([]byte("after-restart"))
	if err != nil {
		t.Fatalf("encrypt 2: %v", err)
	}
	if !bytes.Equal(env.Ciphertext, env2.Ciphertext) {
		t.Fatal("chain derivation after skip diverged")
	}

	s, err := NewSession(server, agent.Public(), "restart-sess", RoleServer)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	pt, err := s.Decrypt(env)
	if err != nil {
		t.Fatalf("decrypt skipped message: %v", err)
	}
	if string(pt) != "after-restart" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

func TestRoundTrip(t *testing.T) {
	a, s, env := testPair(t)
	pt, err := s.Decrypt(env)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "task: hostname" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}

	env2, err := s.Encrypt([]byte("result: win10-vm"))
	if err != nil {
		t.Fatalf("encrypt reverse: %v", err)
	}
	pt2, err := a.Decrypt(env2)
	if err != nil {
		t.Fatalf("decrypt reverse: %v", err)
	}
	if string(pt2) != "result: win10-vm" {
		t.Fatalf("plaintext reverse mismatch: %q", pt2)
	}
}

func TestForwardSecrecy(t *testing.T) {
	agent := fixedIdentity(t, 0x11)
	server := fixedIdentity(t, 0x22)
	a, _ := NewSession(agent, server.Public(), "fs", RoleAgent)
	s, _ := NewSession(server, agent.Public(), "fs", RoleServer)

	var envs []*MessageEnvelope
	for i := 0; i < 3; i++ {
		env, err := a.Encrypt([]byte("m"))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		envs = append(envs, env)
	}

	leaked := &Session{
		sendChain: a.sendChain,
		sendPos:   a.sendPos,
		recvChain: a.recvChain,
		recvPos:   a.recvPos,
		recvKeys:  make(map[uint64][]byte),
		seen:      make(map[uint64]bool),
		hwm:       a.hwm,
		sid:       a.sid,
	}

	if _, err := leaked.Decrypt(envs[0]); err == nil {
		t.Fatal("past message decrypted with leaked current state")
	}
	if _, err := leaked.Decrypt(envs[1]); err == nil {
		t.Fatal("past message decrypted with leaked current state")
	}

	for _, env := range envs {
		if _, err := s.Decrypt(env); err != nil {
			t.Fatalf("server could not decrypt: %v", err)
		}
	}
}

func TestReplayRejected(t *testing.T) {
	a, s, env := testPair(t)
	if _, err := s.Decrypt(env); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if _, err := s.Decrypt(env); err != ErrReplay {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
	_ = a
}

func TestOutOfOrderWithinWindow(t *testing.T) {
	agent := fixedIdentity(t, 0x33)
	server := fixedIdentity(t, 0x44)
	a, _ := NewSession(agent, server.Public(), "ooo", RoleAgent)
	s, _ := NewSession(server, agent.Public(), "ooo", RoleServer)

	var envs []*MessageEnvelope
	for i := 0; i < 5; i++ {
		env, err := a.Encrypt([]byte("m"))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		envs = append(envs, env)
	}
	for _, i := range []int{4, 3, 1, 2, 0} {
		if _, err := s.Decrypt(envs[i]); err != nil {
			t.Fatalf("out-of-order decrypt %d: %v", i, err)
		}
	}
	if _, err := s.Decrypt(envs[4]); err != ErrReplay {
		t.Fatalf("replay after out-of-order: expected ErrReplay, got %v", err)
	}
}

func TestTamperRejected(t *testing.T) {
	a, s, env := testPair(t)
	_ = a

	tampered := *env
	tampered.Ciphertext = append([]byte(nil), env.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xff
	if _, err := s.Decrypt(&tampered); err != ErrAuth {
		t.Fatalf("ciphertext tamper: expected ErrAuth, got %v", err)
	}

	badSid := *env
	badSid.SessionID = "other"
	if _, err := s.Decrypt(&badSid); err != ErrAuth {
		t.Fatalf("sid tamper: expected ErrAuth, got %v", err)
	}

	badVer := *env
	badVer.Version = 99
	if _, err := s.Decrypt(&badVer); err != ErrVersion {
		t.Fatalf("version tamper: expected ErrVersion, got %v", err)
	}

	badNonce := *env
	badNonce.Nonce = env.Nonce[:4]
	if _, err := s.Decrypt(&badNonce); err != ErrMalformed {
		t.Fatalf("nonce tamper: expected ErrMalformed, got %v", err)
	}

	if _, err := s.Decrypt(nil); err != ErrMalformed {
		t.Fatalf("nil envelope: expected ErrMalformed, got %v", err)
	}
}

func TestWrongPeerRejected(t *testing.T) {
	agent := fixedIdentity(t, 0x55)
	server := fixedIdentity(t, 0x66)
	other := fixedIdentity(t, 0x77)

	a, _ := NewSession(agent, server.Public(), "wp", RoleAgent)
	s, _ := NewSession(server, agent.Public(), "wp", RoleServer)
	o, _ := NewSession(other, agent.Public(), "wp", RoleServer)

	env, err := a.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := s.Decrypt(env); err != nil {
		t.Fatalf("real peer decrypt: %v", err)
	}
	if _, err := o.Decrypt(env); err != ErrAuth {
		t.Fatalf("wrong peer: expected ErrAuth, got %v", err)
	}
}

func TestManyMessages(t *testing.T) {
	agent := fixedIdentity(t, 0x88)
	server := fixedIdentity(t, 0x99)
	a, _ := NewSession(agent, server.Public(), "many", RoleAgent)
	s, _ := NewSession(server, agent.Public(), "many", RoleServer)

	const n = 10_000
	for i := 0; i < n; i++ {
		payload := []byte("message-" + itoa(i))
		env, err := a.Encrypt(payload)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		pt, err := s.Decrypt(env)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if !bytes.Equal(pt, payload) {
			t.Fatalf("payload mismatch at %d", i)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
