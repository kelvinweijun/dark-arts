package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

type Role uint8

const (
	RoleAgent  Role = 1
	RoleServer Role = 2
)

type Session struct {
	sendChain [keySize]byte
	sendPos   uint64
	recvChain [keySize]byte
	recvPos   uint64
	recvKeys  map[uint64][]byte
	hwm       uint64
	seen      map[uint64]bool
	sid       string
}

func NewSession(me *Identity, peerPub []byte, sid string, role Role) (*Session, error) {
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	secret, err := me.priv.ECDH(pk)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(secret)
	mePub := me.Public()
	if bytes.Compare(mePub, peerPub) > 0 {
		mePub, peerPub = peerPub, mePub
	}
	h.Write(mePub)
	h.Write(peerPub)
	root := h.Sum(nil)

	sendLbl, recvLbl := "s2a", "a2s"
	if role == RoleAgent {
		sendLbl, recvLbl = "a2s", "s2a"
	}

	s := &Session{
		sendChain: deriveChain(secret, root, sid+sendLbl),
		recvChain: deriveChain(secret, root, sid+recvLbl),
		recvKeys:  make(map[uint64][]byte),
		seen:      make(map[uint64]bool),
		sid:       sid,
	}
	return s, nil
}

func deriveChain(secret, root []byte, info string) [keySize]byte {
	k, err := hkdf.Key(sha256.New, secret, root, "darkarts-handshake-v1"+info, keySize)
	if err != nil {
		panic(err)
	}
	var out [keySize]byte
	copy(out[:], k)
	return out
}

func ratchetStep(chain []byte, n uint64) (msgKey []byte, nextChain [keySize]byte) {
	m := hmac.New(sha256.New, chain)
	m.Write([]byte("ratchet-msg"))
	msgTmp := m.Sum(nil)

	c := hmac.New(sha256.New, chain)
	c.Write([]byte("ratchet-chain"))
	next := c.Sum(nil)
	copy(nextChain[:], next)

	msgKey, err := hkdf.Key(sha256.New, msgTmp, nil, "darkarts-msg-"+strconv.FormatUint(n, 10), keySize)
	if err != nil {
		panic(err)
	}
	return msgKey, nextChain
}

// KeyMaterial returns references to the ratchet chain buffers. Callers may
// transiently obfuscate them in place (e.g. sleep-masking); the addresses
// stay stable for the session lifetime and the contents must not be read or
// written while masked.
func (s *Session) KeyMaterial() [][]byte {
	return [][]byte{s.sendChain[:], s.recvChain[:]}
}

func (s *Session) SendPos() uint64 { return s.sendPos }

func (s *Session) SkipSend(n uint64) {
	for i := uint64(0); i < n; i++ {
		_, s.sendChain = ratchetStep(s.sendChain[:], s.sendPos)
		s.sendPos++
	}
}

func (s *Session) Encrypt(plaintext []byte) (*MessageEnvelope, error) {
	msgKey, nextChain := ratchetStep(s.sendChain[:], s.sendPos)
	s.sendChain = nextChain

	var nonce [nonceSize]byte
	binary.BigEndian.PutUint64(nonce[:8], s.sendPos)
	s.sendPos++

	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce[:], plaintext, s.aad())
	return &MessageEnvelope{
		Version:    sessionVersion,
		SessionID:  s.sid,
		Nonce:      nonce[:],
		Ciphertext: ciphertext,
	}, nil
}

func (s *Session) Decrypt(env *MessageEnvelope) ([]byte, error) {
	if env == nil {
		return nil, ErrMalformed
	}
	if env.SessionID != s.sid {
		return nil, ErrAuth
	}
	if env.Version != sessionVersion {
		return nil, ErrVersion
	}
	if len(env.Nonce) != nonceSize {
		return nil, ErrMalformed
	}
	counter := binary.BigEndian.Uint64(env.Nonce[:8])
	if s.seen[counter] {
		return nil, ErrReplay
	}
	if counter < s.hwm && s.hwm-counter > replayWindow {
		return nil, ErrReplay
	}
	if counter > s.recvPos && counter-s.recvPos > maxCounterGap {
		return nil, ErrMalformed
	}
	if counter >= s.recvPos {
		s.advanceRecv(counter)
	}
	key := s.recvKeys[counter]
	if key == nil {
		return nil, ErrMalformed
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, env.Nonce, env.Ciphertext, s.aad())
	if err != nil {
		return nil, ErrAuth
	}
	s.seen[counter] = true
	if counter > s.hwm {
		s.hwm = counter
	}
	s.prune()
	return pt, nil
}

func (s *Session) advanceRecv(to uint64) {
	for s.recvPos <= to {
		key, next := ratchetStep(s.recvChain[:], s.recvPos)
		s.recvKeys[s.recvPos] = key
		s.recvChain = next
		s.recvPos++
	}
}

func (s *Session) prune() {
	if s.hwm <= replayWindow {
		return
	}
	cutoff := s.hwm - replayWindow
	for c := range s.recvKeys {
		if c < cutoff {
			delete(s.recvKeys, c)
		}
	}
	for c := range s.seen {
		if c < cutoff {
			delete(s.seen, c)
		}
	}
}

func (s *Session) aad() []byte {
	return append([]byte("darkarts-v1"), []byte(s.sid)...)
}
