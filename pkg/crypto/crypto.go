package crypto

import (
	"encoding/json"
	"errors"
)

const (
	sessionVersion = 1
	keySize        = 32
	nonceSize      = 12
	replayWindow   = 256
	maxCounterGap  = 1 << 20
)

var (
	ErrMalformed = errors.New("crypto: malformed input")
	ErrAuth      = errors.New("crypto: authentication failed")
	ErrReplay    = errors.New("crypto: replay detected")
	ErrVersion   = errors.New("crypto: unsupported envelope version")
	errBadSeed   = errors.New("crypto: seed must be 32 bytes")
)

type MessageEnvelope struct {
	Version    uint8  `json:"v"`
	SessionID  string `json:"sid"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"data"`
	Signature  []byte `json:"sig,omitempty"`
}

func (e *MessageEnvelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

func UnmarshalEnvelope(data []byte) (*MessageEnvelope, error) {
	var e MessageEnvelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, ErrMalformed
	}
	if e.Version == 0 {
		return nil, ErrMalformed
	}
	return &e, nil
}
