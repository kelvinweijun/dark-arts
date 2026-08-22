package stager

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"dark-arts/pkg/crypto"
	"dark-arts/pkg/deaddrop"
)

const manifestVersion = 1

var (
	ErrBadManifest  = errors.New("stager: malformed manifest")
	ErrBadOperator  = errors.New("stager: operator key mismatch")
	ErrBadSignature = errors.New("stager: invalid signature")
	ErrHashMismatch = errors.New("stager: blob hash mismatch")
	ErrSizeMismatch = errors.New("stager: blob size mismatch")
	ErrBlobTooLarge = errors.New("stager: blob exceeds size limit")
)

type Manifest struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	Ref       string `json:"ref"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Operator  string `json:"operator"`
	Signature string `json:"signature,omitempty"`
}

type manifestCore struct {
	Version  int    `json:"version"`
	Kind     string `json:"kind"`
	Ref      string `json:"ref"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Operator string `json:"operator"`
}

func SignStage(op *crypto.OperatorKeys, kind string, blob []byte) (*Manifest, error) {
	if op == nil {
		return nil, errors.New("stager: nil operator key")
	}
	sum := sha256.Sum256(blob)
	m := &Manifest{
		Version:  manifestVersion,
		Kind:     kind,
		Ref:      deaddrop.KeyOf(blob),
		Size:     int64(len(blob)),
		SHA256:   hex.EncodeToString(sum[:]),
		Operator: hex.EncodeToString(op.Public),
	}
	m.Signature = hex.EncodeToString(op.Sign(m.signable()))
	return m, nil
}

func (m *Manifest) signable() []byte {
	b, err := json.Marshal(manifestCore{
		Version: m.Version, Kind: m.Kind, Ref: m.Ref,
		Size: m.Size, SHA256: m.SHA256, Operator: m.Operator,
	})
	if err != nil {
		panic(err)
	}
	return b
}

func (m *Manifest) Verify(trusted ed25519.PublicKey) error {
	if m == nil || m.Version != manifestVersion {
		return ErrBadManifest
	}
	if m.Size <= 0 || m.Size > maxStageSize {
		return ErrBadManifest
	}
	opPub, err := hex.DecodeString(m.Operator)
	if err != nil || !bytes.Equal(opPub, trusted) {
		return ErrBadOperator
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		return ErrBadSignature
	}
	if !crypto.VerifyOperatorSignature(trusted, m.signable(), sig) {
		return ErrBadSignature
	}
	return nil
}

func (m *Manifest) VerifyBlob(blob []byte) error {
	if int64(len(blob)) != m.Size {
		return ErrSizeMismatch
	}
	sum := sha256.Sum256(blob)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return ErrHashMismatch
	}
	if m.Ref != deaddrop.KeyOf(blob) {
		return ErrHashMismatch
	}
	return nil
}

func (m *Manifest) String() string {
	return fmt.Sprintf("kind=%s ref=%s size=%d sha256=%s operator=%s",
		m.Kind, m.Ref, m.Size, m.SHA256, m.Operator)
}
