package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
)

type OperatorKeys struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

func NewOperatorKeys() (*OperatorKeys, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &OperatorKeys{Private: priv, Public: pub}, nil
}

func OperatorKeysFromSeed(seed []byte) (*OperatorKeys, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errBadSeed
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &OperatorKeys{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

func (o *OperatorKeys) Sign(data []byte) []byte {
	return ed25519.Sign(o.Private, data)
}

func VerifyOperatorSignature(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}
