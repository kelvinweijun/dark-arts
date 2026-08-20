package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
)

type Identity struct {
	priv *ecdh.PrivateKey
}

func NewIdentity() (*Identity, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{priv: priv}, nil
}

func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != keySize {
		return nil, ErrMalformed
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, ErrMalformed
	}
	return &Identity{priv: priv}, nil
}

func (i *Identity) Public() []byte {
	return i.priv.PublicKey().Bytes()
}

func (i *Identity) PrivateSeed() []byte {
	return i.priv.Bytes()
}
