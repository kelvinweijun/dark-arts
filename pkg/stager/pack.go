package stager

import (
	"context"
	"encoding/json"

	"darkarts/pkg/crypto"
	"darkarts/pkg/deaddrop"
	"darkarts/pkg/store"
)

func Publish(ctx context.Context, m *Manifest, blob []byte, dd deaddrop.Resolver, st store.Store) (manifestRef string, err error) {
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	manifestRef = deaddrop.KeyOf(manifestBytes)

	if st != nil {
		if err := st.Put(ctx, m.Ref, blob); err != nil {
			return "", err
		}
	} else if err := dd.Publish(ctx, m.Ref, blob); err != nil {
		return "", err
	}
	if err := dd.Publish(ctx, manifestRef, manifestBytes); err != nil {
		return "", err
	}
	return manifestRef, nil
}

func PackAndPublish(ctx context.Context, op *crypto.OperatorKeys, kind string, blob []byte, dd deaddrop.Resolver, st store.Store) (*Manifest, string, error) {
	m, err := SignStage(op, kind, blob)
	if err != nil {
		return nil, "", err
	}
	manifestRef, err := Publish(ctx, m, blob, dd, st)
	if err != nil {
		return nil, "", err
	}
	return m, manifestRef, nil
}
