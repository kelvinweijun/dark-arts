package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"dark-arts/pkg/crypto"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genid <seed-hex-64>")
		os.Exit(2)
	}
	seed, err := hex.DecodeString(os.Args[1])
	if err != nil || len(seed) != 32 {
		fmt.Fprintln(os.Stderr, "genid: seed must be 64 hex chars (32 bytes)")
		os.Exit(2)
	}
	ident, err := crypto.IdentityFromSeed(seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genid:", err)
		os.Exit(1)
	}
	pub := ident.Public()
	sum := sha256.Sum256(pub)
	fmt.Printf("pub=%x\nsid=%x\n", pub, sum[:16])
}
