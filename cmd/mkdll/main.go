// mkdll writes the reflective-loader test DLLs (see pkg/reflective) so an
// operator can exercise the `dll` task against a known payload:
//
//	go run ./cmd/mkdll -kind noimports -out testdll.bin
//	go run ./cmd/mkdll -kind imports -out testdll-imports.bin
//
// The noimports variant's `run` export returns loadedBase+0x87 (proves
// relocation); the imports variant returns the resolved IAT slot value + 7
// (proves import resolution without calling through the slot).
package main

import (
	"flag"
	"fmt"
	"os"

	"darkarts/pkg/reflective"
)

func main() {
	kind := flag.String("kind", "noimports", "payload kind: noimports | imports")
	out := flag.String("out", "", "output file (default: print size to stdout)")
	flag.Parse()

	blob, err := reflective.TestPayload(*kind)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdll:", err)
		os.Exit(1)
	}
	if *out == "" {
		fmt.Printf("kind=%s bytes=%d\n", *kind, len(blob))
		return
	}
	if err := os.WriteFile(*out, blob, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "mkdll:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(blob))
}
