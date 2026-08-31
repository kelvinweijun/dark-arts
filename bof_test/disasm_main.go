//go:build ignore

package main

import (
	"dark-arts/pkg/bof"
	"fmt"
	"unsafe"
)

func main() {
	// Resolve trampoline addresses
	addrs := bof.TrampolineAddrs()
	for name, addr := range addrs {
		fmt.Printf("%s -> 0x%x\n", name, addr)
	}

	// Test BeaconPrintfNative_abi0
	fmtAddr := addrs["BeaconPrintfNative"]
	if fmtAddr == 0 {
		fmt.Println("BeaconPrintfNative not found")
		return
	}

	// Use CallFunc to invoke it
	testMsg := []byte("hello\x00")
	bof.CallFunc(fmtAddr, 0, uintptr(unsafe.Pointer(&testMsg[0])), 0)
	fmt.Println("BeaconPrintfNative_abi0 call completed")
}
