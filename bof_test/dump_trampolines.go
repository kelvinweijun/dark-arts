//go:build ignore

package main

import (
	"fmt"
	"os"
	"unsafe"

	"dark-arts/pkg/bof"
)

func main() {
	addrs := bof.TrampolineAddrs()
	for name, addr := range addrs {
		fmt.Printf("%s -> 0x%x\n", name, addr)
	}

	// Dump bytes around BeaconPrintfNative ABI0 entry
	if addr, ok := addrs["BeaconPrintfNative"]; ok && addr != 0 {
		// Read 256 bytes starting at the ABI0 entry
		buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 256)
		fmt.Printf("\nBeaconPrintfNative ABI0 first 256 bytes:\n")
		for i := 0; i < len(buf); i += 16 {
			fmt.Printf("  0x%x: ", addr+uintptr(i))
			for j := 0; j < 16 && i+j < len(buf); j++ {
				fmt.Printf("%02x ", buf[i+j])
			}
			fmt.Println()
		}
	}

	// Dump bytes around BeaconPrintf (the ABIInternal entry)
	if addr, ok := addrs["BeaconPrintf"]; ok && addr != 0 {
		buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 256)
		fmt.Printf("\nBeaconPrintf ABIInternal first 256 bytes:\n")
		for i := 0; i < len(buf); i += 16 {
			fmt.Printf("  0x%x: ", addr+uintptr(i))
			for j := 0; j < 16 && i+j < len(buf); j++ {
				fmt.Printf("%02x ", buf[i+j])
			}
			fmt.Println()
		}
	}

	// Write raw bytes to files for external disassembly
	if addr, ok := addrs["BeaconPrintfNative"]; ok && addr != 0 {
		buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 512)
		os.WriteFile("abi0_wrapper.bin", buf, 0644)
		fmt.Println("\nWrote abi0_wrapper.bin (512 bytes)")
	}

	if addr, ok := addrs["BeaconPrintf"]; ok && addr != 0 {
		buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 512)
		os.WriteFile("abiinternal_func.bin", buf, 0644)
		fmt.Println("Wrote abiinternal_func.bin (512 bytes)")
	}

	fmt.Println("\nDisassemble with: dumpbin /DISASM abi0_wrapper.bin")
	fmt.Println("Or use: ndisasm -b 64 abi0_wrapper.bin")
}
