//go:build windows && amd64

package bof

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestParserStructLayout(t *testing.T) {
	dp := &DataParser{
		buffer: make([]byte, 14),
		offset: 0,
	}
	dp.buffer[10] = 'A'
	dp.buffer[11] = 'B'
	dp.buffer[12] = 'C'
	dp.buffer[13] = 'D'

	base := uintptr(unsafe.Pointer(dp))
	for i := 0; i < 32; i += 8 {
		val := *(*uint64)(unsafe.Pointer(base + uintptr(i)))
		fmt.Printf("offset %2d (0x%02x): 0x%016x\n", i, i, val)
	}

	fmt.Printf("\nbuffer.ptr  = 0x%x\n", uintptr(unsafe.Pointer(&dp.buffer[0])))
	fmt.Printf("buffer.len  = %d\n", len(dp.buffer))
	fmt.Printf("offset      = %d\n", dp.offset)
	fmt.Printf("offset field offset in struct = %d\n", unsafe.Offsetof(dp.offset))
}
