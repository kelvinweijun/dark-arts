package bof

import _ "unsafe"

//go:abi0
//go:noinline
func TestNativeBridge(a, b, c uintptr) uintptr {
	return a + b + c
}