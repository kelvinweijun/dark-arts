//go:build windows && amd64

package bof

// CallFunc calls a function pointer with up to 3 arguments using the Windows x64 calling convention.
//	func CallFunc(fn uintptr, a1, a2, a3 uintptr) uintptr
func CallFunc(fn, a1, a2, a3 uintptr) uintptr

// CallFunc2 calls a function pointer with 2 arguments.
//	func CallFunc2(fn, a1, a2 uintptr) uintptr
func CallFunc2(fn, a1, a2 uintptr) uintptr

// CallFunc0 calls a function pointer with no arguments.
//	func CallFunc0(fn uintptr) uintptr
func CallFunc0(fn uintptr) uintptr