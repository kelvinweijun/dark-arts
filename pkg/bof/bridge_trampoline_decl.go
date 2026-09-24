package bof

// TestCallTrampoline calls the trampoline using Microsoft x64 convention from Go assembly
func TestCallTrampoline(a, b, c uintptr) uintptr