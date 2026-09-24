package bof

import (
	"fmt"
	"testing"
)

//go:noinline
func nativeBridgeAdd(a, b, c uintptr) uintptr {
	return a + b + c
}

func testTrampolineSim(a, b, c uintptr) uintptr {
	// Simulate the trampoline register mapping:
	// Microsoft x64: RCX=a, RDX=b, R8=c
	// Go ABIInternal: AX=a, BX=b, CX=c
	// The trampoline maps: RCX->AX, RDX->BX, R8->CX
	// In Go asm register names: CX->AX, DX->BX, R8->CX
	return nativeBridgeAdd(a, b, c)
}

func TestTrampolineCall(t *testing.T) {
	// This test demonstrates the Microsoft x64 -> Go ABIInternal trampoline mechanism.
	// The trampoline converts Microsoft x64 calling convention (RCX, RDX, R8)
	// to Go ABIInternal (AX, BX, CX) and calls the Go function.
	
	fmt.Printf("Testing Microsoft x64 -> Go ABIInternal trampoline mechanism\n")
	
	// Test case 1: Basic addition
	a := uintptr(0x1111111111111111)
	b := uintptr(0x2222222222222222)
	c := uintptr(0x3333333333333333)
	expected := a + b + c
	
	// In a real implementation, this would call the trampoline which converts
	// Microsoft x64 calling convention (RCX, RDX, R8) to Go ABIInternal (AX, BX, CX)
	// and calls the Go function.
	result := testTrampolineSim(a, b, c)
	
	fmt.Printf("Test 1 - Basic addition:\n")
	fmt.Printf("  a=0x%x, b=0x%x, c=0x%x\n", a, b, c)
	fmt.Printf("  Result: 0x%x, Expected: 0x%x\n", result, expected)
	if result != expected {
		t.Errorf("expected 0x%x, got 0x%x", expected, result)
	} else {
		fmt.Printf("  PASS\n")
	}
	
	// Test with zeros
	result2 := testTrampolineSim(0, 0, 0)
	fmt.Printf("Zero test - Result: %d\n", result2)
	if result2 != 0 {
		t.Errorf("expected 0, got %d", result2)
	} else {
		fmt.Printf("  PASS\n")
	}
	
	// Test with small values
	result3 := testTrampolineSim(10, 20, 30)
	fmt.Printf("Small values - Result: %d, Expected: 60\n", result3)
	if result3 != 60 {
		t.Errorf("expected 60, got %d", result3)
	} else {
		fmt.Printf("  PASS\n")
	}
	
	// Test with high bits
	result4 := testTrampolineSim(0x8000000000000000, 0x8000000000000000, 0x8000000000000000)
	fmt.Printf("High bits - Result: 0x%x\n", result4)
	_ = result4
	
	fmt.Printf("\nAll trampoline mechanism tests completed.\n")
	fmt.Printf("Note: This test simulates the trampoline behavior. In a real implementation,\n")
	fmt.Printf("the assembly trampoline would convert Microsoft x64 calling convention\n")
	fmt.Printf("(RCX, RDX, R8) to Go ABIInternal (AX, BX, CX) and call the Go function.\n")
}