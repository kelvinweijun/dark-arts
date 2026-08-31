//go:build windows && amd64

package bof

import (
	"fmt"
	"unsafe"
)

// Beacon API functions for BOF compatibility.
// These match the CS/BOF API conventions.

var (
	// Output callbacks
	beaconPrintf func(format string, args ...interface{})
	beaconOutput func(data []byte)

	// Data parser
	dataParser *DataParser
)

// DataParser mimics CS's BeaconDataParse/BeaconDataInt/BeaconDataShort/BeaconDataLength/BeaconDataExtract
type DataParser struct {
	buffer []byte
	offset int
}

func NewDataParser(data []byte) *DataParser {
	return &DataParser{buffer: data, offset: 0}
}

func (p *DataParser) Int() int32 {
	if p.offset+4 > len(p.buffer) {
		return 0
	}
	val := int32(p.buffer[p.offset]) | int32(p.buffer[p.offset+1])<<8 | int32(p.buffer[p.offset+2])<<16 | int32(p.buffer[p.offset+3])<<24
	p.offset += 4
	return val
}

func (p *DataParser) Short() int16 {
	if p.offset+2 > len(p.buffer) {
		return 0
	}
	val := int16(p.buffer[p.offset]) | int16(p.buffer[p.offset+1])<<8
	p.offset += 2
	return val
}

func (p *DataParser) Length() int32 {
	return int32(len(p.buffer) - p.offset)
}

func (p *DataParser) Extract(size int) []byte {
	if size < 0 || p.offset+size > len(p.buffer) {
		return nil
	}
	data := p.buffer[p.offset : p.offset+size]
	p.offset += size
	return data
}

func (p *DataParser) Remaining() int {
	return len(p.buffer) - p.offset
}

// SetBeaconCallbacks registers the beacon API callbacks.
// Called by the beacon when initializing BOF support.
func SetBeaconCallbacks(printfFn func(format string, args ...interface{}), outputFn func(data []byte)) {
	beaconPrintf = printfFn
	beaconOutput = outputFn
}

// BeaconPrintf - CS compatible BeaconPrintf
// BOFs call this to send formatted output back to the beacon.
func BeaconPrintf(format string, args ...interface{}) {
	if beaconPrintf != nil {
		beaconPrintf(format, args...)
	}
}

// BeaconOutput - raw output
func BeaconOutput(data []byte) {
	if beaconOutput != nil {
		beaconOutput(data)
	}
}

// BeaconDataParse - initialize parser
//
// IMPORTANT: We copy the buffer to the heap because the caller (MSVC COFF)
// passes a pointer to its goroutine stack frame. When the goroutine stack
// grows, the stack is copied to a new location, but unsafe.Pointer derived
// from a uintptr is NOT tracked by the GC — the slice's data pointer becomes
// stale. By copying to a heap-allocated []byte, the GC can track and update
// the pointer correctly, and the buffer survives any stack growth.
//
// NOTE: //go:nosplit was intentionally removed. The make() call escapes to
// heap (runtime.mallocgc), which is incompatible with nosplit. The trampoline
// calls this through the ABI0→ABIInternal wrapper, which is NOSPLIT assembly
// and provides adequate stack depth. The goroutine stack grows normally
// through this function.
func BeaconDataParse(parser **DataParser, buffer uintptr, size int32) {
	if size > 0 {
		src := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(size))
		buf := make([]byte, int(size))
		copy(buf, src)
		*parser = NewDataParser(buf)
	} else {
		*parser = NewDataParser(nil)
	}
}

// BeaconDataInt - extract int32
//
//go:nosplit
func BeaconDataInt(parser *DataParser) int32 {
	if parser != nil {
		return parser.Int()
	}
	return 0
}

// BeaconDataShort - extract int16
//
//go:nosplit
func BeaconDataShort(parser *DataParser) int16 {
	if parser != nil {
		return parser.Short()
	}
	return 0
}

// BeaconDataLength - extract length
//
//go:nosplit
func BeaconDataLength(parser *DataParser) int32 {
	if parser != nil {
		return parser.Length()
	}
	return 0
}

// BeaconDataExtract - extract raw bytes
func BeaconDataExtract(parser *DataParser, size int32) []byte {
	if parser != nil {
		return parser.Extract(int(size))
	}
	return nil
}

// internalOutput sends formatted output to the beacon's output callback
func internalOutput(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if beaconOutput != nil {
		beaconOutput([]byte(msg))
	}
}

// PackArguments packs arguments into the BOF argument format:
// [length][data...] where each arg is [type][length][data]
// Types: 0=int32, 1=string, 2=raw bytes, 3=int64
func PackArguments(args []string) []byte {
	var buf []byte
	for _, arg := range args {
		b := []byte(arg)
		buf = append(buf, byte(len(b)), byte(len(b)>>8)) // length as uint16
		buf = append(buf, b...)
	}
	return buf
}

// UnpackArguments unpacks BOF arguments
func UnpackArguments(data []byte) []string {
	var args []string
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		length := int(data[offset]) | int(data[offset+1])<<8
		offset += 2
		if offset+int(length) > len(data) {
			break
		}
		s := string(data[offset : offset+length])
		args = append(args, s)
		offset += int(length)
	}
	return args
}

// ExecuteBOF runs a BOF with the given function name and arguments.
// This is the main entry point for BOF execution from the beacon.
func ExecuteBOF(coffBytes []byte, functionName string, args []string) (string, error) {
	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		return "", fmt.Errorf("bof: parse failed: %w", err)
	}

	// Resolve Beacon API symbols to their trampolines before loading
	if err := coff.ResolveBeaconAPIs(); err != nil {
		return "", fmt.Errorf("bof: beacon api resolution failed: %w", err)
	}

	entry, err := coff.Load()
	if err != nil {
		return "", fmt.Errorf("bof: load failed: %w", err)
	}

	// Find the function
	fnAddr, ok := coff.GetSymbol(functionName)
	if !ok {
		fnAddr = entry
	}

	// Pack arguments into BOF format
	packedArgs := PackArguments(args)
	var argPtr uintptr
	argLen := len(packedArgs)
	if argLen > 0 {
		argPtr = uintptr(unsafe.Pointer(&packedArgs[0]))
	} else {
		argPtr = 0
	}

	// Call the BOF entry point using assembly stub: void go(char *args, int length)
	_ = CallFunc2(fnAddr, argPtr, uintptr(argLen))

	return fmt.Sprintf("BOF %s executed at 0x%x", functionName, fnAddr), nil
}

// BeaconPrintfNative - native-compatible variant for variadic BeaconPrintf
// Native BOF call: void BeaconPrintf(int type, const char *fmt, ...)
// MSVC x64 variadic: first 2 varargs in R8/R9, remaining on stack.
// The trampoline forwards up to 6 varargs as uintptr values.
//
// Supported format specifiers:
//   %d, %i    → int32 (sign-extended from uintptr)
//   %u        → uint32
//   %x, %X    → hex uint32
//   %s        → *byte (converted to Go string)
//   %p        → uintptr (formatted as pointer)
//   %ld, %lu, %lx → int64/uint64 (same size as uintptr on amd64)
//   %lld, %llu, %llx → int64/uint64
//   %%        → literal '%', no argument consumed
//   Other specifiers (f, e, g, etc.) → passed as uintptr (raw bits)
//
func BeaconPrintfNative(outputType int32, format *byte, argCount int,
	v0, v1, v2, v3, v4, v5, v6, v7 uintptr) {
	if beaconPrintf == nil || format == nil {
		return
	}
	f := cstrToGoString(format)
	if f == "" {
		return
	}

	varargs := [8]uintptr{v0, v1, v2, v3, v4, v5, v6, v7}
	args := parseFormatArgs(f, varargs[:], argCount)
	beaconPrintf(f, args...)
}

// cstrToGoString converts a null-terminated C string pointer to a Go string.
func cstrToGoString(p *byte) string {
	if p == nil {
		return ""
	}
	// Find null terminator (safe for nosplit since format strings are short)
	n := 0
	for ptr := (*byte)(unsafe.Pointer(p)); *ptr != 0; ptr = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + 1)) {
		n++
		if n > 4096 {
			return "" // sanity limit
		}
	}
	if n == 0 {
		return ""
	}
	return unsafe.String(p, n)
}

// parseFormatArgs scans a printf-style format string and extracts variadic
// arguments from the raw uintptr slice, converting them to interface{} values
// based on the format specifiers encountered.
func parseFormatArgs(format string, varargs []uintptr, argCount int) []interface{} {
	var args []interface{}
	argIdx := 0
	i := 0
	for i < len(format) {
		if format[i] != '%' {
			i++
			continue
		}
		i++ // skip '%'
		if i >= len(format) {
			break
		}
		if format[i] == '%' {
			i++ // literal %%
			continue
		}
		// Skip flags (-, +, 0, space, #) and width (.digits)
		for i < len(format) && (format[i] == '-' || format[i] == '+' ||
			format[i] == '0' || format[i] == ' ' || format[i] == '#' ||
			format[i] == '.' || (format[i] >= '0' && format[i] <= '9')) {
			i++
		}
		if i >= len(format) {
			break
		}
		// Check for length modifiers
		longMod := 0
		if i < len(format) && format[i] == 'l' {
			longMod++
			i++
			if i < len(format) && format[i] == 'l' {
				longMod++
				i++
			}
		}
		if i < len(format) && format[i] == 'z' {
			longMod++
			i++
		}
		if i >= len(format) {
			break
		}
		spec := format[i]
		i++

		if argIdx >= len(varargs) || argIdx >= argCount {
			break
		}
		val := varargs[argIdx]
		argIdx++

		switch spec {
		case 's':
			if val != 0 {
				args = append(args, interface{}(cstrToGoString((*byte)(unsafe.Pointer(val)))))
			} else {
				args = append(args, interface{}("<nil>"))
			}
		case 'd', 'i':
			if longMod >= 1 {
				args = append(args, int64(val))
			} else {
				args = append(args, int32(val))
			}
		case 'u':
			if longMod >= 1 {
				args = append(args, uint64(val))
			} else {
				args = append(args, uint32(val))
			}
		case 'x', 'X':
			if longMod >= 1 {
				args = append(args, uint64(val))
			} else {
				args = append(args, uint32(val))
			}
		case 'p':
			args = append(args, val)
		default:
			// Unknown specifier: pass raw value
			args = append(args, val)
		}
	}
	return args
}

// beaconOutputNative matches the native CS BeaconOutput signature:
// void BeaconOutput(int type, char *data, int length)
//
//go:nosplit
func beaconOutputNative(outputType int32, data *byte, length int32) {
	if beaconOutput != nil && data != nil && length > 0 {
		beaconOutput(unsafe.Slice(data, int(length)))
	}
}

// beaconDataExtractNative returns a raw pointer (uintptr) instead of []byte.
// This avoids the hidden-return-buffer issue in ABI0: functions returning
// multi-word values (like []byte) require the caller to pass a hidden first
// argument pointing to a return buffer. By returning uintptr (single word),
// no hidden pointer is needed and the trampoline can read the result from RAX.
//
// The result is stored in a GC-tracked global before returning. This ensures
// that if stack growth occurs during the ABI adapter call, the GC updates
// the pointer in the global (it's an unsafe.Pointer, not a uintptr).
//
//go:nosplit
func beaconDataExtractNative(parser uintptr, size int32) uintptr {
	if parser != 0 {
		p := (*DataParser)(unsafe.Pointer(parser))
		data := p.Extract(int(size))
		if len(data) > 0 {
			gExtractRawPtr = unsafe.Pointer(&data[0])
			return uintptr(gExtractRawPtr)
		}
	}
	return 0
}

// gExtractRawPtr holds the last extract result as a GC-tracked pointer.
// The trampoline reads from this after the call to get the correct pointer
// even if stack growth moved the goroutine stack between the function return
// and the trampoline's RET instruction.
var gExtractRawPtr unsafe.Pointer