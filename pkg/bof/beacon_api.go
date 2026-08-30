//go:build windows && amd64

package bof

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
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
	if p.offset+4 > len(p.buffer) {
		return 0
	}
	val := int32(p.buffer[p.offset]) | int32(p.buffer[p.offset+1])<<8 | int32(p.buffer[p.offset+2])<<16 | int32(p.buffer[p.offset+3])<<24
	p.offset += 4
	return val
}

func (p *DataParser) Extract(size int) []byte {
	if p.offset+size > len(p.buffer) {
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
func BeaconDataParse(parser **DataParser, buffer uintptr, size int32) {
	if size > 0 {
		*parser = NewDataParser(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(size)))
	} else {
		*parser = NewDataParser(nil)
	}
}

// BeaconDataInt - extract int32
func BeaconDataInt(parser *DataParser) int32 {
	if parser != nil {
		return parser.Int()
	}
	return 0
}

// BeaconDataShort - extract int16
func BeaconDataShort(parser *DataParser) int16 {
	if parser != nil {
		return parser.Short()
	}
	return 0
}

// BeaconDataLength - extract length
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
func ExecuteBOF(coffBytes []byte, functionName string, packedArgs []byte) (string, error) {
	coff, err := ParseCOFF(coffBytes)
	if err != nil {
		return "", fmt.Errorf("bof: parse failed: %w", err)
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

	// Pack arguments for the BOF
	// BOF convention: void go(char *args, int length)
	// We'll pass the packed args as a single buffer
	argData := packedArgs
	if len(argData) == 0 {
		argData = []byte{}
	}

	// Call the BOF entry point
	// Convention: void go(char *args, int length)
	// Some BOFs use: void go(char *args, int argc, char **argv)
	// We'll try the single buffer approach first

	// Prepare the argument buffer
	argPtr := uintptr(0)
	argLen := len(packedArgs)
	if len(packedArgs) > 0 {
		argPtr = uintptr(unsafe.Pointer(&packedArgs[0]))
	}

	// Call the BOF entry point: void go(char *args, int length)
	_ = CallFunc2(fnAddr, argPtr, uintptr(argLen))

	return fmt.Sprintf("BOF %s executed at 0x%x", functionName, fnAddr), nil
}

// AllocateRWX allocates RWX memory for shellcode/BOF execution
func AllocateRWX(size uintptr) (uintptr, error) {
	return windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
}

// FreeMemory frees allocated memory
func FreeMemory(base uintptr, size uintptr) error {
	return windows.VirtualFree(base, 0, windows.MEM_RELEASE)
}