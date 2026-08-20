package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef uint32_t NET_API_STATUS;
NET_API_STATUS netapi_netusergetinfo(void* servername, void* username, uint32_t level, void** bufptr);
*/
import "C"

import (
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"
)

//export netapi_netusergetinfo
func netapi_netusergetinfo(servername unsafe.Pointer, username unsafe.Pointer, level uint32, bufptr *unsafe.Pointer) C.NET_API_STATUS {
	out := filepath.Join(os.Getenv("TEMP"), "uac-mockdll.out")
	marker := filepath.Join(os.Getenv("TEMP"), "uac-mockdll.marker")
	data, _ := exec.Command("whoami", "/groups").CombinedOutput()
	os.WriteFile(out, data, 0644)
	os.WriteFile(marker, []byte("loaded"), 0644)
	return 0
}

func main() {}