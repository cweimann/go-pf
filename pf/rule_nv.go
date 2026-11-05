//go:build freebsd

package pf

/*
#cgo LDFLAGS: -lnv
#include <stdlib.h>

char *gopf_format_rule(int fd, const char *anchor, unsigned int ticket,
    unsigned int nr, unsigned int ruleset, int *errp);
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

func formatRule(fd int, anchor string, ticket, nr, ruleset uint32) (string, error) {
	ca := C.CString(anchor)
	defer C.free(unsafe.Pointer(ca))
	var cerr C.int
	cs := C.gopf_format_rule(C.int(fd), ca, C.uint(ticket), C.uint(nr), C.uint(ruleset), &cerr)
	if cs == nil {
		errno := syscall.Errno(cerr)
		if errno == 0 {
			errno = syscall.EIO
		}
		return "", fmt.Errorf("DIOCGETRULENV: %w", errno)
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs), nil
}
