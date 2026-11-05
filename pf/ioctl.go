//go:build freebsd

package pf

import (
	"fmt"
	"syscall"
	"unsafe"
)

func (h *Handle) ioctl(req uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, h.fd(), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func (h *Handle) tableIoctl(req uintptr, io *pfiocTable) error {
	if err := h.ioctl(req, unsafe.Pointer(io)); err != nil {
		return fmt.Errorf("ioctl 0x%x: %w", req, err)
	}
	return nil
}

// compile-time size checks against FreeBSD 15.1 amd64 layouts
func init() {
	if unsafe.Sizeof(pfrTable{}) != pfrTableSize {
		panic(fmt.Sprintf("pfrTable size %d != %d", unsafe.Sizeof(pfrTable{}), pfrTableSize))
	}
	if unsafe.Sizeof(pfrAddr{}) != pfrAddrSize {
		panic(fmt.Sprintf("pfrAddr size %d != %d", unsafe.Sizeof(pfrAddr{}), pfrAddrSize))
	}
	if unsafe.Sizeof(pfiocTable{}) != pfiocTableSize {
		panic(fmt.Sprintf("pfiocTable size %d != %d", unsafe.Sizeof(pfiocTable{}), pfiocTableSize))
	}
}
