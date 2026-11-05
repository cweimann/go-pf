//go:build freebsd

package pf

import (
	"fmt"
	"os"
)

// Handle is an open connection to /dev/pf.
type Handle struct {
	f *os.File
}

// Open opens /dev/pf for ioctl control. Requires appropriate privileges
// (typically root, or membership in the group that owns /dev/pf).
func Open() (*Handle, error) {
	f, err := os.OpenFile(DevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", DevicePath, err)
	}
	return &Handle{f: f}, nil
}

// Close closes the /dev/pf file descriptor.
func (h *Handle) Close() error {
	if h == nil || h.f == nil {
		return nil
	}
	err := h.f.Close()
	h.f = nil
	return err
}

func (h *Handle) fd() uintptr {
	return h.f.Fd()
}
