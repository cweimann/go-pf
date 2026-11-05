//go:build freebsd

package pf

import (
	"fmt"
	"unsafe"
)

// Table describes a PF address table.
type Table struct {
	Name   string
	Anchor string
	Flags  uint32
}

// ListTables returns all PF tables (main ruleset and anchors).
func (h *Handle) ListTables() ([]Table, error) {
	// Kernel requires pfrio_esize == sizeof(pfr_table) always (ENODEV otherwise).
	// Match pfctl: allocate a buffer, pass its capacity as pfrio_size, grow if the
	// kernel reports a larger needed size.
	buf := make([]pfrTable, 64)
	for {
		io := pfiocTable{
			Buffer: uintptr(unsafe.Pointer(&buf[0])),
			Esize:  int32(unsafe.Sizeof(pfrTable{})),
			Size:   int32(len(buf)),
			Flags:  FlagAllrsets,
		}
		if err := h.tableIoctl(diocrGetTables, &io); err != nil {
			return nil, err
		}
		n := int(io.Size)
		if n == 0 {
			return nil, nil
		}
		if n <= len(buf) {
			out := make([]Table, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, Table{
					Name:   cstring(buf[i].Name[:]),
					Anchor: cstring(buf[i].Anchor[:]),
					Flags:  buf[i].Flags,
				})
			}
			return out, nil
		}
		buf = make([]pfrTable, n)
	}
}

// AddTables creates one or more tables. Tables that only exist for runtime
// address updates should include TFlagPersist in flags.
func (h *Handle) AddTables(names []string, flags uint32) (added int, err error) {
	if len(names) == 0 {
		return 0, nil
	}
	buf := make([]pfrTable, len(names))
	for i, name := range names {
		if err := setTableName(&buf[i], name, ""); err != nil {
			return 0, err
		}
		buf[i].Flags = flags
	}
	io := pfiocTable{
		Buffer: uintptr(unsafe.Pointer(&buf[0])),
		Esize:  int32(unsafe.Sizeof(pfrTable{})),
		Size:   int32(len(buf)),
	}
	if err := h.tableIoctl(diocrAddTables, &io); err != nil {
		return 0, err
	}
	return int(io.Nadd), nil
}

// AddTable creates a single persistent table.
func (h *Handle) AddTable(name string) error {
	n, err := h.AddTables([]string{name}, TFlagPersist)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("table %q already exists or was not created", name)
	}
	return nil
}

// DeleteTables deletes the named tables.
func (h *Handle) DeleteTables(names []string) (deleted int, err error) {
	if len(names) == 0 {
		return 0, nil
	}
	buf := make([]pfrTable, len(names))
	for i, name := range names {
		if err := setTableName(&buf[i], name, ""); err != nil {
			return 0, err
		}
	}
	io := pfiocTable{
		Buffer: uintptr(unsafe.Pointer(&buf[0])),
		Esize:  int32(unsafe.Sizeof(pfrTable{})),
		Size:   int32(len(buf)),
	}
	if err := h.tableIoctl(diocrDelTables, &io); err != nil {
		return 0, err
	}
	return int(io.Ndel), nil
}

// DeleteTable deletes a single table.
func (h *Handle) DeleteTable(name string) error {
	n, err := h.DeleteTables([]string{name})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("table %q not deleted (missing or referenced)", name)
	}
	return nil
}

// ListAddrs returns all addresses in a table.
func (h *Handle) ListAddrs(table string) ([]Addr, error) {
	var t pfrTable
	if err := setTableName(&t, table, ""); err != nil {
		return nil, err
	}

	buf := make([]pfrAddr, 64)
	for {
		io := pfiocTable{
			Table:  t,
			Buffer: uintptr(unsafe.Pointer(&buf[0])),
			Esize:  int32(unsafe.Sizeof(pfrAddr{})),
			Size:   int32(len(buf)),
		}
		if err := h.tableIoctl(diocrGetAddrs, &io); err != nil {
			return nil, err
		}
		n := int(io.Size)
		if n == 0 {
			return nil, nil
		}
		if n <= len(buf) {
			out := make([]Addr, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, fromPfr(buf[i]))
			}
			return out, nil
		}
		buf = make([]pfrAddr, n)
	}
}

// AddAddrs adds addresses to a table. Returns how many were effectively added.
func (h *Handle) AddAddrs(table string, addrs []Addr) (added int, err error) {
	return h.mutateAddrs(diocrAddAddrs, table, addrs, true)
}

// DeleteAddrs removes addresses from a table. Returns how many were deleted.
func (h *Handle) DeleteAddrs(table string, addrs []Addr) (deleted int, err error) {
	n, err := h.mutateAddrs(diocrDelAddrs, table, addrs, false)
	return n, err
}

// ClearAddrs removes all addresses from a table.
func (h *Handle) ClearAddrs(table string) (deleted int, err error) {
	var t pfrTable
	if err := setTableName(&t, table, ""); err != nil {
		return 0, err
	}
	io := pfiocTable{Table: t}
	if err := h.tableIoctl(diocrClrAddrs, &io); err != nil {
		return 0, err
	}
	return int(io.Ndel), nil
}

// SetAddrs replaces the entire contents of a table.
func (h *Handle) SetAddrs(table string, addrs []Addr) (added, deleted, changed int, err error) {
	var t pfrTable
	if err := setTableName(&t, table, ""); err != nil {
		return 0, 0, 0, err
	}

	var buf []pfrAddr
	var ptr uintptr
	if len(addrs) > 0 {
		var err error
		buf, err = toPfrSlice(addrs)
		if err != nil {
			return 0, 0, 0, err
		}
		ptr = uintptr(unsafe.Pointer(&buf[0]))
	}

	io := pfiocTable{
		Table:  t,
		Buffer: ptr,
		Esize:  int32(unsafe.Sizeof(pfrAddr{})),
		Size:   int32(len(buf)),
	}
	if err := h.tableIoctl(diocrSetAddrs, &io); err != nil {
		return 0, 0, 0, err
	}
	return int(io.Nadd), int(io.Ndel), int(io.Nchange), nil
}

func (h *Handle) mutateAddrs(req uintptr, table string, addrs []Addr, wantAdd bool) (int, error) {
	if len(addrs) == 0 {
		return 0, nil
	}
	var t pfrTable
	if err := setTableName(&t, table, ""); err != nil {
		return 0, err
	}
	buf, err := toPfrSlice(addrs)
	if err != nil {
		return 0, err
	}
	io := pfiocTable{
		Table:  t,
		Buffer: uintptr(unsafe.Pointer(&buf[0])),
		Esize:  int32(unsafe.Sizeof(pfrAddr{})),
		Size:   int32(len(buf)),
	}
	if err := h.tableIoctl(req, &io); err != nil {
		return 0, err
	}
	if wantAdd {
		return int(io.Nadd), nil
	}
	return int(io.Ndel), nil
}

func toPfrSlice(addrs []Addr) ([]pfrAddr, error) {
	buf := make([]pfrAddr, len(addrs))
	for i, a := range addrs {
		pa, err := a.toPfr()
		if err != nil {
			return nil, err
		}
		buf[i] = pa
	}
	return buf, nil
}
