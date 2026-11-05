//go:build freebsd

package pf

import (
	"fmt"
	"net"
	"strings"
)

// Addr is a PF table address (host or network).
type Addr struct {
	IP      net.IP
	Mask    int  // prefix length
	Not     bool // negation (!)
}

func (a Addr) String() string {
	s := a.IP.String()
	bits := a.Mask
	if bits < 0 {
		if a.IP.To4() != nil {
			bits = 32
		} else {
			bits = 128
		}
	}
	if a.IP.To4() != nil && bits != 32 || a.IP.To4() == nil && bits != 128 {
		s = fmt.Sprintf("%s/%d", s, bits)
	}
	if a.Not {
		return "!" + s
	}
	return s
}

// ParseAddr parses an address or CIDR, optionally prefixed with '!'.
func ParseAddr(s string) (Addr, error) {
	s = strings.TrimSpace(s)
	not := false
	if strings.HasPrefix(s, "!") {
		not = true
		s = strings.TrimSpace(s[1:])
	}

	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return Addr{}, fmt.Errorf("parse %q: %w", s, err)
		}
		ones, _ := ipnet.Mask.Size()
		return Addr{IP: ip.Mask(ipnet.Mask), Mask: ones, Not: not}, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return Addr{}, fmt.Errorf("parse %q: invalid address", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return Addr{IP: v4, Mask: 32, Not: not}, nil
	}
	return Addr{IP: ip.To16(), Mask: 128, Not: not}, nil
}

func (a Addr) toPfr() (pfrAddr, error) {
	var pa pfrAddr
	if a.Not {
		pa.Not = 1
	}

	if v4 := a.IP.To4(); v4 != nil {
		pa.AF = AFInet
		copy(pa.Addr[:4], v4)
		mask := a.Mask
		if mask < 0 {
			mask = 32
		}
		if mask > 32 {
			return pa, fmt.Errorf("IPv4 prefix length %d out of range", mask)
		}
		pa.Net = uint8(mask)
		return pa, nil
	}

	v6 := a.IP.To16()
	if v6 == nil {
		return pa, fmt.Errorf("invalid IP")
	}
	pa.AF = AFInet6
	copy(pa.Addr[:], v6)
	mask := a.Mask
	if mask < 0 {
		mask = 128
	}
	if mask > 128 {
		return pa, fmt.Errorf("IPv6 prefix length %d out of range", mask)
	}
	pa.Net = uint8(mask)
	return pa, nil
}

func fromPfr(pa pfrAddr) Addr {
	a := Addr{Mask: int(pa.Net), Not: pa.Not != 0}
	switch pa.AF {
	case AFInet:
		ip := make(net.IP, 4)
		copy(ip, pa.Addr[:4])
		a.IP = ip
	case AFInet6:
		ip := make(net.IP, 16)
		copy(ip, pa.Addr[:])
		a.IP = ip
	}
	return a
}

func setTableName(t *pfrTable, name, anchor string) error {
	if len(name) == 0 {
		return fmt.Errorf("empty table name")
	}
	if len(name) >= tableNameSize {
		return fmt.Errorf("table name %q too long (max %d)", name, tableNameSize-1)
	}
	if len(anchor) >= maxPathLen {
		return fmt.Errorf("anchor %q too long (max %d)", anchor, maxPathLen-1)
	}
	copy(t.Name[:], name)
	if anchor != "" {
		copy(t.Anchor[:], anchor)
	}
	return nil
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
