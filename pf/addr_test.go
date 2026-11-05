//go:build freebsd

package pf

import (
	"bytes"
	"net"
	"testing"
	"unsafe"
)

func TestStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(pfrTable{}); got != pfrTableSize {
		t.Fatalf("pfrTable size %d want %d", got, pfrTableSize)
	}
	if got := unsafe.Sizeof(pfrAddr{}); got != pfrAddrSize {
		t.Fatalf("pfrAddr size %d want %d", got, pfrAddrSize)
	}
	if got := unsafe.Sizeof(pfiocTable{}); got != pfiocTableSize {
		t.Fatalf("pfiocTable size %d want %d", got, pfiocTableSize)
	}
}

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.1", "192.0.2.1"},
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"!198.51.100.7", "!198.51.100.7"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tc := range cases {
		a, err := ParseAddr(tc.in)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", tc.in, err)
		}
		if got := a.String(); got != tc.want {
			t.Fatalf("ParseAddr(%q).String() = %q want %q", tc.in, got, tc.want)
		}
		pa, err := a.toPfr()
		if err != nil {
			t.Fatalf("toPfr(%q): %v", tc.in, err)
		}
		round := fromPfr(pa)
		if round.String() != a.String() {
			t.Fatalf("roundtrip %q -> %q", a.String(), round.String())
		}
	}
}

func TestParseAddrIPv4Bytes(t *testing.T) {
	a, err := ParseAddr("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	pa, err := a.toPfr()
	if err != nil {
		t.Fatal(err)
	}
	if pa.AF != AFInet || pa.Net != 32 {
		t.Fatalf("af/net = %d/%d", pa.AF, pa.Net)
	}
	want := net.IPv4(203, 0, 113, 9).To4()
	if !bytes.Equal(pa.Addr[:4], want) {
		t.Fatalf("addr bytes %v want %v", pa.Addr[:4], want)
	}
}
