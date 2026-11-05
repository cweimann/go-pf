//go:build freebsd

package pf

import (
	"strings"
	"testing"
)

func TestParseAddrsReader(t *testing.T) {
	in := `
# private nets
192.168.0.0/16
172.16.0.0/12 # rfc1918
10.0.0.0/8

!198.51.100.1
`
	addrs, err := ParseAddrsReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "!198.51.100.1"}
	if len(addrs) != len(want) {
		t.Fatalf("got %d addrs want %d: %v", len(addrs), len(want), addrs)
	}
	for i := range want {
		if got := addrs[i].String(); got != want[i] {
			t.Fatalf("[%d] got %q want %q", i, got, want[i])
		}
	}
}
