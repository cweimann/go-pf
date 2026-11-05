//go:build freebsd

package pf

import (
	"fmt"
	"unsafe"
)

// pfiocRuleset is struct pfioc_ruleset.
type pfiocRuleset struct {
	Nr   uint32
	Path [maxPathLen]byte
	Name [anchorNameSize]byte
}

func init() {
	if unsafe.Sizeof(pfiocRuleset{}) != pfiocRulesetSize {
		panic(fmt.Sprintf("pfiocRuleset size %d != %d", unsafe.Sizeof(pfiocRuleset{}), pfiocRulesetSize))
	}
}

// ChildAnchors returns the names of anchors directly under path
// (empty path is the main ruleset). Nested anchors are not included.
func (h *Handle) ChildAnchors(path string) ([]string, error) {
	var prs pfiocRuleset
	copy(prs.Path[:], path)
	if err := h.ioctl(diocGetRulesets, unsafe.Pointer(&prs)); err != nil {
		return nil, fmt.Errorf("DIOCGETRULESETS: %w", err)
	}
	n := prs.Nr
	out := make([]string, 0, n)
	for i := uint32(0); i < n; i++ {
		var one pfiocRuleset
		copy(one.Path[:], path)
		one.Nr = i
		if err := h.ioctl(diocGetRuleset, unsafe.Pointer(&one)); err != nil {
			return nil, fmt.Errorf("DIOCGETRULESET: %w", err)
		}
		name := cstring(one.Name[:])
		if name == "" || name == "_pf" {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// AllAnchors returns every anchor path under root, depth-first
// (does not include the empty main-ruleset path).
func (h *Handle) AllAnchors() ([]string, error) {
	var out []string
	var walk func(string) error
	walk = func(path string) error {
		children, err := h.ChildAnchors(path)
		if err != nil {
			return err
		}
		for _, name := range children {
			child := name
			if path != "" {
				child = path + "/" + name
			}
			out = append(out, child)
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	return out, nil
}
