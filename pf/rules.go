//go:build freebsd

package pf

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// Rule is one PF filter/scrub/nat rule rendered in pf.conf-like text.
type Rule struct {
	Anchor  string // ruleset path; empty for main
	Ruleset uint32 // ActionPass, ActionScrub, ...
	Nr      uint32
	Text    string
}

// rulesInfo is the ticket + count from DIOCGETRULES for one (anchor, action).
type rulesInfo struct {
	Ticket uint32
	Nr     uint32
}

func (h *Handle) getRulesInfo(anchor string, action uint8) (rulesInfo, error) {
	buf := make([]byte, pfiocRuleSize)
	binary.LittleEndian.PutUint32(buf[pfiocRuleOffRuleAction:], uint32(action))
	if anchor != "" {
		copy(buf[pfiocRuleOffAnchor:], anchor)
	}
	if err := h.ioctl(diocGetRules, unsafe.Pointer(&buf[0])); err != nil {
		return rulesInfo{}, fmt.Errorf("DIOCGETRULES: %w", err)
	}
	return rulesInfo{
		Ticket: binary.LittleEndian.Uint32(buf[pfiocRuleOffTicket:]),
		Nr:     binary.LittleEndian.Uint32(buf[pfiocRuleOffNr:]),
	}, nil
}

func (h *Handle) listRulesIn(anchor string, actions []uint32) ([]Rule, error) {
	var out []Rule
	fd := int(h.fd())
	for _, action := range actions {
		info, err := h.getRulesInfo(anchor, uint8(action))
		if err != nil {
			return nil, err
		}
		for i := uint32(0); i < info.Nr; i++ {
			text, err := formatRule(fd, anchor, info.Ticket, i, action)
			if err != nil {
				return nil, fmt.Errorf("anchor %q ruleset %d #%d: %w", anchor, action, i, err)
			}
			out = append(out, Rule{
				Anchor:  anchor,
				Ruleset: action,
				Nr:      i,
				Text:    text,
			})
		}
	}
	return out, nil
}

// defaultShowActions are the rulesets pfctl -sr walks (scrub then filter).
var defaultShowActions = []uint32{ActionScrub, ActionPass}

// ListRules returns rules for a single anchor path ("" = main ruleset).
func (h *Handle) ListRules(anchor string) ([]Rule, error) {
	return h.listRulesIn(anchor, defaultShowActions)
}

// ListAllRules returns rules from the main ruleset and every nested anchor.
// Unlike pfctl -sr, named anchors are always included.
func (h *Handle) ListAllRules() ([]Rule, error) {
	var out []Rule
	main, err := h.ListRules("")
	if err != nil {
		return nil, err
	}
	out = append(out, main...)

	anchors, err := h.AllAnchors()
	if err != nil {
		return nil, err
	}
	for _, a := range anchors {
		rs, err := h.ListRules(a)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}
