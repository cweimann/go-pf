//go:build freebsd

package pf

// Constants and structures matching FreeBSD <net/pfvar.h> for table ioctls.
// Layout verified against FreeBSD 15.1 amd64 (see aiscripts/pf_ioctl_sizes.c).

const (
	DevicePath = "/dev/pf"

	maxPathLen       = 1024
	tableNameSize    = 32
	pfrTableSize      = 1064
	pfrAddrSize       = 20
	pfiocTableSize    = 1104
	pfiocRulesetSize  = 1092
	pfiocRuleSize     = 3040
	anchorNameSize    = 64
	pfiocRuleOffTicket     = 4
	pfiocRuleOffNr         = 12
	pfiocRuleOffAnchor     = 16
	pfiocRuleOffRuleAction = 2968
)

// Address families (from <sys/socket.h>).
const (
	AFInet  = 2
	AFInet6 = 28
)

// Table flags (PFR_TFLAG_*).
const (
	TFlagPersist   = 0x00000001
	TFlagConst     = 0x00000002
	TFlagActive    = 0x00000004
	TFlagInactive  = 0x00000008
	TFlagReferenced = 0x00000010
	TFlagRefdAnchor = 0x00000020
	TFlagCounters  = 0x00000040
)

// ioctl flags for radix table ops (PFR_FLAG_*).
const (
	FlagDummy    = 0x00000002
	FlagFeedback = 0x00000004
	FlagClstats  = 0x00000008
	FlagAddrstoo = 0x00000010
	FlagReplace  = 0x00000020
	FlagAllrsets = 0x00000040
)

// DIOC* table ioctls: _IOWR('D', n, struct pfioc_table) on FreeBSD amd64.
// Computed with sizeof(pfioc_table)==1104.
const (
	diocrClrTables = 0xc450443c // DIOCRCLRTABLES  ('D', 60)
	diocrAddTables = 0xc450443d // DIOCRADDTABLES  ('D', 61)
	diocrDelTables = 0xc450443e // DIOCRDELTABLES  ('D', 62)
	diocrGetTables = 0xc450443f // DIOCRGETTABLES  ('D', 63)
	diocrClrAddrs  = 0xc4504442 // DIOCRCLRADDRS   ('D', 66)
	diocrAddAddrs  = 0xc4504443 // DIOCRADDADDRS   ('D', 67)
	diocrDelAddrs  = 0xc4504444 // DIOCRDELADDRS   ('D', 68)
	diocrSetAddrs  = 0xc4504445 // DIOCRSETADDRS   ('D', 69)
	diocrGetAddrs  = 0xc4504446 // DIOCRGETADDRS   ('D', 70)

	diocGetRules    = 0xcbe04406 // DIOCGETRULES    ('D', 6)  sizeof(pfioc_rule)=3040
	diocGetRuleNV   = 0xc0184407 // DIOCGETRULENV   ('D', 7)  sizeof(pfioc_nv)=24
	diocGetRulesets = 0xc444443a // DIOCGETRULESETS ('D', 58) sizeof(pfioc_ruleset)=1092
	diocGetRuleset  = 0xc444443b // DIOCGETRULESET  ('D', 59)
)

// Rule action / ruleset selectors (enum in pf.h).
const (
	ActionPass   = 0
	ActionDrop   = 1
	ActionScrub  = 2
	ActionNoScrub = 3
	ActionNat    = 4
	ActionNoNat  = 5
	ActionBinat  = 6
	ActionNoBinat = 7
	ActionRdr    = 8
	ActionNoRdr  = 9
	ActionMatch  = 12
)

// pfrTable is struct pfr_table.
type pfrTable struct {
	Anchor [maxPathLen]byte
	Name   [tableNameSize]byte
	Flags  uint32
	Fback  uint8
	_pad   [3]byte
}

// pfrAddr is struct pfr_addr.
type pfrAddr struct {
	Addr  [16]byte // IPv4 in first 4 bytes, or full IPv6
	AF    uint8
	Net   uint8
	Not   uint8
	Fback uint8
}

// pfiocTable is struct pfioc_table. C int fields are int32 on FreeBSD.
type pfiocTable struct {
	Table   pfrTable
	Buffer  uintptr
	Esize   int32
	Size    int32
	Size2   int32
	Nadd    int32
	Ndel    int32
	Nchange int32
	Flags   int32
	Ticket  uint32
}
