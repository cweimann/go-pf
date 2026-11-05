# go-pf

Go library and CLI to control [PF](https://man.freebsd.org/cgi/man.cgi?query=pf&sektion=4) on FreeBSD through `/dev/pf` ioctls.

The main goal is table management (list / add / delete addresses) without needing [pftabled](https://github.com/awaw/pftabled). Broader ioctl coverage can grow over time.

Requires FreeBSD (built and layout-checked against 15.1; should work on 14.2). Needs permission to open `/dev/pf` (usually root).

## Library

```go
package main

import (
	"fmt"
	"log"

	"k12usa.com/go-pf/pf"
)

func main() {
	h, err := pf.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	tables, err := h.ListTables()
	if err != nil {
		log.Fatal(err)
	}
	for _, t := range tables {
		fmt.Println(t.Name)
	}

	addr, _ := pf.ParseAddr("203.0.113.10")
	if _, err := h.AddAddrs("blockedsites", []pf.Addr{addr}); err != nil {
		log.Fatal(err)
	}
}
```

Useful methods on `*pf.Handle`:

| Method | IOCTL |
| --- | --- |
| `ListTables` | `DIOCRGETTABLES` |
| `AddTable` / `AddTables` | `DIOCRADDTABLES` |
| `DeleteTable` / `DeleteTables` | `DIOCRDELTABLES` |
| `ListAddrs` | `DIOCRGETADDRS` |
| `AddAddrs` | `DIOCRADDADDRS` |
| `DeleteAddrs` | `DIOCRDELADDRS` |
| `ClearAddrs` | `DIOCRCLRADDRS` |
| `SetAddrs` | `DIOCRSETADDRS` |
| `ChildAnchors` / `AllAnchors` | `DIOCGETRULESETS` / `DIOCGETRULESET` |
| `ListRules` / `ListAllRules` | `DIOCGETRULES` + `DIOCGETRULENV` |

## CLI

```sh
go install k12usa.com/go-pf/cmd/gopf@latest   # or: go build -o gopf ./cmd/gopf

gopf tables
gopf table NAME                 # list addresses
gopf table NAME create
gopf table NAME destroy
gopf table NAME add ADDR...
gopf table NAME delete ADDR...
gopf table NAME clear
gopf table NAME replace [ADDR...]
gopf table NAME replace -f FILE
gopf table NAME load FILE

gopf show rules              # main ruleset + every nested anchor
gopf show rules ANCHOR       # one ruleset only
gopf show anchors
```

`ADDR` is an IP or CIDR, optionally prefixed with `!`.

`gopf show rules` always walks named anchors. That is the gap versus plain `pfctl -sr`, which only expands unnamed/inline anchors unless you pass `-a '…/*'`.
