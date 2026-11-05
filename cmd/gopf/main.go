// Command gopf is a small FreeBSD PF table management CLI.
package main

import (
	"fmt"
	"os"
	"strings"

	"k12usa.com/go-pf/pf"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	h, err := pf.Open()
	if err != nil {
		fatal(err)
	}
	defer h.Close()

	switch os.Args[1] {
	case "tables":
		cmdTables(h)
	case "table":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		cmdTable(h, os.Args[2], os.Args[3:])
	case "show":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		cmdShow(h, os.Args[2], os.Args[3:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func cmdTables(h *pf.Handle) {
	tables, err := h.ListTables()
	if err != nil {
		fatal(err)
	}
	for _, t := range tables {
		if t.Anchor != "" {
			fmt.Printf("%s@%s\n", t.Anchor, t.Name)
		} else {
			fmt.Println(t.Name)
		}
	}
}

func cmdTable(h *pf.Handle, name string, args []string) {
	if len(args) == 0 {
		listAddrs(h, name)
		return
	}
	switch args[0] {
	case "show", "list":
		listAddrs(h, name)
	case "add":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: gopf table NAME add ADDR..."))
		}
		addrs, err := parseAddrs(args[1:])
		if err != nil {
			fatal(err)
		}
		n, err := h.AddAddrs(name, addrs)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("added %d\n", n)
	case "delete", "del", "remove", "rm":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: gopf table NAME delete ADDR..."))
		}
		addrs, err := parseAddrs(args[1:])
		if err != nil {
			fatal(err)
		}
		n, err := h.DeleteAddrs(name, addrs)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("deleted %d\n", n)
	case "clear":
		n, err := h.ClearAddrs(name)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("cleared %d\n", n)
	case "replace", "set":
		addrs, err := addrsFromArgs(args[1:])
		if err != nil {
			fatal(err)
		}
		a, d, c, err := h.SetAddrs(name, addrs)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("added %d deleted %d changed %d\n", a, d, c)
	case "load":
		if len(args) != 2 {
			fatal(fmt.Errorf("usage: gopf table NAME load FILE"))
		}
		a, d, c, err := h.SetAddrsFile(name, args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Printf("added %d deleted %d changed %d\n", a, d, c)
	case "create":
		if err := h.AddTable(name); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	case "destroy":
		if err := h.DeleteTable(name); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	default:
		fatal(fmt.Errorf("unknown table subcommand %q", args[0]))
	}
}

func listAddrs(h *pf.Handle, name string) {
	addrs, err := h.ListAddrs(name)
	if err != nil {
		fatal(err)
	}
	for _, a := range addrs {
		fmt.Println(a.String())
	}
}

func cmdShow(h *pf.Handle, what string, args []string) {
	switch what {
	case "rules", "rule":
		cmdShowRules(h, args)
	case "anchors", "anchor":
		anchors, err := h.AllAnchors()
		if err != nil {
			fatal(err)
		}
		for _, a := range anchors {
			fmt.Println(a)
		}
	default:
		fatal(fmt.Errorf("unknown show target %q (try: rules, anchors)", what))
	}
}

func cmdShowRules(h *pf.Handle, args []string) {
	var (
		rules []pf.Rule
		err   error
	)
	if len(args) == 0 {
		rules, err = h.ListAllRules()
	} else {
		anchor := args[0]
		if anchor == "/" || anchor == "*" {
			anchor = ""
		}
		rules, err = h.ListRules(anchor)
	}
	if err != nil {
		fatal(err)
	}

	cur := "\x00" // impossible path
	for _, r := range rules {
		if r.Anchor != cur {
			cur = r.Anchor
			if cur == "" {
				fmt.Println("# main ruleset")
			} else {
				fmt.Printf("\n# anchor %s\n", cur)
			}
		}
		fmt.Println(r.Text)
	}
}

func parseAddrs(args []string) ([]pf.Addr, error) {
	out := make([]pf.Addr, 0, len(args))
	for _, s := range args {
		for _, part := range strings.Fields(s) {
			a, err := pf.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// addrsFromArgs accepts either ADDR... or -f FILE (FILE may be "-" for stdin).
func addrsFromArgs(args []string) ([]pf.Addr, error) {
	if len(args) >= 1 && (args[0] == "-f" || args[0] == "--file") {
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: replace -f FILE")
		}
		if args[1] == "-" {
			return pf.ParseAddrsReader(os.Stdin)
		}
		return pf.ParseAddrsFile(args[1])
	}
	return parseAddrs(args)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  gopf tables
  gopf table NAME [show]
  gopf table NAME create
  gopf table NAME destroy
  gopf table NAME add ADDR...
  gopf table NAME delete ADDR...
  gopf table NAME clear
  gopf table NAME replace [ADDR...]
  gopf table NAME replace -f FILE
  gopf table NAME load FILE    # same as replace -f FILE

  gopf show rules              # main + all anchors (unlike pfctl -sr)
  gopf show rules [ANCHOR]     # one ruleset only ("" or * = main)
  gopf show anchors

ADDR may be an IP or CIDR, optionally prefixed with '!'.
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gopf: %v\n", err)
	os.Exit(1)
}
