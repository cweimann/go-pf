//go:build freebsd

/*
 * Fetch one PF rule via DIOCGETRULENV and format it similarly to pfctl -sr.
 * Linked from rule_nv.go (cgo).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/nv.h>
#include <sys/types.h>
#include <unistd.h>

static int
sb_printf(char **buf, size_t *len, size_t *cap, const char *fmt, ...)
{
	va_list ap;
	int n;
	char scratch[512];

	va_start(ap, fmt);
	n = vsnprintf(scratch, sizeof(scratch), fmt, ap);
	va_end(ap);
	if (n < 0)
		return (-1);
	if ((size_t)n >= sizeof(scratch))
		n = sizeof(scratch) - 1;
	if (*len + (size_t)n + 1 > *cap) {
		size_t ncap = *cap ? *cap * 2 : 256;
		while (ncap < *len + (size_t)n + 1)
			ncap *= 2;
		char *nb = realloc(*buf, ncap);
		if (nb == NULL)
			return (-1);
		*buf = nb;
		*cap = ncap;
	}
	memcpy(*buf + *len, scratch, (size_t)n);
	*len += (size_t)n;
	(*buf)[*len] = '\0';
	return (0);
}

static int
do_ioctl_nv(int dev, unsigned long cmd, size_t size, nvlist_t **nvl)
{
	struct pfioc_nv nv;
	void *data;
	size_t nvlen;
	int ret;

	data = nvlist_pack(*nvl, &nvlen);
	if (data == NULL)
		return (ENOMEM);
	if (nvlen > size)
		size = nvlen;
retry:
	nv.data = malloc(size);
	if (nv.data == NULL) {
		free(data);
		return (ENOMEM);
	}
	memcpy(nv.data, data, nvlen);
	nv.len = nvlen;
	nv.size = size;
	ret = ioctl(dev, cmd, &nv);
	if (ret == -1 && errno == ENOSPC) {
		size *= 2;
		free(nv.data);
		goto retry;
	}
	nvlist_destroy(*nvl);
	*nvl = NULL;
	if (ret == 0) {
		*nvl = nvlist_unpack(nv.data, nv.len, 0);
		ret = (*nvl == NULL) ? EIO : 0;
	} else {
		ret = errno;
	}
	free(data);
	free(nv.data);
	return (ret);
}

static int
mask_bits(const uint8_t *mask, int maxbytes)
{
	int bits = 0, i, b;

	for (i = 0; i < maxbytes; i++) {
		b = mask[i];
		while (b) {
			bits += b & 1;
			b >>= 1;
		}
	}
	return (bits);
}

static int
fmt_addr_wrap(char **buf, size_t *len, size_t *cap, const nvlist_t *aw, int af)
{
	uint64_t type = nvlist_get_number(aw, "type");
	const nvlist_t *a, *m;
	const void *ab, *mb;
	size_t alen = 0, mlen = 0;
	char as[INET6_ADDRSTRLEN];
	int bits, i, any;

	switch (type) {
	case PF_ADDR_TABLE:
		return sb_printf(buf, len, cap, "<%s>",
		    nvlist_get_string(aw, "tblname"));
	case PF_ADDR_DYNIFTL:
		return sb_printf(buf, len, cap, "(%s)",
		    nvlist_get_string(aw, "ifname"));
	case PF_ADDR_NOROUTE:
		return sb_printf(buf, len, cap, "no-route");
	case PF_ADDR_URPFFAILED:
		return sb_printf(buf, len, cap, "urpf-failed");
	case PF_ADDR_ADDRMASK:
	case PF_ADDR_RANGE:
		break;
	default:
		return sb_printf(buf, len, cap, "?");
	}

	a = nvlist_get_nvlist(aw, "addr");
	m = nvlist_get_nvlist(aw, "mask");
	ab = nvlist_get_binary(a, "addr", &alen);
	mb = nvlist_get_binary(m, "addr", &mlen);
	if (ab == NULL || mb == NULL || alen < 4 || mlen < 4)
		return sb_printf(buf, len, cap, "?");

	if (af == AF_INET || (af == 0 && alen >= 4 &&
	    (((const uint8_t *)mb)[0] | ((const uint8_t *)mb)[1] |
	     ((const uint8_t *)mb)[2] | ((const uint8_t *)mb)[3]) != 0 &&
	    alen >= 16 &&
	    ((const uint8_t *)mb)[4] == 0 && ((const uint8_t *)mb)[5] == 0)) {
		/* prefer IPv4 when af says so, or mask looks v4-only */
	}

	if (af == AF_INET6) {
		struct in6_addr ia6, im6;
		memcpy(&ia6, ab, 16);
		memcpy(&im6, mb, 16);
		inet_ntop(AF_INET6, &ia6, as, sizeof(as));
		bits = mask_bits(im6.s6_addr, 16);
		any = 1;
		for (i = 0; i < 16; i++)
			if (ia6.s6_addr[i])
				any = 0;
		if (any && bits == 0)
			return sb_printf(buf, len, cap, "any");
		if (bits == 128)
			return sb_printf(buf, len, cap, "%s", as);
		return sb_printf(buf, len, cap, "%s/%d", as, bits);
	}

	/* AF_INET or unspecified: try v4 first if high mask bytes empty */
	if (af == AF_INET || af == 0) {
		struct in_addr ia, im;
		int v6mask = 0;
		if (mlen >= 16) {
			for (i = 4; i < 16; i++)
				if (((const uint8_t *)mb)[i])
					v6mask = 1;
		}
		if (!v6mask || af == AF_INET) {
			memcpy(&ia, ab, 4);
			memcpy(&im, mb, 4);
			inet_ntop(AF_INET, &ia, as, sizeof(as));
			bits = mask_bits((const uint8_t *)&im, 4);
			if (ia.s_addr == 0 && bits == 0)
				return sb_printf(buf, len, cap, "any");
			if (bits == 32)
				return sb_printf(buf, len, cap, "%s", as);
			return sb_printf(buf, len, cap, "%s/%d", as, bits);
		}
		/* fall through to v6 */
		struct in6_addr ia6, im6;
		memcpy(&ia6, ab, 16);
		memcpy(&im6, mb, 16);
		inet_ntop(AF_INET6, &ia6, as, sizeof(as));
		bits = mask_bits(im6.s6_addr, 16);
		any = 1;
		for (i = 0; i < 16; i++)
			if (ia6.s6_addr[i])
				any = 0;
		if (any && bits == 0)
			return sb_printf(buf, len, cap, "any");
		if (bits == 128)
			return sb_printf(buf, len, cap, "%s", as);
		return sb_printf(buf, len, cap, "%s/%d", as, bits);
	}

	return sb_printf(buf, len, cap, "?");
}

static int
fmt_ports(char **buf, size_t *len, size_t *cap, const nvlist_t *ra)
{
	uint64_t pop;
	size_t nitems = 0;
	const uint64_t *ports;
	uint16_t p0, p1;

	pop = nvlist_get_number(ra, "port_op");
	if (pop == PF_OP_NONE)
		return (0);
	if (!nvlist_exists_number_array(ra, "port"))
		return (0);
	ports = nvlist_get_number_array(ra, "port", &nitems);
	if (ports == NULL || nitems < 1)
		return (0);
	/* values are the on-wire uint16 (network byte order) widened */
	p0 = ntohs((uint16_t)ports[0]);
	p1 = nitems > 1 ? ntohs((uint16_t)ports[1]) : 0;
	switch (pop) {
	case PF_OP_EQ:
		return sb_printf(buf, len, cap, " port = %u", p0);
	case PF_OP_NE:
		return sb_printf(buf, len, cap, " port != %u", p0);
	case PF_OP_LT:
		return sb_printf(buf, len, cap, " port < %u", p0);
	case PF_OP_LE:
		return sb_printf(buf, len, cap, " port <= %u", p0);
	case PF_OP_GT:
		return sb_printf(buf, len, cap, " port > %u", p0);
	case PF_OP_GE:
		return sb_printf(buf, len, cap, " port >= %u", p0);
	case PF_OP_IRG:
		return sb_printf(buf, len, cap, " port %u >< %u", p0, p1);
	case PF_OP_XRG:
		return sb_printf(buf, len, cap, " port %u <> %u", p0, p1);
	case PF_OP_RRG:
		return sb_printf(buf, len, cap, " port %u:%u", p0, p1);
	default:
		return (0);
	}
}

static int
addr_wrap_is_any(const nvlist_t *aw, int af)
{
	uint64_t type;
	const nvlist_t *a, *m;
	const void *ab, *mb;
	size_t alen = 0, mlen = 0;
	int i;

	type = nvlist_get_number(aw, "type");
	if (type != PF_ADDR_ADDRMASK)
		return (0);
	a = nvlist_get_nvlist(aw, "addr");
	m = nvlist_get_nvlist(aw, "mask");
	ab = nvlist_get_binary(a, "addr", &alen);
	mb = nvlist_get_binary(m, "addr", &mlen);
	if (ab == NULL || mb == NULL)
		return (0);
	for (i = 0; i < (int)alen && i < 16; i++)
		if (((const uint8_t *)ab)[i] || ((const uint8_t *)mb)[i])
			return (0);
	(void)af;
	return (1);
}

static int
rule_addr_is_any(const nvlist_t *ra, int af)
{
	return addr_wrap_is_any(nvlist_get_nvlist(ra, "addr"), af);
}

static int
fmt_rule_addr(char **buf, size_t *len, size_t *cap, const nvlist_t *ra,
    int af, const char *which)
{
	uint64_t neg = nvlist_get_number(ra, "neg");

	if (sb_printf(buf, len, cap, " %s ", which) != 0)
		return (-1);
	if (neg && sb_printf(buf, len, cap, "! ") != 0)
		return (-1);
	if (fmt_addr_wrap(buf, len, cap, nvlist_get_nvlist(ra, "addr"), af) != 0)
		return (-1);
	return fmt_ports(buf, len, cap, ra);
}

static void
fmt_tcp_flags(char **buf, size_t *len, size_t *cap, uint64_t flags,
    uint64_t flagset)
{
	static const struct { int bit; char ch; } map[] = {
		{ TH_FIN, 'F' }, { TH_SYN, 'S' }, { TH_RST, 'R' },
		{ TH_PUSH, 'P' }, { TH_ACK, 'A' }, { TH_URG, 'U' },
	};
	char fbuf[8], sbuf[8];
	size_t fi = 0, si = 0;
	size_t i;

	if (flagset == 0)
		return;
	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		if (flags & map[i].bit)
			fbuf[fi++] = map[i].ch;
		if (flagset & map[i].bit)
			sbuf[si++] = map[i].ch;
	}
	fbuf[fi] = '\0';
	sbuf[si] = '\0';
	sb_printf(buf, len, cap, " flags %s/%s", fbuf, sbuf);
}

static const char *
proto_name(uint64_t proto)
{
	switch (proto) {
	case IPPROTO_ICMP: return "icmp";
	case IPPROTO_TCP: return "tcp";
	case IPPROTO_UDP: return "udp";
	case IPPROTO_GRE: return "gre";
	case IPPROTO_ESP: return "esp";
	case IPPROTO_AH: return "ah";
	case IPPROTO_ICMPV6: return "ipv6-icmp";
	default: return NULL;
	}
}

/* Exported to cgo: returns malloc'd string; caller frees. NULL on error (*errp set). */
char *
gopf_format_rule(int fd, const char *anchor, uint32_t ticket, uint32_t nr,
    uint32_t ruleset, int *errp)
{
	nvlist_t *nvl;
	const nvlist_t *rule;
	const char *anchor_call, *ifname, *label;
	char *buf = NULL;
	size_t len = 0, cap = 0;
	uint64_t action, dir, af, proto, quick, logv, keep, ifnot;
	uint64_t flags, flagset, rflag;
	static const char *acts[] = {
		"pass", "block", "scrub", "no scrub", "nat", "no nat",
		"binat", "no binat", "rdr", "no rdr", "", "", "match"
	};
	int error;

	if (errp)
		*errp = 0;

	nvl = nvlist_create(0);
	if (nvl == NULL) {
		if (errp) *errp = ENOMEM;
		return (NULL);
	}
	nvlist_add_number(nvl, "nr", nr);
	nvlist_add_number(nvl, "ticket", ticket);
	nvlist_add_string(nvl, "anchor", anchor ? anchor : "");
	nvlist_add_number(nvl, "ruleset", ruleset);

	error = do_ioctl_nv(fd, DIOCGETRULENV, 8192, &nvl);
	if (error != 0) {
		if (errp) *errp = error;
		nvlist_destroy(nvl);
		return (NULL);
	}

	rule = nvlist_get_nvlist(nvl, "rule");
	anchor_call = nvlist_exists_string(nvl, "anchor_call") ?
	    nvlist_get_string(nvl, "anchor_call") : "";
	action = nvlist_get_number(rule, "action");
	dir = nvlist_get_number(rule, "direction");
	af = nvlist_get_number(rule, "af");
	proto = nvlist_get_number(rule, "proto");
	quick = nvlist_get_number(rule, "quick");
	logv = nvlist_get_number(rule, "log");
	keep = nvlist_get_number(rule, "keep_state");
	ifnot = nvlist_get_number(rule, "ifnot");
	flags = nvlist_get_number(rule, "flags");
	flagset = nvlist_get_number(rule, "flagset");
	rflag = nvlist_get_number(rule, "rule_flag");
	ifname = nvlist_get_string(rule, "ifname");
	label = nvlist_exists_string(rule, "label") ?
	    nvlist_get_string(rule, "label") : "";

	if (anchor_call[0]) {
		sb_printf(&buf, &len, &cap, "anchor \"%s\"", anchor_call);
	} else if (action <= 12 && acts[action][0]) {
		sb_printf(&buf, &len, &cap, "%s", acts[action]);
	} else {
		sb_printf(&buf, &len, &cap, "action(%llu)",
		    (unsigned long long)action);
	}

	if (action == PF_DROP) {
		if (rflag & PFRULE_RETURN)
			sb_printf(&buf, &len, &cap, " return");
		else if (rflag & PFRULE_RETURNRST)
			sb_printf(&buf, &len, &cap, " return-rst");
		else if (rflag & PFRULE_RETURNICMP)
			sb_printf(&buf, &len, &cap, " return-icmp");
		else
			sb_printf(&buf, &len, &cap, " drop");
	}
	if (dir == PF_IN)
		sb_printf(&buf, &len, &cap, " in");
	else if (dir == PF_OUT)
		sb_printf(&buf, &len, &cap, " out");
	if (logv)
		sb_printf(&buf, &len, &cap, " log");
	if (quick)
		sb_printf(&buf, &len, &cap, " quick");
	if (ifname[0]) {
		if (ifnot)
			sb_printf(&buf, &len, &cap, " on ! %s", ifname);
		else
			sb_printf(&buf, &len, &cap, " on %s", ifname);
	}
	if (af == AF_INET)
		sb_printf(&buf, &len, &cap, " inet");
	else if (af == AF_INET6)
		sb_printf(&buf, &len, &cap, " inet6");
	if (proto) {
		const char *pn = proto_name(proto);
		if (pn)
			sb_printf(&buf, &len, &cap, " proto %s", pn);
		else
			sb_printf(&buf, &len, &cap, " proto %llu",
			    (unsigned long long)proto);
	}
	{
		const nvlist_t *src = nvlist_get_nvlist(rule, "src");
		const nvlist_t *dst = nvlist_get_nvlist(rule, "dst");
		int src_any = rule_addr_is_any(src, (int)af);
		int dst_any = rule_addr_is_any(dst, (int)af);

		if (src_any && dst_any &&
		    nvlist_get_number(src, "port_op") == PF_OP_NONE &&
		    nvlist_get_number(dst, "port_op") == PF_OP_NONE &&
		    nvlist_get_number(src, "neg") == 0 &&
		    nvlist_get_number(dst, "neg") == 0) {
			sb_printf(&buf, &len, &cap, " all");
		} else {
			fmt_rule_addr(&buf, &len, &cap, src, (int)af, "from");
			fmt_rule_addr(&buf, &len, &cap, dst, (int)af, "to");
		}
	}
	if (proto == IPPROTO_TCP)
		fmt_tcp_flags(&buf, &len, &cap, flags, flagset);
	if (keep == PF_STATE_NORMAL)
		sb_printf(&buf, &len, &cap, " keep state");
	else if (keep == PF_STATE_MODULATE)
		sb_printf(&buf, &len, &cap, " modulate state");
	else if (keep == PF_STATE_SYNPROXY)
		sb_printf(&buf, &len, &cap, " synproxy state");
	if (label[0])
		sb_printf(&buf, &len, &cap, " label \"%s\"", label);

	nvlist_destroy(nvl);
	if (buf == NULL) {
		buf = strdup("");
		if (buf == NULL && errp)
			*errp = ENOMEM;
	}
	return (buf);
}
