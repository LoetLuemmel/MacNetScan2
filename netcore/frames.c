/* frames.c - the dissector behind the Frames view: a captured frame (NC_Frame, netcore.c) as one summary line for
   the packet list and as the lines of its protocol tree. Its own file and segment: netcore.c alone came within
   2 KB of the 32 KB a 68K segment holds. Reads only the frame; no Open Transport calls. Plain C, 68K. */

#include "OTCompat.h"
#include <OpenTransport.h>
#include "netcore.h"

static void UToStr(unsigned long n, char *s)
{
	char t[16];
	short i = 0, j = 0;
	if (n == 0) { s[0] = '0'; s[1] = 0; return; }
	while (n > 0) { t[i++] = (char) ('0' + (n % 10)); n /= 10; }
	while (i > 0) s[j++] = t[--i];
	s[j] = 0;
}

static void StrCat(char *dst, const char *src)
{
	short i = 0, j = 0;
	while (dst[i]) i++;
	while (src[j]) dst[i++] = src[j++];
	dst[i] = 0;
}

static UInt16 Get16(const UInt8 *p) { return (UInt16) ((p[0] << 8) | p[1]); }
static UInt32 Get32(const UInt8 *p) { return ((UInt32) p[0] << 24) | ((UInt32) p[1] << 16) | ((UInt32) p[2] << 8) | p[3]; }

static void CatNum(char *s, unsigned long v) { char nb[12]; UToStr(v, nb); StrCat(s, nb); }

static void CatHex(char *s, unsigned long v, short digits)
{
	static const char hx[] = "0123456789abcdef";
	while (*s) s++;
	while (digits--) *s++ = hx[(v >> (4 * digits)) & 15];
	*s = 0;
}

static void CatIP4(char *s, const UInt8 *p) { char t[20]; NC_IPToStr(Get32(p), t); StrCat(s, t); }
static void CatMAC(char *s, const UInt8 *p) { char t[20]; NC_MACToStr(p, t); StrCat(s, t); }

static void CatIP6(char *s, const UInt8 *p)						/* the longest run of zero groups as "::" */
{
	short i, start, run, best = -1, bestLen = 0;
	for (i = 0; i < 8; ) {
		if (Get16(p + 2 * i) != 0) { i++; continue; }
		start = i;
		while (i < 8 && Get16(p + 2 * i) == 0) i++;
		run = (short) (i - start);
		if (run > 1 && run > bestLen) { best = start; bestLen = run; }
	}
	for (i = 0; i < 8; i++) {
		UInt16 g = Get16(p + 2 * i);
		if (i == best) { StrCat(s, "::"); i = (short) (i + bestLen - 1); continue; }
		if (i > 0 && i != best + bestLen) StrCat(s, ":");
		CatHex(s, g, (short) (g >= 0x1000 ? 4 : g >= 0x100 ? 3 : g >= 0x10 ? 2 : 1));
	}
}

static void CatAT(char *s, const UInt8 *net, UInt8 node, short socket)	/* "3.79:4", node 255 the broadcast */
{
	CatNum(s, Get16(net)); StrCat(s, ".");
	if (node == 255) StrCat(s, "bcast"); else CatNum(s, node);
	if (socket >= 0) { StrCat(s, ":"); CatNum(s, (unsigned long) socket); }
}

static const char *UdpName(UInt16 port)
{
	switch (port) {
		case 53:	return "DNS";
		case 67: case 68: return "DHCP";
		case 123:	return "NTP";
		case 137:	return "NBNS";
		case 138:	return "NBDGM";
		case 1900:	return "SSDP";
		case 5353:	return "mDNS";
		case 5355:	return "LLMNR";
	}
	return NULL;
}

static const char *DnsType(UInt16 t)
{
	switch (t) {
		case 1: return "A"; case 2: return "NS"; case 5: return "CNAME"; case 12: return "PTR"; case 13: return "HINFO";
		case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV"; case 47: return "NSEC"; case 255: return "ANY";
	}
	return "?";
}

	/* a DNS name at off, with compression; the bytes it takes at off, -1 if broken */
static long DnsName(const UInt8 *m, long n, long off, char *out, short max)
{
	long p = off, used = -1;
	short o = 0, jumps = 0, i;
	out[0] = 0;
	while (p < n) {
		UInt8 len = m[p];
		if (len == 0) { if (used < 0) used = p + 1 - off; break; }
		if ((len & 0xC0) == 0xC0) {
			if (p + 1 >= n || ++jumps > 8) return -1;
			if (used < 0) used = p + 2 - off;
			p = ((long) (len & 0x3F) << 8) | m[p + 1];
			continue;
		}
		if (p + 1 + len > n) return -1;
		if (o > 0 && o < max - 1) out[o++] = '.';
		for (i = 0; i < len && o < max - 1; i++) out[o++] = (char) (m[p + 1 + i] >= ' ' && m[p + 1 + i] < 127 ? m[p + 1 + i] : '?');
		p += 1 + len;
	}
	out[o] = 0;
	return used;
}

	/* the summary of a DNS or mDNS message: query or response, the first name and type */
static void DnsInfo(const UInt8 *m, long n, char *info)
{
	char name[48];
	long off;
	UInt16 qd, an;
	if (n < 12) return;
	qd = Get16(m + 4); an = Get16(m + 6);
	StrCat(info, (m[2] & 0x80) ? "Response" : "Query");
	off = 12;
	if (qd > 0 && DnsName(m, n, off, name, sizeof(name)) > 0) {
		off += DnsName(m, n, off, name, sizeof(name));
		StrCat(info, " "); StrCat(info, off + 2 <= n ? DnsType(Get16(m + off)) : "?"); StrCat(info, " "); StrCat(info, name);
		off += 4;
	} else if (an > 0 && DnsName(m, n, off, name, sizeof(name)) > 0) {
		long u = DnsName(m, n, off, name, sizeof(name));
		StrCat(info, " "); StrCat(info, name);
		if (off + u + 2 <= n) { StrCat(info, " "); StrCat(info, DnsType(Get16(m + off + u))); }
		if (off + u + 10 <= n && Get16(m + off + u) == 1 && Get16(m + off + u + 8) == 4 && off + u + 14 <= n) {
			StrCat(info, " "); CatIP4(info, m + off + u + 10);
		}
	}
}

static const char *DhcpType(UInt8 t)
{
	switch (t) {
		case 1: return "Discover"; case 2: return "Offer"; case 3: return "Request"; case 4: return "Decline";
		case 5: return "ACK"; case 6: return "NAK"; case 7: return "Release"; case 8: return "Inform";
	}
	return "?";
}

	/* the DHCP option code at the BOOTP payload p (after the magic cookie), or NULL */
static const UInt8 *DhcpOpt(const UInt8 *p, long n, UInt8 code, short *len)
{
	long o = 240;
	if (n < 240 || Get32(p + 236) != 0x63825363UL) return NULL;
	while (o + 2 <= n && p[o] != 255) {
		if (p[o] == 0) { o++; continue; }
		if (p[o] == code && o + 2 + p[o + 1] <= n) { *len = p[o + 1]; return p + o + 2; }
		o += 2 + p[o + 1];
	}
	return NULL;
}

static const char *IcmpName(UInt8 t)
{
	switch (t) {
		case 0: return "Echo reply"; case 3: return "Destination unreachable"; case 5: return "Redirect";
		case 8: return "Echo request"; case 11: return "Time exceeded";
	}
	return "ICMP";
}

static const char *Icmp6Name(UInt8 t)
{
	switch (t) {
		case 1: return "Destination unreachable"; case 3: return "Time exceeded";
		case 128: return "Echo request"; case 129: return "Echo reply";
		case 133: return "Router solicitation"; case 134: return "Router advertisement";
		case 135: return "Neighbor solicitation"; case 136: return "Neighbor advertisement";
		case 143: return "MLDv2 report";
	}
	return "ICMPv6";
}

static const char *DdpName(UInt8 t)
{
	switch (t) {
		case 1: return "RTMP"; case 2: return "NBP"; case 3: return "ATP"; case 4: return "AEP";
		case 5: return "RTMP Request"; case 6: return "ZIP"; case 7: return "ADSP";
	}
	return "DDP";
}

	/* the first NBP tuple: "object:type@zone" */
static void NbpTuple(const UInt8 *p, long n, char *s)
{
	long o = 2 + 5;
	short part, i;
	for (part = 0; part < 3 && o < n; part++) {
		UInt8 len = p[o++];
		if (part == 1) StrCat(s, ":");
		if (part == 2) StrCat(s, "@");
		for (i = 0; i < len && o < n; i++, o++) { char c[2]; c[0] = (char) (p[o] >= ' ' && p[o] < 127 ? p[o] : '?'); c[1] = 0; StrCat(s, c); }
	}
}

/* ------------------------------------------------------------------ AppleTalk above DDP */

	/* a Pascal string (a zone, a server name) onto s, printable characters only, s kept below limit bytes */
static void CatPas(char *s, const UInt8 *p, long n, short limit)
{
	short len, i, o = 0;
	if (n < 1) return;
	len = p[0];
	while (s[o]) o++;
	for (i = 0; i < len && i + 1 < n && o < limit - 1; i++) s[o++] = (char) (p[1 + i] >= ' ' && p[1 + i] < 127 ? p[1 + i] : '?');
	s[o] = 0;
}

	/* a 32-bit field as a signed number - also where long is 64 bits (the host test) */
static long Signed32(UInt32 v)
{
	v &= 0xFFFFFFFFUL;
	return (v & 0x80000000UL) ? -(long) ((~v & 0xFFFFFFFFUL) + 1) : (long) v;
}

static long Signed16(UInt16 v) { return (v & 0x8000) ? -((long) (UInt16) ~v + 1L) : (long) v; }

static void CatSigned(char *s, long v)
{
	if (v < 0) { StrCat(s, "-"); CatNum(s, (unsigned long) -v); } else CatNum(s, (unsigned long) v);
}

static const char *AspName(UInt8 fn)
{
	static const char *k[] = { "?", "CloseSess", "Command", "GetStatus", "OpenSess", "Tickle", "Write", "WriteContinue", "Attention" };
	return fn <= 8 ? k[fn] : "?";
}

	/* AFP 2.x command codes, as the first byte of an ASP Command or Write */
static const char *AfpName(UInt8 c)
{
	static const char *k[] = { "?", "ByteRangeLock", "CloseVol", "CloseDir", "CloseFork", "CopyFile", "CreateDir",
		"CreateFile", "Delete", "Enumerate", "Flush", "FlushFork", "?", "?", "GetForkParms", "GetSrvrInfo",
		"GetSrvrParms", "GetVolParms", "Login", "LoginCont", "Logout", "MapID", "MapName", "MoveAndRename",
		"OpenVol", "OpenDir", "OpenFork", "Read", "Rename", "SetDirParms", "SetFileParms", "SetForkParms",
		"SetVolParms", "Write", "GetFileDirParms", "SetFileDirParms", "ChangePassword", "GetUserInfo",
		"GetSrvrMsg", "CreateID", "DeleteID", "ResolveID", "ExchangeFiles", "CatSearch" };
	static const char *d[] = { "OpenDT", "CloseDT", "?", "GetIcon", "GetIconInfo", "AddAPPL", "RemoveAPPL",
		"GetAPPL", "AddComment", "RemoveComment", "GetComment" };
	if (c <= 43) return k[c];
	if (c >= 48 && c <= 58) return d[c - 48];
	if (c == 192) return "AddIcon";
	return "?";
}

	/* an AFP result code by name, the common ones; NULL for the rest */
static const char *AfpErr(long e)
{
	switch (e) {
		case 0:		return "ok";
		case -5000:	return "AccessDenied";
		case -5001:	return "AuthContinue";
		case -5002:	return "BadUAM";
		case -5003:	return "BadVersNum";
		case -5006:	return "DenyConflict";
		case -5007:	return "DirNotEmpty";
		case -5008:	return "DiskFull";
		case -5009:	return "EOFErr";
		case -5010:	return "FileBusy";
		case -5013:	return "ItemNotFound";
		case -5014:	return "LockErr";
		case -5015:	return "MiscErr";
		case -5017:	return "ObjectExists";
		case -5018:	return "ObjectNotFound";
		case -5019:	return "ParamErr";
		case -5023:	return "UserNotAuth";
		case -5024:	return "CallNotSupported";
		case -5025:	return "ObjectTypeErr";
		case -5028:	return "ServerGoingDown";
	}
	return NULL;
}

static void CatAfpResult(char *s, long e)
{
	const char *nm = AfpErr(e);
	if (nm) StrCat(s, nm);
	if (e != 0) { StrCat(s, nm ? " (" : "error "); CatSigned(s, e); if (nm) StrCat(s, ")"); }
}

	/* ZIP's functions: over DDP (1-8), and the ATP requests to socket 6 (7-9, a different numbering) */
static const char *ZipName(UInt8 fn, short atp)
{
	static const char *k[] = { "?", "Query", "Reply", "TakeDown", "BringUp", "GetNetInfo", "GetNetInfo Reply",
		"Notify", "Extended Reply" };
	if (atp) return fn == 7 ? "GetMyZone" : fn == 8 ? "GetZoneList" : fn == 9 ? "GetLocalZones" : "?";
	return fn <= 8 ? k[fn] : "?";
}

	/* what an ATP transaction carries, from its request: ZIP to socket 6, else ASP if the first user byte is an
	   ASP function. PAP (printing) puts its function in the second user byte and can read as ASP - no state tells. */
enum { kAtpPlain = 0, kAtpZip, kAtpAsp };

static short AtpKind(const UInt8 *req)
{
	if (req[10] == 6) return kAtpZip;
	if (req[13 + 4] >= 1 && req[13 + 4] <= 8) return kAtpAsp;
	return kAtpPlain;
}

	/* the request a TResp answers: an earlier TReq with its TID, from the response's destination to its source */
static const NCFrame *AtpRequest(const NCFrame *f)
{
	const UInt8 *p = f->data;
	UInt16 tid = Get16(p + 15);
	long i, total = NC_FrameTotal();
	for (i = total - 1; i >= 0 && i >= total - NC_MAXFRAMES; i--) {
		const NCFrame *g = NC_Frame(i);
		const UInt8 *q;
		if (!g) break;
		if (g == f || g->us > f->us || g->type != 0x809B || g->caplen < 21) continue;
		q = g->data;
		if (q[12] != 3 || (q[13] >> 6) != 1 || Get16(q + 15) != tid) continue;
		if (Get16(q + 6) == Get16(p + 4) && q[9] == p[8] && q[11] == p[10] && q[8] == p[9] && q[10] == p[11]) return g;
	}
	return NULL;
}

	/* the bytes of ATP data, from DDP's length: Open Transport's frame length counts Ethernet's padding too */
static long AtpData(const NCFrame *f)
{
	long l = (long) (Get16(f->data) & 0x3FF) - 21;
	return l > 0 ? l : 0;
}

	/* the summary of an ATP packet (DDP type 3) and what rides on it */
static void AtpSummary(const NCFrame *f, char *proto, char *info)
{
	const UInt8 *p = f->data, *u = p + 17, *d = p + 21;
	long dn = f->caplen - 21;
	UInt8 fn = (UInt8) (p[13] >> 6);
	const NCFrame *rq;
	proto[0] = 0;
	if (fn == 3) { StrCat(proto, "ATP"); StrCat(info, "TRel  TID "); CatNum(info, Get16(p + 15)); return; }
	rq = fn == 1 ? f : fn == 2 ? AtpRequest(f) : NULL;
	if (!rq && fn == 2 && p[11] == 6) {						/* from ZIP's socket: zones, whichever request it was */
		StrCat(proto, "ZIP"); StrCat(info, "Zone list  "); CatNum(info, Get16(u + 2)); StrCat(info, " zones");
		if (dn >= 2) { StrCat(info, "  "); CatPas(info, d, dn, 96); }
		if (u[0]) StrCat(info, "  (last)");
		return;
	}
	if (!rq) {
		long r = Signed32(Get32(u));
		StrCat(proto, "ATP"); StrCat(info, fn == 1 ? "TReq" : fn == 2 ? "TResp" : "?");
		StrCat(info, "  TID "); CatNum(info, Get16(p + 15));
		if (fn == 2) {
			if (r == 0 || AfpErr(r)) { StrCat(info, "  "); CatAfpResult(info, r); }
			StrCat(info, "  len "); CatNum(info, AtpData(f));
		}
		return;
	}
	switch (AtpKind(rq->data)) {
	case kAtpZip:
		StrCat(proto, "ZIP"); StrCat(info, ZipName(rq->data[17], 1));
		if (fn == 1) { StrCat(info, " from "); CatNum(info, Get16(u + 2)); }
		else {
			StrCat(info, " Reply  "); CatNum(info, Get16(u + 2)); StrCat(info, " zones");
			if (dn >= 2) { StrCat(info, "  "); CatPas(info, d, dn, 96); }
			if (u[0]) StrCat(info, "  (last)");
		}
		break;
	case kAtpAsp: {
		UInt8 af = rq->data[17];
		long rn = rq->caplen - 21;
		UInt8 cmd = (UInt8) (rn >= 1 ? rq->data[21] : 0);
		if ((af == 2 || af == 6) && rn >= 1) {
			StrCat(proto, "AFP"); StrCat(info, "FP"); StrCat(info, AfpName(cmd));
			if (fn == 1) { StrCat(info, "  sess "); CatNum(info, u[1]); StrCat(info, " #"); CatNum(info, Get16(u + 2)); }
			else { StrCat(info, " Reply  "); CatAfpResult(info, Signed32(Get32(u))); }
		} else {
			StrCat(proto, "ASP"); StrCat(info, AspName(af));
			if (fn == 2) StrCat(info, " Reply");
			if (af == 5 || af == 1) { StrCat(info, "  sess "); CatNum(info, fn == 1 ? u[1] : rq->data[18]); }
			if (af == 4 && fn == 2) { StrCat(info, "  sess "); CatNum(info, u[1]); StrCat(info, "  "); CatAfpResult(info, Signed16(Get16(u + 2))); }
			if (af == 3 && fn == 2 && dn >= 12) { StrCat(info, "  "); CatPas(info, d + 10, dn - 10, 96); }
		}
		break;
	}
	default:
		StrCat(proto, "ATP"); StrCat(info, fn == 1 ? "TReq" : "TResp"); StrCat(info, "  TID "); CatNum(info, Get16(p + 15));
	}
}

void NC_FrameSummary(const NCFrame *f, char *src, char *dst, char *proto, char *info)
{
	const UInt8 *p = f->data;
	long n = f->caplen;
	src[0] = dst[0] = proto[0] = info[0] = 0;
	switch (f->type) {
	case 0x0806:												/* ARP */
		StrCat(proto, "ARP");
		if (n < 28) break;
		CatIP4(src, p + 14);
		if (Get16(p + 6) == 1) {
			StrCat(dst, "Broadcast");
			if (Get32(p + 14) == Get32(p + 24)) { StrCat(info, "Gratuitous ARP for "); CatIP4(info, p + 14); }
			else { StrCat(info, "Who has "); CatIP4(info, p + 24); StrCat(info, "? Tell "); CatIP4(info, p + 14); }
		} else {
			CatIP4(dst, p + 24);
			CatIP4(info, p + 14); StrCat(info, " is at "); CatMAC(info, p + 8);
		}
		break;
	case 0x0800: {												/* IPv4 */
		short ihl;
		const UInt8 *t;
		long tn;
		if (n < 20) { StrCat(proto, "IPv4"); break; }
		ihl = (short) ((p[0] & 15) * 4);
		t = p + ihl; tn = n - ihl;
		CatIP4(src, p + 12); CatIP4(dst, p + 16);
		if (p[9] == 17 && tn >= 8) {
			UInt16 sp = Get16(t), dp = Get16(t + 2);
			const char *nm = UdpName(dp);
			if (!nm) nm = UdpName(sp);
			StrCat(proto, nm ? nm : "UDP");
			if (nm && (sp == 53 || dp == 53 || sp == 5353 || dp == 5353 || sp == 5355 || dp == 5355)) DnsInfo(t + 8, tn - 8, info);
			else if (nm && (sp == 67 || sp == 68)) {
				short l;
				const UInt8 *o = DhcpOpt(t + 8, tn - 8, 53, &l);
				StrCat(info, "DHCP "); StrCat(info, o && l >= 1 ? DhcpType(o[0]) : "?");
				o = DhcpOpt(t + 8, tn - 8, 12, &l);
				if (o) { short i; StrCat(info, " "); for (i = 0; i < l && i < 24; i++) { char c[2]; c[0] = (char) o[i]; c[1] = 0; StrCat(info, c); } }
			} else if (nm && dp == 1900 && tn > 8) {
				short i;
				for (i = 0; i < 40 && 8 + i < tn && t[8 + i] != 13; i++) { char c[2]; c[0] = (char) t[8 + i]; c[1] = 0; StrCat(info, c); }
			} else { CatNum(info, sp); StrCat(info, " > "); CatNum(info, dp); StrCat(info, "  len "); CatNum(info, Get16(t + 4) - 8); }
		} else if (p[9] == 6 && tn >= 20) {
			UInt8 fl = t[13];
			StrCat(proto, "TCP");
			CatNum(info, Get16(t)); StrCat(info, " > "); CatNum(info, Get16(t + 2)); StrCat(info, " [");
			if (fl & 0x02) StrCat(info, "SYN ");
			if (fl & 0x10) StrCat(info, "ACK ");
			if (fl & 0x01) StrCat(info, "FIN ");
			if (fl & 0x04) StrCat(info, "RST ");
			if (fl & 0x08) StrCat(info, "PSH ");
			StrCat(info, "] len "); CatNum(info, (unsigned long) (Get16(p + 2) - ihl - (t[12] >> 4) * 4));
		} else if (p[9] == 1 && tn >= 4) { StrCat(proto, "ICMP"); StrCat(info, IcmpName(t[0])); }
		else if (p[9] == 2) { StrCat(proto, "IGMP"); StrCat(info, "Membership "); if (tn >= 8) CatIP4(info, t + 4); }
		else { StrCat(proto, "IPv4"); StrCat(info, "protocol "); CatNum(info, p[9]); }
		break;
	}
	case 0x86DD: {												/* IPv6, past one hop-by-hop header */
		UInt8 nh;
		long o = 40;
		if (n < 40) { StrCat(proto, "IPv6"); break; }
		CatIP6(src, p + 8); CatIP6(dst, p + 24);
		nh = p[6];
		if (nh == 0 && n >= 42) { nh = p[40]; o = 40 + (p[41] + 1) * 8; }
		if (nh == 58 && o < n) { StrCat(proto, "ICMPv6"); StrCat(info, Icmp6Name(p[o])); }
		else if (nh == 17 && o + 8 <= n) {
			UInt16 sp = Get16(p + o), dp = Get16(p + o + 2);
			const char *nm = UdpName(dp);
			if (!nm) nm = UdpName(sp);
			StrCat(proto, nm ? nm : "UDP");
			if (nm && (sp == 5353 || dp == 5353 || sp == 53 || dp == 53 || sp == 5355 || dp == 5355)) DnsInfo(p + o + 8, n - o - 8, info);
			else { CatNum(info, sp); StrCat(info, " > "); CatNum(info, dp); }
		} else if (nh == 6 && o + 14 <= n) { StrCat(proto, "TCP"); CatNum(info, Get16(p + o)); StrCat(info, " > "); CatNum(info, Get16(p + o + 2)); }
		else { StrCat(proto, "IPv6"); StrCat(info, "next header "); CatNum(info, nh); }
		break;
	}
	case 0x88CC: {												/* LLDP */
		long o = 0;
		StrCat(proto, "LLDP"); CatMAC(src, f->src); StrCat(dst, "LLDP multicast");
		while (o + 2 <= n) {
			short t = (short) (p[o] >> 1), len = (short) (((p[o] & 1) << 8) | p[o + 1]), i;
			o += 2;
			if (t == 0 || o + len > n) break;
			if (t == 5 || t == 4) {
				StrCat(info, t == 5 ? "System " : "  Port ");
				for (i = 0; i < len && i < 24; i++) { char c[2]; c[0] = (char) (p[o + i] >= ' ' ? p[o + i] : '.'); c[1] = 0; StrCat(info, c); }
			}
			o += len;
		}
		break;
	}
	case 0x809B:												/* AppleTalk DDP, long header */
		if (n < 13) { StrCat(proto, "DDP"); break; }
		CatAT(src, p + 6, p[9], p[11]); CatAT(dst, p + 4, p[8], p[10]);
		StrCat(proto, DdpName(p[12]));
		if (p[12] == 2 && n > 15) {
			static const char *kNbpFn[] = { "?", "BrRq", "LkUp", "LkUp-Reply", "FwdReq" };
			UInt8 fn = (UInt8) (p[13] >> 4);
			StrCat(info, fn <= 4 ? kNbpFn[fn] : "?"); StrCat(info, " ");
			NbpTuple(p + 13, n - 13, info);
		} else if (p[12] == 1 && n >= 17) { StrCat(info, "Router "); CatNum(info, Get16(p + 13)); StrCat(info, "."); CatNum(info, p[16]); }
		else if (p[12] == 3 && n >= 21) AtpSummary(f, proto, info);
		else if (p[12] == 6 && n >= 14) {
			StrCat(info, ZipName(p[13], 0));
			if ((p[13] == 5 || p[13] == 6) && n >= 20) { StrCat(info, "  "); CatPas(info, p + 19, n - 19, 96); }
		}
		else if (p[12] == 4 && n >= 14) StrCat(info, p[13] == 1 ? "Echo request" : p[13] == 2 ? "Echo reply" : "?");
		else if (p[12] == 5 && n >= 14) StrCat(info, p[13] == 1 ? "Route request" : p[13] == 2 ? "Route data request" : p[13] == 3 ? "Route data request, full" : "?");
		else { StrCat(info, "len "); CatNum(info, Get16(p) & 0x3FF); }
		break;
	case 0x80F3:												/* AARP */
		StrCat(proto, "AARP"); CatMAC(src, f->src);
		if (n < 28) break;
		{
			UInt16 fn = Get16(p + 6);
			StrCat(dst, fn == 2 ? "" : "AppleTalk broadcast");	/* addresses: 0, net, node at 14 and 24 */
			if (fn == 2) CatAT(dst, p + 25, p[27], -1);
			StrCat(info, fn == 1 ? "Request for " : fn == 2 ? "Response " : fn == 3 ? "Probe for " : "? ");
			CatAT(info, fn == 2 ? p + 15 : p + 25, fn == 2 ? p[17] : p[27], -1);
		}
		break;
	default:
		StrCat(proto, "?");
	}
	if (!src[0]) CatMAC(src, f->src);
}

	/* the protocol tree, one line per field; returns the count */
#define L	(s = (nl < max ? lines[nl++] : lines[max - 1]), s[0] = 0, s)
#define H	(s = L, StrCat(s, "\001"), s)							/* a heading: drawn bold */

	/* the tree of a DNS, mDNS or LLMNR message m (mn bytes) below UDP, from IPv4 and IPv6 alike */
static short DnsDetail(const UInt8 *m, long mn, UInt16 sp, UInt16 dp, char (*lines)[NC_DETAILLEN], short max, short nl)
{
	char *s;
	long off = 12, u;
	UInt16 i, qd, an;
	char name[48];
	H; StrCat(s, dp == 5353 || sp == 5353 ? "Multicast DNS" : dp == 5355 || sp == 5355 ? "LLMNR" : "DNS");
	if (mn < 12) return nl;
	qd = Get16(m + 4); an = Get16(m + 6);
	L; StrCat(s, "  ID 0x"); CatHex(s, Get16(m), 4); StrCat(s, (m[2] & 0x80) ? "  response" : "  query");
	StrCat(s, "  questions "); CatNum(s, qd); StrCat(s, "  answers "); CatNum(s, an);
	for (i = 0; i < qd && i < 4; i++) {
		u = DnsName(m, mn, off, name, sizeof(name));
		if (u < 0 || off + u + 4 > mn) break;
		L; StrCat(s, "  Q  "); StrCat(s, name); StrCat(s, "  "); StrCat(s, DnsType(Get16(m + off + u)));
		off += u + 4;
	}
	for (i = 0; i < an && i < 6; i++) {
		UInt16 ty, rl;
		u = DnsName(m, mn, off, name, sizeof(name));
		if (u < 0 || off + u + 10 > mn) break;
		ty = Get16(m + off + u); rl = Get16(m + off + u + 8);
		L; StrCat(s, "  A  "); StrCat(s, name); StrCat(s, "  "); StrCat(s, DnsType(ty));
		if (ty == 1 && rl == 4 && off + u + 14 <= mn) { StrCat(s, "  "); CatIP4(s, m + off + u + 10); }
		else if ((ty == 12 || ty == 5) && off + u + 10 + rl <= mn) {
			char tgt[48];
			if (DnsName(m, mn, off + u + 10, tgt, sizeof(tgt)) > 0) { L; StrCat(s, "      -> "); StrCat(s, tgt); }
		}
		off += u + 10 + rl;
	}
	return nl;
}

	/* the tree above DDP for RTMP, AEP, RTMP requests, ZIP and ATP with ZIP, ASP and AFP on it */
static short AppleTalkDetail(const NCFrame *f, char (*lines)[NC_DETAILLEN], short max, short nl)
{
	const UInt8 *p = f->data;
	long n = f->caplen;
	char *s;
	short i;
	switch (p[12]) {
	case 1: {													/* RTMP data: the sender, then the routing tuples */
		long o = 17;
		H; StrCat(s, "RTMP");
		if (n < 17) break;
		L; StrCat(s, "  Router  "); CatNum(s, Get16(p + 13)); StrCat(s, "."); CatNum(s, p[16]);
		for (i = 0; o + 3 <= n && i < 12; i++) {
			UInt8 dist = p[o + 2];
			L; StrCat(s, "  Net "); CatNum(s, Get16(p + o));
			if ((dist & 0x80) && o + 6 <= n) { StrCat(s, "-"); CatNum(s, Get16(p + o + 3)); }
			StrCat(s, "  distance "); CatNum(s, dist & 0x1F);
			o += (dist & 0x80) ? 6 : 3;
		}
		break;
	}
	case 4:
		H; StrCat(s, "AEP");
		if (n < 14) break;
		L; StrCat(s, "  "); StrCat(s, p[13] == 1 ? "Echo request (1)" : p[13] == 2 ? "Echo reply (2)" : "?");
		StrCat(s, ", "); CatNum(s, n - 14); StrCat(s, " bytes echoed");
		break;
	case 5:
		H; StrCat(s, "RTMP Request");
		if (n < 14) break;
		L; StrCat(s, "  Function "); CatNum(s, p[13]);
		StrCat(s, p[13] == 1 ? " (route request)" : p[13] == 2 ? " (data, split horizon)" : p[13] == 3 ? " (data, full table)" : "");
		break;
	case 6:
		H; StrCat(s, "ZIP");
		if (n < 14) break;
		L; StrCat(s, "  Function "); CatNum(s, p[13]); StrCat(s, " ("); StrCat(s, ZipName(p[13], 0)); StrCat(s, ")");
		if ((p[13] == 5 || p[13] == 6) && n >= 20) {
			L; StrCat(s, "  Flags 0x"); CatHex(s, p[14], 2);
			if (p[13] == 6) { StrCat(s, "  net "); CatNum(s, Get16(p + 15)); StrCat(s, "-"); CatNum(s, Get16(p + 17)); }
			L; StrCat(s, "  Zone  "); CatPas(s, p + 19, n - 19, NC_DETAILLEN);
		}
		break;
	case 3: {
		const UInt8 *u = p + 17, *d = p + 21;
		long dn = n - 21;
		UInt8 fn = (UInt8) (p[13] >> 6);
		const NCFrame *rq;
		H; StrCat(s, "ATP");
		if (n < 21) break;
		L; StrCat(s, "  "); StrCat(s, fn == 1 ? "TReq" : fn == 2 ? "TResp" : fn == 3 ? "TRel" : "?");
		StrCat(s, "  TID "); CatNum(s, Get16(p + 15));
		StrCat(s, fn == 1 ? "  bitmap 0x" : "  seq 0x"); CatHex(s, p[14], 2);
		L; StrCat(s, "  Control 0x"); CatHex(s, p[13], 2);
		if (p[13] & 0x20) StrCat(s, "  XO");
		if (p[13] & 0x10) StrCat(s, "  EOM");
		if (p[13] & 0x08) StrCat(s, "  STS");
		L; StrCat(s, "  User bytes  "); for (i = 0; i < 4; i++) { CatHex(s, u[i], 2); StrCat(s, " "); }
		StrCat(s, " data "); CatNum(s, AtpData(f));
		if (fn == 3) break;
		rq = fn == 1 ? f : AtpRequest(f);
		if (!rq) {
			long r = Signed32(Get32(u));
			L; StrCat(s, "  Request not captured: Open Transport hands");
			L; StrCat(s, "  on only what this Mac receives");
			if (p[11] == 6) {									/* ZIP's socket: a zone list */
				long o = 0;
				H; StrCat(s, "ZIP");
				L; StrCat(s, "  Zone list  "); CatNum(s, Get16(u + 2)); StrCat(s, " zones"); if (u[0]) StrCat(s, "  last");
				for (i = 0; o < dn && i < 8; i++) { L; StrCat(s, "  Zone  "); CatPas(s, d + o, dn - o, NC_DETAILLEN); o += 1 + d[o]; }
			} else if (r == 0 || AfpErr(r)) { L; StrCat(s, "  As an ASP reply: result "); CatAfpResult(s, r); }
			break;
		}
		if (fn == 2) {
			unsigned long dt = f->us - rq->us;
			L; StrCat(s, "  Answers the TReq after "); CatNum(s, dt / 1000UL); StrCat(s, "."); CatNum(s, (dt / 100UL) % 10); StrCat(s, " ms");
		}
		switch (AtpKind(rq->data)) {
		case kAtpZip:
			H; StrCat(s, "ZIP");
			L; StrCat(s, "  "); StrCat(s, ZipName(rq->data[17], 1)); StrCat(s, fn == 1 ? "  start " : " Reply  zones ");
			CatNum(s, Get16(u + 2)); if (fn == 2 && u[0]) StrCat(s, "  last");
			if (fn == 2) {
				long o = 0;
				for (i = 0; o < dn && i < 8; i++) { L; StrCat(s, "  Zone  "); CatPas(s, d + o, dn - o, NC_DETAILLEN); o += 1 + d[o]; }
			}
			break;
		case kAtpAsp: {
			UInt8 af = rq->data[17];
			long rn = rq->caplen - 21;
			H; StrCat(s, "ASP");
			L; StrCat(s, "  "); StrCat(s, AspName(af)); StrCat(s, fn == 1 ? "" : " Reply"); StrCat(s, "  (SPFunction "); CatNum(s, af); StrCat(s, ")");
			if (fn == 1) {
				if (af == 4) { L; StrCat(s, "  Workstation socket "); CatNum(s, u[1]); StrCat(s, ", version 0x"); CatHex(s, Get16(u + 2), 4); }
				else if (af != 3) { L; StrCat(s, "  Session "); CatNum(s, u[1]); if (af == 2 || af == 6 || af == 7) { StrCat(s, ", sequence "); CatNum(s, Get16(u + 2)); } }
			} else if (af == 4) {
				L; StrCat(s, "  Server socket "); CatNum(s, u[0]); StrCat(s, ", session "); CatNum(s, u[1]);
				L; StrCat(s, "  Result  "); CatAfpResult(s, Signed16(Get16(u + 2)));
			} else if (af == 3 && dn >= 12) {
				L; StrCat(s, "  Server  "); CatPas(s, d + 10, dn - 10, NC_DETAILLEN);
				L; StrCat(s, "  Flags 0x"); CatHex(s, Get16(d + 8), 4);
			}
			if ((af == 2 || af == 6) && rn >= 1) {
				UInt8 cmd = rq->data[21];
				H; StrCat(s, "AFP");
				L; StrCat(s, "  FP"); StrCat(s, AfpName(cmd)); StrCat(s, "  (command "); CatNum(s, cmd); StrCat(s, ")");
				if (fn == 2) { L; StrCat(s, "  Result  "); CatAfpResult(s, Signed32(Get32(u))); StrCat(s, ", "); CatNum(s, AtpData(f)); StrCat(s, " bytes"); }
				else if (rn >= 4 && (cmd == 17 || cmd == 26 || cmd == 4 || cmd == 27 || cmd == 33)) {
					L; StrCat(s, cmd == 17 || cmd == 26 ? "  Volume " : "  Fork "); CatNum(s, Get16(rq->data + 23));	/* after a pad or flag byte */
				}
			}
			break;
		}
		}
		break;
	}
	}
	return nl;
}

short NC_FrameDetail(const NCFrame *f, char (*lines)[NC_DETAILLEN], short max)
{
	const UInt8 *p = f->data;
	long n = f->caplen;
	short nl = 0;
	char *s;

	H; StrCat(s, "Frame  "); CatNum(s, f->len); StrCat(s, " bytes, "); CatNum(s, f->caplen); StrCat(s, " kept");
	L; StrCat(s, "  Arrival  +"); CatNum(s, f->us / 1000000UL); StrCat(s, ".");
	{ char t[8]; unsigned long u = f->us % 1000000UL; short i; for (i = 5; i >= 0; i--) { t[i] = (char) ('0' + u % 10); u /= 10; } t[6] = 0; StrCat(s, t); }
	StrCat(s, " s");
	H; StrCat(s, "Link  (Open Transport hands no MAC header on)");
	L; StrCat(s, "  Source  "); CatMAC(s, f->src);
	L; StrCat(s, "  Type  0x"); CatHex(s, f->type, 4);

	switch (f->type) {
	case 0x0806:
		H; StrCat(s, "ARP");
		if (n < 28) break;
		L; StrCat(s, "  Operation  "); StrCat(s, Get16(p + 6) == 1 ? "request (1)" : Get16(p + 6) == 2 ? "reply (2)" : "?");
		L; StrCat(s, "  Sender  "); CatMAC(s, p + 8); StrCat(s, "  "); CatIP4(s, p + 14);
		L; StrCat(s, "  Target  "); CatMAC(s, p + 18); StrCat(s, "  "); CatIP4(s, p + 24);
		break;
	case 0x0800: {
		short ihl;
		const UInt8 *t;
		long tn;
		H; StrCat(s, "IPv4");
		if (n < 20) break;
		ihl = (short) ((p[0] & 15) * 4); t = p + ihl; tn = n - ihl;
		L; StrCat(s, "  Header "); CatNum(s, ihl); StrCat(s, " bytes, total "); CatNum(s, Get16(p + 2)); StrCat(s, ", TTL "); CatNum(s, p[8]);
		L; StrCat(s, "  ID 0x"); CatHex(s, Get16(p + 4), 4); StrCat(s, (p[6] & 0x40) ? "  DF" : ""); StrCat(s, (p[6] & 0x20) ? "  MF" : "");
		StrCat(s, "  protocol "); CatNum(s, p[9]);
		L; StrCat(s, "  Source  "); CatIP4(s, p + 12);
		L; StrCat(s, "  Destination  "); CatIP4(s, p + 16);
		if (p[9] == 17 && tn >= 8) {
			UInt16 sp = Get16(t), dp = Get16(t + 2);
			H; StrCat(s, "UDP");
			L; StrCat(s, "  Ports  "); CatNum(s, sp); StrCat(s, " > "); CatNum(s, dp); StrCat(s, ", length "); CatNum(s, Get16(t + 4));
			if (sp == 53 || dp == 53 || sp == 5353 || dp == 5353 || sp == 5355 || dp == 5355)
				nl = DnsDetail(t + 8, tn - 8, sp, dp, lines, max, nl);
			else if (sp == 67 || sp == 68) {
				const UInt8 *m = t + 8, *o;
				long mn = tn - 8;
				short l, i;
				H; StrCat(s, "DHCP");
				if (mn < 240) { L; StrCat(s, "  (cut off)"); break; }
				o = DhcpOpt(m, mn, 53, &l);
				L; StrCat(s, "  "); StrCat(s, o && l >= 1 ? DhcpType(o[0]) : "?"); StrCat(s, "  xid 0x"); CatHex(s, Get32(m + 4), 8);
				L; StrCat(s, "  Client  "); CatMAC(s, m + 28);
				if (Get32(m + 16)) { L; StrCat(s, "  Your address  "); CatIP4(s, m + 16); }
				o = DhcpOpt(m, mn, 50, &l); if (o && l == 4) { L; StrCat(s, "  Requested  "); CatIP4(s, o); }
				o = DhcpOpt(m, mn, 54, &l); if (o && l == 4) { L; StrCat(s, "  Server  "); CatIP4(s, o); }
				o = DhcpOpt(m, mn, 12, &l);
				if (o) { L; StrCat(s, "  Host name  "); for (i = 0; i < l && i < 40; i++) { char c[2]; c[0] = (char) o[i]; c[1] = 0; StrCat(s, c); } }
			}
		} else if (p[9] == 6 && tn >= 20) {
			H; StrCat(s, "TCP");
			L; StrCat(s, "  Ports  "); CatNum(s, Get16(t)); StrCat(s, " > "); CatNum(s, Get16(t + 2));
			L; StrCat(s, "  Seq "); CatNum(s, Get32(t + 4)); StrCat(s, "  Ack "); CatNum(s, Get32(t + 8));
			L; StrCat(s, "  Flags 0x"); CatHex(s, t[13], 2); StrCat(s, "  window "); CatNum(s, Get16(t + 14));
		} else if (p[9] == 1 && tn >= 4) {
			H; StrCat(s, "ICMP");
			L; StrCat(s, "  "); StrCat(s, IcmpName(t[0])); StrCat(s, "  type "); CatNum(s, t[0]); StrCat(s, " code "); CatNum(s, t[1]);
		}
		break;
	}
	case 0x86DD: {
		UInt8 nh;
		long o = 40;
		H; StrCat(s, "IPv6");
		if (n < 40) break;
		L; StrCat(s, "  Payload "); CatNum(s, Get16(p + 4)); StrCat(s, " bytes, hop limit "); CatNum(s, p[7]); StrCat(s, ", next "); CatNum(s, p[6]);
		L; StrCat(s, "  Source  "); CatIP6(s, p + 8);
		L; StrCat(s, "  Destination  "); CatIP6(s, p + 24);
		nh = p[6];
		if (nh == 0 && n >= 42) { L; StrCat(s, "  Hop-by-hop options, next "); CatNum(s, p[40]); nh = p[40]; o = 40 + (p[41] + 1) * 8; }
		if (nh == 58 && o + 4 <= n) {
			H; StrCat(s, "ICMPv6");
			L; StrCat(s, "  "); StrCat(s, Icmp6Name(p[o])); StrCat(s, "  type "); CatNum(s, p[o]); StrCat(s, " code "); CatNum(s, p[o + 1]);
			if ((p[o] == 135 || p[o] == 136) && o + 24 <= n) { L; StrCat(s, "  Target  "); CatIP6(s, p + o + 8); }
			if (p[o] == 134 && o + 16 <= n) { L; StrCat(s, "  Router lifetime "); CatNum(s, Get16(p + o + 6)); StrCat(s, " s"); }
		} else if (nh == 17 && o + 8 <= n) {
			UInt16 sp = Get16(p + o), dp = Get16(p + o + 2);
			H; StrCat(s, "UDP");
			L; StrCat(s, "  Ports  "); CatNum(s, sp); StrCat(s, " > "); CatNum(s, dp); StrCat(s, ", length "); CatNum(s, Get16(p + o + 4));
			if (sp == 53 || dp == 53 || sp == 5353 || dp == 5353 || sp == 5355 || dp == 5355)
				nl = DnsDetail(p + o + 8, n - o - 8, sp, dp, lines, max, nl);
		}
		break;
	}
	case 0x88CC: {
		static const char *kTlv[] = { "End", "Chassis", "Port", "TTL", "Port description", "System name",
									  "System description", "Capabilities", "Management address" };
		long o = 0;
		H; StrCat(s, "LLDP");
		while (o + 2 <= n) {
			short t = (short) (p[o] >> 1), len = (short) (((p[o] & 1) << 8) | p[o + 1]), i;
			o += 2;
			if (t == 0 || o + len > n) break;
			L; StrCat(s, "  "); StrCat(s, t <= 8 ? kTlv[t] : "TLV"); StrCat(s, "  ");
			if ((t == 1 || t == 2) && len == 7 && (p[o] == 4 || p[o] == 3)) CatMAC(s, p + o + 1);
			else if (t == 3 && len >= 2) { CatNum(s, Get16(p + o)); StrCat(s, " s"); }
			else if (t == 7 && len >= 4) { StrCat(s, "0x"); CatHex(s, Get16(p + o), 4); StrCat(s, " enabled 0x"); CatHex(s, Get16(p + o + 2), 4); }
			else if (t == 8 && len >= 6 && p[o + 1] == 1) CatIP4(s, p + o + 2);
			else {
				short skip = (short) ((t == 1 || t == 2) ? 1 : 0);
				for (i = skip; i < len && i < 40; i++) { char c[2]; c[0] = (char) (p[o + i] >= ' ' && p[o + i] < 127 ? p[o + i] : '.'); c[1] = 0; StrCat(s, c); }
			}
			o += len;
		}
		break;
	}
	case 0x809B:
		H; StrCat(s, "AppleTalk DDP");
		if (n < 13) break;
		L; StrCat(s, "  Hops "); CatNum(s, (p[0] >> 2) & 15); StrCat(s, ", length "); CatNum(s, Get16(p) & 0x3FF); StrCat(s, ", type "); CatNum(s, p[12]);
		StrCat(s, " ("); StrCat(s, DdpName(p[12])); StrCat(s, ")");
		L; StrCat(s, "  Source  "); CatAT(s, p + 6, p[9], p[11]);
		L; StrCat(s, "  Destination  "); CatAT(s, p + 4, p[8], p[10]);
		if (p[12] == 2 && n > 15) {
			H; StrCat(s, "NBP");
			L; StrCat(s, "  Function "); CatNum(s, p[13] >> 4); StrCat(s, ", tuples "); CatNum(s, p[13] & 15); StrCat(s, ", id "); CatNum(s, p[14]);
			L; StrCat(s, "  "); NbpTuple(p + 13, n - 13, s);
		} else nl = AppleTalkDetail(f, lines, max, nl);
		break;
	case 0x80F3:
		H; StrCat(s, "AARP");
		if (n < 28) break;
		L; StrCat(s, "  Function  "); CatNum(s, Get16(p + 6));
		StrCat(s, Get16(p + 6) == 1 ? " (request)" : Get16(p + 6) == 2 ? " (response)" : Get16(p + 6) == 3 ? " (probe)" : "");
		L; StrCat(s, "  Sender  "); CatMAC(s, p + 8); StrCat(s, "  "); CatAT(s, p + 15, p[17], -1);
		L; StrCat(s, "  Target  "); CatMAC(s, p + 18); StrCat(s, "  "); CatAT(s, p + 25, p[27], -1);
		break;
	}
#undef L
#undef H
	return nl;
}

/* ------------------------------------------------------------------ pcap */

static void Put16(UInt8 *b, UInt16 v) { b[0] = (UInt8) (v >> 8); b[1] = (UInt8) v; }
static void Put32(UInt8 *b, UInt32 v) { Put16(b, (UInt16) (v >> 16)); Put16(b + 2, (UInt16) v); }

long NC_PcapHeader(unsigned char *b)
{
	Put32(b, 0xA1B2C3D4UL);									/* microsecond timestamps, our byte order */
	Put16(b + 4, 2); Put16(b + 6, 4);						/* version 2.4 */
	Put32(b + 8, 0); Put32(b + 12, 0);						/* UTC, no accuracy claim */
	Put32(b + 16, 16 + NC_SNAPLEN);
	Put32(b + 20, 113);										/* LINKTYPE_LINUX_SLL */
	return 24;
}

	/* SLL's packet type from the destination, as the MAC header would have told it: 0 to us, 1 broadcast,
	   2 multicast. A flooded frame for another host also reads as 0: its destination MAC is not there. */
static UInt16 SllType(const NCFrame *f)
{
	const UInt8 *p = f->data;
	long n = f->caplen;
	switch (f->type) {
	case 0x0806: return (UInt16) (n >= 8 && Get16(p + 6) == 1 ? 1 : 0);	/* a request is broadcast */
	case 0x0800:
		if (n >= 20 && p[16] >= 224 && p[16] <= 239) return 2;
		return (UInt16) (n >= 20 && p[19] == 255 ? 1 : 0);
	case 0x86DD: return (UInt16) (n >= 40 && p[24] == 0xFF ? 2 : 0);
	case 0x88CC: return 2;
	case 0x809B: return (UInt16) (n >= 13 && p[8] == 255 ? 2 : 0);		/* AppleTalk broadcast is a multicast */
	case 0x80F3: return 2;
	}
	return 0;
}

long NC_PcapRecord(const NCFrame *f, unsigned char *b)
{
	short i;
	Put32(b, NC_FrameEpoch() + f->us / 1000000UL);
	Put32(b + 4, f->us % 1000000UL);
	Put32(b + 8, 16 + (UInt32) f->caplen);
	Put32(b + 12, 16 + (UInt32) f->len);
	Put16(b + 16, SllType(f));
	Put16(b + 18, 1);										/* ARPHRD_ETHER */
	Put16(b + 20, 6);
	for (i = 0; i < 6; i++) b[22 + i] = f->src[i];
	b[28] = b[29] = 0;
	Put16(b + 30, f->type);
	for (i = 0; i < f->caplen; i++) b[32 + i] = f->data[i];
	return 32 + f->caplen;
}

/* ------------------------------------------------------------------ a frame as text, for Copy */

#define CR		"\015"

static void Put(char *buf, long *o, long max, const char *s)
{
	while (*s && *o < max) buf[(*o)++] = *s++;
}

long NC_FrameText(const NCFrame *f, long no, char *buf, long max)
{
	static const char hx[] = "0123456789abcdef";
	char src[48], dst[48], proto[16], info[96], t[64];
	char lines[40][NC_DETAILLEN];
	long o = 0, off;
	short nl, i, x, k;
	unsigned long u;

	NC_FrameSummary(f, src, dst, proto, info);
	Put(buf, &o, max, "No.\tTime\tSource\tDestination\tProtocol\tLength\tInfo" CR);
	t[0] = 0; CatNum(t, (unsigned long) no); Put(buf, &o, max, t); Put(buf, &o, max, "\t");
	t[0] = 0; CatNum(t, f->us / 1000000UL); StrCat(t, ".");
	u = f->us % 1000000UL;
	{ char d[8]; for (k = 5; k >= 0; k--) { d[k] = (char) ('0' + u % 10); u /= 10; } d[6] = 0; StrCat(t, d); }
	Put(buf, &o, max, t); Put(buf, &o, max, "\t");
	Put(buf, &o, max, src); Put(buf, &o, max, "\t"); Put(buf, &o, max, dst); Put(buf, &o, max, "\t");
	Put(buf, &o, max, proto); Put(buf, &o, max, "\t");
	t[0] = 0; CatNum(t, (unsigned long) f->len); Put(buf, &o, max, t); Put(buf, &o, max, "\t");
	Put(buf, &o, max, info); Put(buf, &o, max, CR CR);

	nl = NC_FrameDetail(f, lines, 40);							/* the tree; headings lose their bold mark */
	for (i = 0; i < nl; i++) { Put(buf, &o, max, lines[i][0] == '\001' ? lines[i] + 1 : lines[i]); Put(buf, &o, max, CR); }
	Put(buf, &o, max, CR);

	for (off = 0; off < f->caplen; off += 16) {					/* the bytes, as the pane shows them */
		k = 0;
		t[k++] = hx[(off >> 12) & 15]; t[k++] = hx[(off >> 8) & 15]; t[k++] = hx[(off >> 4) & 15]; t[k++] = hx[off & 15];
		t[k++] = ' ';
		for (x = 0; x < 16 && off + x < f->caplen; x++) {
			if (x == 8) t[k++] = ' ';
			t[k++] = ' '; t[k++] = hx[f->data[off + x] >> 4]; t[k++] = hx[f->data[off + x] & 15];
		}
		t[k] = 0;
		Put(buf, &o, max, t); Put(buf, &o, max, CR);
	}
	return o;
}
