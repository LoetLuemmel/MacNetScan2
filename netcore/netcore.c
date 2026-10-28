/* netcore.c - MacNetScan 2's network engine (see netcore.h). The probing, packet building and parsing come from
   MacNetScan 1's ipscan.c unchanged in substance; what changed is the control flow: every loop that waited (the sweep,
   the UDP name queries, DNS, ping, traceroute) is now a state that the next Idle call continues, so the application
   keeps calling WaitNextEvent. NBP lookups stay synchronous (one zone per call, 1 s): OT 1.1's SDK has no asynchronous
   mapper sample to go by. Plain C, 68K. */

#include "OTCompat.h"
#include <Events.h>						/* TickCount: in the TCL project a .c file has no MacHeaders prefix */
#include <Memory.h>						/* NewPtr, NewPtrClear, DisposePtr, BlockMove */
#include <Errors.h>						/* memFullErr */
#include <OSUtils.h>						/* GetDateTime, ReadLocation: the capture's start for pcap */
#include <Files.h>						/* PBHGetVInfo, PBHGetVolParms: the mounted AppleShare volumes */
#include <OpenTransport.h>
#include <OpenTptInternet.h>
#include <OpenTptAppleTalk.h>
#include <OpenTptLinks.h>
#include "netcore.h"

#define CR				"\015"			/* report line end: CR whatever '\n' means to the compiler */
#define TICKS_PER_SEC	60L

/* ------------------------------------------------------------------ small helpers */

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

static void StrCopy(char *dst, const char *src, short max)
{
	short i = 0;
	while (src[i] && i < max - 1) { dst[i] = src[i]; i++; }
	dst[i] = 0;
}

static Boolean StrEqual(const char *a, const char *b)
{
	short i = 0;
	while (a[i] && a[i] == b[i]) i++;
	return (Boolean) (a[i] == b[i]);
}

static void TrimRight(char *s)
{
	short e = 0;
	while (s[e]) e++;
	while (e > 0 && (s[e - 1] == ' ' || s[e - 1] == 0)) s[--e] = 0;
}

static Boolean StrEq(const char *a, const char *b)
{
	short i = 0;
	while (a[i] && b[i]) { if (a[i] != b[i]) return false; i++; }
	return a[i] == b[i];
}

void NC_IPToStr(InetHost ip, char *s)
{
	char nb[8];
	s[0] = 0;
	UToStr((ip >> 24) & 0xFF, nb); StrCat(s, nb); StrCat(s, ".");
	UToStr((ip >> 16) & 0xFF, nb); StrCat(s, nb); StrCat(s, ".");
	UToStr((ip >> 8) & 0xFF, nb);  StrCat(s, nb); StrCat(s, ".");
	UToStr(ip & 0xFF, nb);         StrCat(s, nb);
}

/* round-trip times are taken in the notifiers, the moment the answer arrives: measured when the Idle call next ran,
   they were the application's sleep time (TickCount resolution, 0 or 100 ms for a 1 ms LAN answer) */
void NC_RttToStr(long us, char *s)
{
	char nb[12];
	if (us < 0) { s[0] = '-'; s[1] = 0; return; }
	if (us < 10000L) {								/* below 10 ms: one decimal */
		UToStr((unsigned long) (us / 1000L), s);
		UToStr((unsigned long) ((us % 1000L) / 100L), nb);
		StrCat(s, "."); StrCat(s, nb);
	} else
		UToStr((unsigned long) ((us + 500L) / 1000L), s);
}

static long StampUs(OTTimeStamp *t0, OTTimeStamp *t1)
{
	OTTimeStamp d;
	OTSubtractTimeStamps(&d, t0, t1);
	return (long) OTTimeStampInMicroseconds(&d);
}

/* "192.168.3.1" -> address; false if it is not a dotted quad */
static Boolean ParseDotted(const char *s, InetHost *ip)
{
	unsigned long v = 0, part = 0;
	short dots = 0, digits = 0, i = 0;
	for (;; i++) {
		char c = s[i];
		if (c >= '0' && c <= '9') { part = part * 10 + (c - '0'); digits++; if (part > 255) return false; }
		else if (c == '.' || c == 0) {
			if (digits == 0) return false;
			v = (v << 8) | part; part = 0; digits = 0;
			if (c == 0) break;
			if (++dots > 3) return false;
		}
		else return false;
	}
	if (dots != 3) return false;
	*ip = (InetHost) v;
	return true;
}

/* ------------------------------------------------------------------ parameters */

typedef struct { UInt16 port; char name[10]; } PortDef;

static const PortDef kKnown[] = {			/* known ports -> label; also the default probe set */
	{ 9000, "ABridge" }, { 80, "HTTP" }, { 443, "HTTPS" }, { 445, "SMB" },
	{ 139, "NetBIOS" }, { 548, "AFP" }, { 22, "SSH" }, { 631, "IPP" },
	{ 21, "FTP" }, { 23, "Telnet" }
};
#define NKNOWN ((short) (sizeof(kKnown) / sizeof(kKnown[0])))

static UInt16	gPorts[NC_MAXPORTS];
static short	gNPorts = 0;
static short	gFirst = 1, gLast = 254;
static short	gProbeTicks = 36;			/* ~0.6 s per attempt */
static short	gNSlots = NC_MAXSLOTS;

static InetHost	gLocalIP = 0, gNetmask = 0, gBase = 0;

void NC_SetDefaultPorts(void)
{
	short i;
	gNPorts = NKNOWN;
	for (i = 0; i < gNPorts; i++) gPorts[i] = kKnown[i].port;
}

void NC_SetRange(short first, short last)
{
	if (first > last) { short t = first; first = last; last = t; }
	if (first < 1) first = 1;
	if (last > 254) last = 254;
	gFirst = first; gLast = last;
}
void NC_GetRange(short *first, short *last) { *first = gFirst; *last = gLast; }

void NC_SetTimeoutMs(long ms)
{
	long t = ms * TICKS_PER_SEC / 1000L;
	if (t < 3) t = 3;
	if (t > 600) t = 600;
	gProbeTicks = (short) t;
}
long NC_TimeoutMs(void) { return (long) gProbeTicks * 1000L / TICKS_PER_SEC; }

void NC_SetConcurrency(short n)
{
	if (n < 1) n = 1;
	if (n > NC_MAXSLOTS) n = NC_MAXSLOTS;
	gNSlots = n;
}
short NC_Concurrency(void) { return gNSlots; }

short NC_ParsePorts(const char *s)
{
	UInt16 p[NC_MAXPORTS];
	short n = 0, i = 0;
	long v = 0;
	Boolean have = false;
	for (;;) {
		char c = s[i++];
		if (c >= '0' && c <= '9') { v = v * 10 + (c - '0'); have = true; }
		else {
			if (have && n < NC_MAXPORTS && v > 0 && v < 65536L) p[n++] = (UInt16) v;
			v = 0; have = false;
			if (c == 0) break;
		}
	}
	if (n > 0) { for (i = 0; i < n; i++) gPorts[i] = p[i]; gNPorts = n; }
	return n;
}

void NC_PortsToStr(char *out)
{
	short i;
	char nb[8];
	out[0] = 0;
	for (i = 0; i < gNPorts; i++) {
		if (i) StrCat(out, ",");
		UToStr(gPorts[i], nb); StrCat(out, nb);
	}
}

short NC_PortCount(void) { return gNPorts; }
UInt16 NC_Port(short i) { return (i >= 0 && i < gNPorts) ? gPorts[i] : 0; }

void NC_PortLabel(short i, char *out)
{
	short k;
	UInt16 p = NC_Port(i);
	for (k = 0; k < NKNOWN; k++)
		if (kKnown[k].port == p) { StrCopy(out, kKnown[k].name, 12); return; }
	UToStr(p, out);
}

InetHost NC_LocalIP(void) { return gLocalIP; }
InetHost NC_Netmask(void) { return gNetmask; }
InetHost NC_Base(void) { return gBase; }

/* ------------------------------------------------------------------ sweep: probes */

enum { PR_TIMEOUT = 0, PR_OPEN = 1, PR_REFUSED = 2 };

typedef struct { Boolean up; UInt32 openMask; long rtt; } HostRec;

typedef struct {
	EndpointRef				ep;
	short					host;
	short					portIdx;
	long					start;					/* ticks, for the timeout */
	OTTimeStamp				t0;						/* connect issued */
	OTTimeStamp				t1;						/* answer arrived (set by the notifier) */
	Boolean					busy;
	volatile OTEventCode	ev;
} Slot;

static HostRec	gRec[256];
static Slot		gSlots[NC_MAXSLOTS];
static NCHost	*gHosts = NULL;						/* heap: two 20 KB tables would overflow the 32 KB of A5 globals */
static NCHost	*gOld = NULL;
static short	gNHosts = 0;
static short	gPhase = NC_SWEEP_IDLE;
static long		gWorkNext = 0, gWorkTotal = 0;
static Boolean	gStop = false;
static long		gChange = 0, gActivity = 0;

static pascal void SlotNotifier(void *ctx, OTEventCode code, OTResult r, void *ck)
{
	Slot *s = (Slot *) ctx;
	if (r || ck) {}
	if ((code == T_CONNECT || code == T_DISCONNECT) && s->ev == 0) { OTGetTimeStamp(&s->t1); s->ev = code; }
}

static Boolean StartProbe(Slot *s, short host, short portIdx)
{
	OSStatus	err;
	InetAddress	addr, local;
	TCall		call;
	TBind		bindReq;

	s->ep = OTOpenEndpoint(OTCreateConfiguration(kTCPName), 0, NULL, &err);
	if (err != noErr || s->ep == NULL) { s->ep = NULL; return false; }
	OTMemzero(&local, sizeof(local));
	OTInitInetAddress(&local, 0, kOTAnyInetAddress);
	bindReq.addr.buf = (UInt8 *) &local; bindReq.addr.len = sizeof(local); bindReq.qlen = 0;
	if (OTBind(s->ep, &bindReq, NULL) != noErr) { OTCloseProvider(s->ep); s->ep = NULL; return false; }
	s->ev = 0;
	if (OTInstallNotifier(s->ep, SlotNotifier, s) != noErr) { OTCloseProvider(s->ep); s->ep = NULL; return false; }
	if (OTSetAsynchronous(s->ep) != noErr) {
		OTRemoveNotifier(s->ep); OTCloseProvider(s->ep); s->ep = NULL; return false;
	}
	OTMemzero(&addr, sizeof(addr));
	OTInitInetAddress(&addr, gPorts[portIdx], gBase | (InetHost) host);
	OTMemzero(&call, sizeof(call));
	call.addr.buf = (UInt8 *) &addr; call.addr.len = sizeof(addr);
	OTGetTimeStamp(&s->t0);
	err = OTConnect(s->ep, &call, NULL);
	if (err != noErr && err != kOTNoDataErr) {
		OTRemoveNotifier(s->ep); OTCloseProvider(s->ep); s->ep = NULL; return false;
	}
	s->host = host; s->portIdx = portIdx; s->start = TickCount(); s->busy = true;
	return true;
}

static void FinishSlot(Slot *s, short verdict)
{
	long el = (verdict == PR_TIMEOUT) ? -1 : StampUs(&s->t0, &s->t1);
	if (verdict == PR_OPEN) {
		gRec[s->host].up = true;
		gRec[s->host].openMask |= (1UL << s->portIdx);
		if (gRec[s->host].rtt < 0) gRec[s->host].rtt = el;
		OTSndDisconnect(s->ep, NULL);
	} else if (verdict == PR_REFUSED) {
		gRec[s->host].up = true;
		if (gRec[s->host].rtt < 0) gRec[s->host].rtt = el;
		OTRcvDisconnect(s->ep, NULL);
	} else
		OTSndDisconnect(s->ep, NULL);
	OTRemoveNotifier(s->ep);
	OTCloseProvider(s->ep);
	s->busy = false; s->ep = NULL;
	if (verdict != PR_TIMEOUT) { gActivity++; gChange++; }
}

/* the hosts found so far, in address order; names already resolved are kept */
static void BuildHosts(void)
{
	static long built = -1;
	short nOld = gNHosts, octet, k;
	if (built == gChange || !gHosts) return;			/* nothing new since the last time */
	built = gChange;
	BlockMove(gHosts, gOld, (long) nOld * sizeof(NCHost));
	gNHosts = 0;
	for (octet = gFirst; octet <= gLast && gNHosts < NC_MAXHOSTS; octet++) {
		NCHost *h;
		if (!gRec[octet].up) continue;
		h = &gHosts[gNHosts++];
		h->ip = gBase | (InetHost) octet;
		h->rttUs = gRec[octet].rtt;
		h->openMask = gRec[octet].openMask;
		h->name[0] = 0; h->nameSource = 0;
		for (k = 0; k < nOld; k++)
			if (gOld[k].ip == h->ip) { BlockMove(gOld[k].name, h->name, NC_NAMELEN); h->nameSource = gOld[k].nameSource; break; }
	}
}

/* ------------------------------------------------------------------ sweep: names (NetBIOS, mDNS, DNS) */

enum { NM_START = 0, NM_NBNS, NM_MDNS, NM_DNS, NM_NEXT };

static EndpointRef		gUdp = NULL;			/* one UDP endpoint for every name query */
static InetSvcRef		gSvc = NULL;			/* reverse DNS, asynchronous */
static volatile Boolean	gSvcDone = false;
static volatile OTResult gSvcResult = 0;
static Boolean			gSvcBusy = false;		/* a call is outstanding: its buffer must stay put */
static InetHost			gSvcFor = 0;
static InetDomainName	gSvcName;
static short			gNameIdx = 0, gNameState = NM_START;
static long				gNameStart = 0;
static UInt16			gQueryID = 0x4D4E;

static pascal void SvcNotifier(void *ctx, OTEventCode code, OTResult r, void *ck)
{
	if (ctx || ck) {}
	if (code == T_DNRADDRTONAMECOMPLETE) { gSvcResult = r; gSvcDone = true; }
}

static Boolean OpenUdp(void)
{
	OSStatus err;
	InetAddress local;
	TBind bindReq;
	if (gUdp) return true;
	gUdp = OTOpenEndpoint(OTCreateConfiguration(kUDPName), 0, NULL, &err);
	if (err != noErr || gUdp == NULL) { gUdp = NULL; return false; }
	OTMemzero(&local, sizeof(local));
	OTInitInetAddress(&local, 0, kOTAnyInetAddress);
	bindReq.addr.buf = (UInt8 *) &local; bindReq.addr.len = sizeof(local); bindReq.qlen = 0;
	if (OTBind(gUdp, &bindReq, NULL) != noErr) { OTCloseProvider(gUdp); gUdp = NULL; return false; }
	OTSetNonBlocking(gUdp);
	return true;
}

static Boolean OpenSvc(void)
{
	OSStatus err;
	if (gSvc) return true;
	gSvc = OTOpenInternetServices(kDefaultInternetServicesPath, 0, &err);
	if (err != noErr || gSvc == NULL) { gSvc = NULL; return false; }
	if (OTInstallNotifier(gSvc, SvcNotifier, NULL) != noErr || OTSetAsynchronous(gSvc) != noErr) {
		OTCloseProvider(gSvc); gSvc = NULL; return false;
	}
	return true;
}

/* throw away late answers to earlier queries */
static void DrainUdp(void)
{
	UInt8 junk[64];
	InetAddress from;
	TUnitData rcv;
	OTFlags flags;
	OTResult res;
	short guard = 0;
	if (!gUdp) return;
	do {
		OTMemzero(&rcv, sizeof(rcv));
		rcv.addr.buf = (UInt8 *) &from; rcv.addr.maxlen = sizeof(from);
		rcv.udata.buf = junk; rcv.udata.maxlen = sizeof(junk); flags = 0;
		res = OTRcvUData(gUdp, &rcv, &flags);
		if (res == kOTLookErr) { if (OTLook(gUdp) == T_UDERR) OTRcvUDErr(gUdp, NULL); res = noErr; }
	} while (res == noErr && ++guard < 32);
}

static Boolean UdpSend(InetHost dst, InetPort port, const UInt8 *q, long qlen)
{
	InetAddress to;
	TUnitData snd;
	if (!OpenUdp()) return false;
	DrainUdp();
	OTMemzero(&to, sizeof(to));
	OTInitInetAddress(&to, port, dst);
	OTMemzero(&snd, sizeof(snd));
	snd.addr.buf = (UInt8 *) &to; snd.addr.len = sizeof(to);
	snd.udata.buf = (UInt8 *) q; snd.udata.len = qlen;
	return OTSndUData(gUdp, &snd) == noErr;
}

/* one datagram if there is one (non-blocking): its length, 0 if none */
static long UdpPoll(UInt8 *reply, long max, InetHost *from)
{
	InetAddress f;
	TUnitData rcv;
	OTFlags flags;
	OTResult res;
	if (!gUdp) return 0;
	OTMemzero(&rcv, sizeof(rcv)); OTMemzero(&f, sizeof(f));
	rcv.addr.buf = (UInt8 *) &f; rcv.addr.maxlen = sizeof(f);
	rcv.udata.buf = reply; rcv.udata.maxlen = max; flags = 0;
	res = OTRcvUData(gUdp, &rcv, &flags);
	if (res == noErr) { if (from) *from = f.fHost; return (long) rcv.udata.len; }
	if (res == kOTLookErr && OTLook(gUdp) == T_UDERR) OTRcvUDErr(gUdp, NULL);
	return 0;
}

/* NetBIOS node status (NBSTAT) request for "*" */
static Boolean NbnsSend(InetHost ip)
{
	UInt8 q[50], nb16[16];
	short i;
	gQueryID++;
	q[0] = (UInt8) (gQueryID >> 8); q[1] = (UInt8) gQueryID;
	q[2] = 0x00; q[3] = 0x00; q[4] = 0x00; q[5] = 0x01;
	for (i = 6; i < 12; i++) q[i] = 0;
	q[12] = 0x20;
	nb16[0] = '*'; for (i = 1; i < 16; i++) nb16[i] = 0x00;
	for (i = 0; i < 16; i++) {
		q[13 + i * 2] = (UInt8) ('A' + (nb16[i] >> 4));
		q[13 + i * 2 + 1] = (UInt8) ('A' + (nb16[i] & 0x0F));
	}
	q[45] = 0x00; q[46] = 0x00; q[47] = 0x21; q[48] = 0x00; q[49] = 0x01;
	return UdpSend(ip, 137, q, 50);
}

static Boolean NbnsParse(const UInt8 *rep, long n, char *out)
{
	long i, base = -1, nameCount;
	short k;
	if (n < 12 || rep[0] != (UInt8) (gQueryID >> 8) || rep[1] != (UInt8) gQueryID) return false;
	for (i = 12; i + 11 < n; i++)
		if (rep[i] == 0x00 && rep[i + 1] == 0x21 && rep[i + 2] == 0x00 && rep[i + 3] == 0x01) { base = i + 10; break; }
	if (base < 0 || base >= n) return false;
	nameCount = rep[base++];
	for (i = 0; i < nameCount && base + 18 <= n; i++, base += 18)
		if (rep[base + 15] == 0x00 && !(rep[base + 16] & 0x80)) {
			for (k = 0; k < 15; k++) out[k] = (char) rep[base + k];
			out[15] = 0; TrimRight(out);
			if (out[0]) return true;
		}
	return false;
}

static long PutLabel(UInt8 *b, long pos, const char *s)
{
	long L = 0, k;
	while (s[L]) L++;
	b[pos++] = (UInt8) L;
	for (k = 0; k < L; k++) b[pos++] = (UInt8) s[k];
	return pos;
}
static long PutLabelNum(UInt8 *b, long pos, long v)
{
	char tmp[12];
	UToStr((unsigned long) v, tmp);
	return PutLabel(b, pos, tmp);
}
static long SkipName(const UInt8 *b, long pos, long n)
{
	while (pos < n) {
		UInt8 len = b[pos];
		if (len == 0) return pos + 1;
		if ((len & 0xC0) == 0xC0) return pos + 2;
		pos += 1 + len;
	}
	return pos;
}
static void DecodeName(const UInt8 *b, long pos, long n, char *out, long max)
{
	long o = 0, k;
	short hops = 0;
	while (pos < n && hops < 20) {
		UInt8 len = b[pos];
		if (len == 0) break;
		if ((len & 0xC0) == 0xC0) { pos = ((len & 0x3F) << 8) | b[pos + 1]; hops++; continue; }
		pos++;
		if (o > 0 && o < max - 1) out[o++] = '.';
		for (k = 0; k < len && pos < n && o < max - 1; k++) out[o++] = (char) b[pos++];
	}
	out[o] = 0;
}

/* multicast DNS PTR query for <ip>.in-addr.arpa, unicast reply requested (legacy query: the ID comes back) */
static Boolean MdnsSend(InetHost ip)
{
	UInt8 q[64];
	long i;
	gQueryID++;
	for (i = 0; i < 12; i++) q[i] = 0;
	q[0] = (UInt8) (gQueryID >> 8); q[1] = (UInt8) gQueryID;
	q[5] = 0x01;
	i = 12;
	i = PutLabelNum(q, i, ip & 0xFF);
	i = PutLabelNum(q, i, (ip >> 8) & 0xFF);
	i = PutLabelNum(q, i, (ip >> 16) & 0xFF);
	i = PutLabelNum(q, i, (ip >> 24) & 0xFF);
	i = PutLabel(q, i, "in-addr");
	i = PutLabel(q, i, "arpa");
	q[i++] = 0x00; q[i++] = 0x00; q[i++] = 0x0C; q[i++] = 0x80; q[i++] = 0x01;
	return UdpSend(0xE00000FBUL, 5353, q, i);
}

static Boolean MdnsParse(const UInt8 *rep, long n, char *out)
{
	long i, pos, qd, an, e;
	if (n < 12 || rep[0] != (UInt8) (gQueryID >> 8) || rep[1] != (UInt8) gQueryID) return false;
	an = (rep[6] << 8) | rep[7];
	if (an == 0) return false;
	qd = (rep[4] << 8) | rep[5];
	pos = 12;
	for (i = 0; i < qd; i++) { pos = SkipName(rep, pos, n); pos += 4; }
	pos = SkipName(rep, pos, n);
	if (pos + 10 > n) return false;
	pos += 10;
	DecodeName(rep, pos, n, out, NC_NAMELEN - 2);
	e = 0; while (out[e]) e++;
	if (e > 6 && out[e - 6] == '.' && out[e - 5] == 'l' && out[e - 4] == 'o' && out[e - 3] == 'c' &&
		out[e - 2] == 'a' && out[e - 1] == 'l') out[e - 6] = 0;
	return out[0] ? true : false;
}

static void SetName(InetHost ip, const char *name, char source)
{
	short i;
	for (i = 0; i < gNHosts; i++)
		if (gHosts[i].ip == ip) {
			StrCopy(gHosts[i].name, name, NC_NAMELEN);
			gHosts[i].nameSource = source;
			gChange++;
			return;
		}
}

/* a reverse lookup that finished, perhaps for a host the namer has already passed */
static void CollectSvc(void)
{
	if (!gSvcBusy || !gSvcDone) return;
	gSvcBusy = false;
	if (gSvcResult == noErr && gSvcName[0]) {
		char nm[NC_NAMELEN];
		short e;
		StrCopy(nm, gSvcName, NC_NAMELEN);
		e = 0; while (nm[e]) e++;
		if (e > 0 && nm[e - 1] == '.') nm[e - 1] = 0;		/* DNS answers end in '.' */
		SetName(gSvcFor, nm, 'D');
	}
}

/* one step of naming host gNameIdx; false when every host has had its turn */
static Boolean NameStep(void)
{
	UInt8 rep[1100];
	InetHost from = 0;
	long n;
	char nm[NC_NAMELEN];
	NCHost *h;

	CollectSvc();
	if (gNameIdx >= gNHosts) return gSvcBusy;			/* wait for the last reverse lookup */
	h = &gHosts[gNameIdx];
	switch (gNameState) {
	case NM_START:
		if (h->name[0]) { gNameState = NM_NEXT; break; }
		gNameState = NbnsSend(h->ip) ? NM_NBNS : NM_MDNS;
		gNameStart = TickCount();
		if (gNameState == NM_MDNS) { MdnsSend(h->ip); }
		break;
	case NM_NBNS:
		n = UdpPoll(rep, sizeof(rep), &from);
		if (n > 0 && NbnsParse(rep, n, nm)) { SetName(h->ip, nm, 'N'); gNameState = NM_NEXT; break; }
		if (TickCount() - gNameStart > 36) {
			gNameState = NM_MDNS; gNameStart = TickCount();
			if (!MdnsSend(h->ip)) gNameState = NM_DNS;
		}
		break;
	case NM_MDNS:
		n = UdpPoll(rep, sizeof(rep), &from);
		if (n > 0 && MdnsParse(rep, n, nm)) { SetName(h->ip, nm, 'M'); gNameState = NM_NEXT; break; }
		if (TickCount() - gNameStart > 40) gNameState = NM_DNS;
		break;
	case NM_DNS:
		if (gSvcBusy) {										/* the previous lookup still runs: wait a while */
			if (TickCount() - gNameStart > 300) { if (!h->name[0]) StrCopy(h->name, "?", NC_NAMELEN); gNameState = NM_NEXT; }
			break;
		}
		if (OpenSvc()) {
			gSvcName[0] = 0; gSvcDone = false; gSvcFor = h->ip;
			if (OTInetAddressToName(gSvc, h->ip, gSvcName) == noErr) gSvcBusy = true;
		}
		if (!h->name[0]) StrCopy(h->name, "?", NC_NAMELEN);	/* DNS may still overwrite it */
		gChange++;
		gNameState = NM_NEXT;
		break;
	default:
		gNameIdx++; gNameState = NM_START;
		break;
	}
	return true;
}

/* ------------------------------------------------------------------ sweep: control */

OSStatus NC_Init(void)
{
	InetInterfaceInfo info;
	OSStatus err;
	short i;
	if (gNPorts == 0) NC_SetDefaultPorts();
	if (!gHosts) gHosts = (NCHost *) NewPtrClear((long) NC_MAXHOSTS * sizeof(NCHost));
	if (!gOld) gOld = (NCHost *) NewPtrClear((long) NC_MAXHOSTS * sizeof(NCHost));
	if (!gHosts || !gOld) return memFullErr;
	err = InitOpenTransport();
	if (err != noErr) return err;
	for (i = 0; i < NC_MAXSLOTS; i++) { gSlots[i].busy = false; gSlots[i].ep = NULL; }
	err = OTInetGetInterfaceInfo(&info, kDefaultInetInterface);
	if (err == noErr) { gLocalIP = info.fAddress; gNetmask = info.fNetmask; }
	gBase = gLocalIP & 0xFFFFFF00UL;
	return err;
}

void NC_SweepStart(void)
{
	short i;
	long span;
	NC_SweepStop();
	while (gPhase == NC_SWEEP_PROBING) NC_SweepIdle();		/* let the old probes finish */
	if (gNPorts == 0) NC_SetDefaultPorts();
	for (i = 0; i < 256; i++) { gRec[i].up = false; gRec[i].openMask = 0; gRec[i].rtt = -1; }
	gNHosts = 0;
	span = gLast - gFirst + 1;
	if (span < 0) span = 0;
	gWorkTotal = span * gNPorts;
	gWorkNext = 0;
	gStop = false;
	gNameIdx = 0; gNameState = NM_START;
	gPhase = NC_SWEEP_PROBING;
	gChange++;
}

void NC_SweepStop(void) { if (gPhase == NC_SWEEP_PROBING || gPhase == NC_SWEEP_NAMING) gStop = true; }

short NC_SweepIdle(void)
{
	short i, budget;
	Boolean anyBusy = false;
	long t0 = TickCount();

	if (gPhase == NC_SWEEP_PROBING) {
		for (i = 0; i < gNSlots; i++)
			if (!gSlots[i].busy && gWorkNext < gWorkTotal && !gStop) {
				short host = gFirst + (short) (gWorkNext / gNPorts);
				short pidx = (short) (gWorkNext % gNPorts);
				gWorkNext++;
				StartProbe(&gSlots[i], host, pidx);
			}
		for (i = 0; i < NC_MAXSLOTS; i++)
			if (gSlots[i].busy) {
				anyBusy = true;
				if (gSlots[i].ev == T_CONNECT) FinishSlot(&gSlots[i], PR_OPEN);
				else if (gSlots[i].ev == T_DISCONNECT) FinishSlot(&gSlots[i], PR_REFUSED);
				else if (TickCount() - gSlots[i].start > gProbeTicks) FinishSlot(&gSlots[i], PR_TIMEOUT);
			}
		BuildHosts();
		if ((gWorkNext >= gWorkTotal || gStop) && !anyBusy) {
			gPhase = gStop ? NC_SWEEP_DONE : NC_SWEEP_NAMING;
			gChange++;
		}
	} else if (gPhase == NC_SWEEP_NAMING) {
		budget = 0;
		while (budget++ < 8 && TickCount() - t0 < 2) {		/* a few cheap steps, never more than ~2 ticks */
			if (gStop || !NameStep()) { gPhase = NC_SWEEP_DONE; gChange++; break; }
		}
	} else
		CollectSvc();
	return gPhase;
}

short NC_SweepPhase(void) { return gPhase; }

void NC_SweepProgress(long *done, long *total)
{
	if (gPhase == NC_SWEEP_NAMING || gPhase == NC_SWEEP_DONE) { *done = gNameIdx; *total = gNHosts; }
	else { *done = gWorkNext; *total = gWorkTotal; }
	if (*done > *total) *done = *total;
}

short NC_HostCount(void) { return gNHosts; }
const NCHost *NC_Host(short i) { return (gHosts && i >= 0 && i < gNHosts) ? &gHosts[i] : NULL; }
long NC_ChangeCount(void) { return gChange; }
long NC_ActivityCount(void) { return gActivity; }

static void App(char *buf, long *o, long max, const char *s)
{
	long j = 0;
	while (s[j] && *o < max - 1) buf[(*o)++] = s[j++];
	buf[*o] = 0;
}

long NC_BuildReport(char *buf, long max)
{
	long o = 0;
	short i, p;
	char nb[16], ipb[20], pl[16];
	App(buf, &o, max, "MacNetScan  net="); NC_IPToStr(gBase, ipb); App(buf, &o, max, ipb);
	App(buf, &o, max, "/24  found="); UToStr((unsigned long) gNHosts, nb); App(buf, &o, max, nb);
	App(buf, &o, max, CR "IP\tms\tHost name\tServices" CR);
	for (i = 0; i < gNHosts; i++) {
		Boolean any = false;
		NC_IPToStr(gHosts[i].ip, ipb); App(buf, &o, max, ipb); App(buf, &o, max, "\t");
		NC_RttToStr(gHosts[i].rttUs, nb); App(buf, &o, max, nb);
		App(buf, &o, max, "\t"); App(buf, &o, max, gHosts[i].name); App(buf, &o, max, "\t");
		for (p = 0; p < gNPorts; p++)
			if (gHosts[i].openMask & (1UL << p)) {
				if (any) App(buf, &o, max, " ");
				NC_PortLabel(p, pl); App(buf, &o, max, pl); any = true;
			}
		if (!any) App(buf, &o, max, "(alive)");
		App(buf, &o, max, CR);
	}
	return o;
}

/* ------------------------------------------------------------------ AppleTalk */

#define MAXZONES	64

static ATSvcRef	gAT = NULL;
static char		gZones[MAXZONES][34];
static short	gNZones = -1;							/* -1: not fetched yet */
static NCEntity	*gEnt = NULL;							/* heap, NC_MAXHOSTS entries */
static short	gNEnt = 0;
static short	gNbpZone = 0, gNbpTotal = 0;
static Boolean	gNbpRunning = false;
static MapperRef gMapper = NULL;

static Boolean OpenAT(void)
{
	OSStatus err;
	if (gAT) return true;
	gAT = OTOpenAppleTalkServices(kDefaultAppleTalkServicesPath, 0, &err);
	if (err != noErr || gAT == NULL) { gAT = NULL; return false; }
	return true;
}

Boolean NC_ATAvailable(void) { return OpenAT(); }

static void DDPToStr(DDPAddress *a, char *out)
{
	char nb[12];
	out[0] = 0;
	UToStr(a->fNetwork, nb); StrCat(out, nb); StrCat(out, ".");
	UToStr(a->fNodeID, nb);  StrCat(out, nb); StrCat(out, ":");
	UToStr(a->fSocket, nb);  StrCat(out, nb);
}

static void MyZone(char *out)
{
	TNetbuf mz;
	Str255 nm;
	short k;
	out[0] = 0;
	if (!OpenAT()) return;
	mz.buf = (UInt8 *) nm; mz.maxlen = sizeof(nm); mz.len = 0;
	if (OTATalkGetMyZone(gAT, &mz) == noErr) {
		for (k = 0; k < nm[0] && k < 32; k++) out[k] = (char) nm[k + 1];
		out[k] = 0;
	}
}

OSStatus NC_ATInfo(NCATInfo *info)
{
	struct AppleTalkInfo ai;				/* OT 1.1 declares it without a typedef */
	TNetbuf nb;
	OSStatus err;
	OTMemzero(info, sizeof(NCATInfo));
	if (!OpenAT()) return kOTNotFoundErr;
	nb.buf = (UInt8 *) &ai; nb.maxlen = sizeof(ai); nb.len = 0;
	err = OTATalkGetInfo(gAT, &nb);
	if (err != noErr) return err;
	DDPToStr(&ai.fOurAddress, info->address);
	if (ai.fFlags & kATalkInfoHasRouter) DDPToStr(&ai.fRouterAddress, info->router);
	info->cableLow = ai.fCableRange[0];
	info->cableHigh = ai.fCableRange[1];
	info->isExtended = (ai.fFlags & kATalkInfoIsExtended) ? true : false;
	MyZone(info->zone);
	return noErr;
}

static void FetchZones(void)
{
	TNetbuf zb;
	Ptr buf;
	long p;
	short k;
	gNZones = 0;
	if (!OpenAT()) return;
	buf = NewPtr(8192);
	if (!buf) return;
	zb.buf = (UInt8 *) buf; zb.maxlen = 8192; zb.len = 0;
	if (OTATalkGetZoneList(gAT, &zb) == noErr) {
		p = 0;
		while (p < (long) zb.len && gNZones < MAXZONES) {
			short len = ((unsigned char *) buf)[p];
			if (len == 0) break;
			for (k = 0; k < len && k < 32; k++) gZones[gNZones][k] = buf[p + 1 + k];
			gZones[gNZones][k] = 0;
			TrimRight(gZones[gNZones]);
			if (gZones[gNZones][0]) gNZones++;
			p += 1 + len;
		}
	}
	DisposePtr(buf);
}

short NC_ZoneCount(void) { if (gNZones < 0) FetchZones(); return gNZones; }
const char *NC_Zone(short i) { return (i >= 0 && i < NC_ZoneCount()) ? gZones[i] : ""; }

/* one NBP lookup of "=:=@zone" (Inside Macintosh: OT - OTLookupName is a MAPPER call); appends the entities */
static void NbpLookupZone(const char *zone)
{
	UInt8 nameBuf[128];
	char nbpStr[80];
	long nameLen;
	Ptr rbuf;
	TLookupRequest req;
	TLookupReply reply;
	OSStatus err;

	nbpStr[0] = 0; StrCat(nbpStr, "=:=@"); StrCat(nbpStr, zone);
	nameLen = OTSetAddressFromNBPString(nameBuf, nbpStr, -1);
	rbuf = NewPtr(8192);
	if (rbuf == NULL) return;
	OTMemzero(&req, sizeof(req)); OTMemzero(&reply, sizeof(reply));
	req.name.buf = nameBuf; req.name.len = nameLen;
	req.addr.buf = NULL; req.addr.len = 0;
	req.maxcnt = 200; req.timeout = 1000; req.flags = 0;
	reply.names.buf = (UInt8 *) rbuf; reply.names.maxlen = 8192; reply.names.len = 0;
	err = OTLookupName(gMapper, &req, &reply);
	if (err == noErr && reply.rspcount > 0) {
		char *base = (char *) rbuf;
		long avail = (long) reply.names.len, off = 0, n;
		for (n = 0; n < (long) reply.rspcount && gNEnt < NC_MAXHOSTS; n++) {
			TLookupBuffer *lb;
			UInt8 *ab, *nmp;
			NBPEntity ent;
			NCEntity *e;
			long alen, nlen, rec;
			/* never walk past what OT returned, never hand OT a name longer than an NBPEntity (ipscan.c hardening) */
			if (off + (long) sizeof(TLookupBuffer) > avail) break;
			lb = (TLookupBuffer *) (base + off);
			alen = (long) lb->fAddressLength;
			nlen = (long) lb->fNameLength;
			rec = 4 + alen + nlen;
			if (alen < 0 || nlen < 0 || nlen > 96 || off + rec > avail) break;
			ab = lb->fAddressBuffer;
			nmp = ab + alen;
			OTSetNBPEntityFromAddress(&ent, nmp, (size_t) nlen);
			e = &gEnt[gNEnt++];
			e->object[0] = e->type[0] = e->zone[0] = 0;
			OTExtractNBPName(&ent, e->object);
			OTExtractNBPType(&ent, e->type);
			OTExtractNBPZone(&ent, e->zone);
			if (!e->zone[0]) StrCopy(e->zone, zone, sizeof(e->zone));
			DDPToStr((DDPAddress *) ab, e->address);
			e->net = ((DDPAddress *) ab)->fNetwork;
			e->node = ((DDPAddress *) ab)->fNodeID;
			e->socket = ((DDPAddress *) ab)->fSocket;
			e->rttUs = -2;
			e->info[0] = 0;
			off += (rec + 3) & ~3L;
		}
	}
	DisposePtr(rbuf);
}

/* ---- after NBP: an AEP echo to every node (DDP type 4 to socket 4), an ASP GetStatus to every AFP server (ATP to
   its session listening socket). Both on endpoints of their own, non-blocking, one question at a time. */

enum { PROBE_ECHO, PROBE_ASP, PROBE_DONE };
static EndpointRef		gDdpEp = NULL, gAtpEp = NULL;
static short			gProbePass = PROBE_DONE, gProbeIdx = 0;
static Boolean			gProbeWait = false;
static unsigned long	gProbeT0 = 0;
static OTTimeStamp		gProbeStamp;
static UInt8			gProbeBuf[600];
static OTSequence		gAspSeq = 0;

static EndpointRef OpenAtEp(const char *config)
{
	EndpointRef ep;
	OSStatus err;
	TBind req;
	ep = OTOpenEndpoint(OTCreateConfiguration(config), 0, NULL, &err);
	if (err != noErr || ep == NULL) return NULL;
	OTMemzero(&req, sizeof(req));								/* any free socket */
	if (OTBind(ep, &req, NULL) != noErr) { OTCloseProvider(ep); return NULL; }
	OTSetNonBlocking(ep);
	return ep;
}

static void ProbeEnd(void)
{
	if (gDdpEp) { OTCloseProvider(gDdpEp); gDdpEp = NULL; }
	if (gAtpEp) { OTCloseProvider(gAtpEp); gAtpEp = NULL; }
	gProbePass = PROBE_DONE;
	gProbeWait = false;
}

static void ProbeBegin(void)
{
	ProbeEnd();
	gDdpEp = OpenAtEp(kDDPName);
	gAtpEp = OpenAtEp(kATPName);
	gProbePass = (gDdpEp || gAtpEp) ? PROBE_ECHO : PROBE_DONE;
	gProbeIdx = 0;
}

static void SetNodeRtt(UInt16 net, UInt8 node, long us)		/* every entity on that node shares the answer */
{
	short i;
	for (i = 0; i < gNEnt; i++) if (gEnt[i].net == net && gEnt[i].node == node && gEnt[i].rttUs < 0) gEnt[i].rttUs = us;
}

static void CatMax(char *dst, const char *src, short max)		/* StrCat, cut at max - 1 */
{
	short i = 0, j = 0;
	while (dst[i] && i < max - 1) i++;
	while (src[j] && i < max - 1) dst[i++] = src[j++];
	dst[i] = 0;
}

static void CatPStr(char *dst, const UInt8 *p, short max)
{
	char t[64];
	short n = p[0], i;
	if (n > 63) n = 63;
	for (i = 0; i < n; i++) t[i] = (char) (p[i + 1] >= ' ' && p[i + 1] < 127 ? p[i + 1] : '?');
	t[n] = 0;
	CatMax(dst, t, max);
}

	/* An AFP status block (FPGetSrvrInfo): offsets of machine type, AFP versions, UAMs, the volume icon, then flags
	   and the server name. OT may or may not hand the 4 ATP user bytes on in front: take the base that parses. */
static Boolean AfpInfo(const UInt8 *b, long n, char *out, short max)
{
	static const char *kFlag[] = { "CopyFile", "change password", "no saved login", "server messages",
								   "signature", "TCP/IP", "notifications", "reconnect" };
	long base, mt, vo, uo, k;
	unsigned short flags;
	short i, cnt;
	for (base = 0; base <= 4; base += 4) {
		if (n - base < 12) continue;
		mt = (b[base] << 8) | b[base + 1]; vo = (b[base + 2] << 8) | b[base + 3]; uo = (b[base + 4] << 8) | b[base + 5];
		if (b[base + 10] == 0 || base + 11 + b[base + 10] > n) continue;
		if (mt < 11 || vo < 11 || uo < 11 || base + mt >= n || base + vo >= n || base + uo >= n) continue;
		flags = (unsigned short) ((b[base + 8] << 8) | b[base + 9]);
		out[0] = 0;
		if (base + mt + 1 + b[base + mt] <= n) CatPStr(out, b + base + mt, max);
		CatMax(out, "   ", max);
		cnt = b[base + vo]; k = base + vo + 1;
		CatMax(out, "AFP ", max);
		for (i = 0; i < cnt && k < n && k + 1 + b[k] <= n; i++) {		/* "AFPVersion 2.1", "AFP3.3", "AFPX03": the number */
			UInt8 v[40];
			short s = 0, m = b[k];
			if (m > 39) m = 39;
			if (m > 11 && b[k + 1] == 'A' && b[k + 4] == 'V') s = 11;		/* "AFPVersion " */
			else if (m > 3 && b[k + 1] == 'A' && b[k + 2] == 'F' && b[k + 3] == 'P') s = 3;
			v[0] = (UInt8) (m - s); BlockMove(b + k + 1 + s, v + 1, m - s);
			if (i) CatMax(out, " ", max);
			CatPStr(out, v, max);
			k += 1 + b[k];
		}
		CatMax(out, "   UAM ", max);
		cnt = b[base + uo]; k = base + uo + 1;
		for (i = 0; i < cnt && k < n && k + 1 + b[k] <= n; i++) { if (i) CatMax(out, ", ", max); CatPStr(out, b + k, max); k += 1 + b[k]; }
		for (i = 0; i < 8; i++) if (flags & (1 << i)) { CatMax(out, i == 0 ? "   " : ", ", max); CatMax(out, kFlag[i], max); }
		return true;
	}
	return false;
}

static void ProbeStep(void)
{
	NCEntity *e;
	TUnitData ud;
	OTFlags flags;
	OTResult res;
	if (gProbeWait) {
		e = &gEnt[gProbeIdx];
		if (gProbePass == PROBE_ECHO) {
			DDPAddress from;
			OTTimeStamp now;
			for (;;) {												/* the echo replies so far */
				OTMemzero(&ud, sizeof(ud));
				ud.addr.buf = (UInt8 *) &from; ud.addr.maxlen = sizeof(from);
				ud.udata.buf = gProbeBuf; ud.udata.maxlen = sizeof(gProbeBuf);
				flags = 0;
				res = OTRcvUData(gDdpEp, &ud, &flags);
				if (res == kOTLookErr) { if (OTLook(gDdpEp) == T_UDERR) OTRcvUDErr(gDdpEp, NULL); break; }
				if (res != noErr) break;
				if (ud.udata.len < 1 || gProbeBuf[0] != 2) continue;	/* AEP reply */
				OTGetTimeStamp(&now);
				SetNodeRtt(from.fNetwork, from.fNodeID, StampUs(&gProbeStamp, &now));
				gChange++;
			}
			if (e->rttUs >= 0 || TickCount() - gProbeT0 > 60) {
				SetNodeRtt(e->net, e->node, -1);					/* no answer within a second */
				gProbeWait = false; gProbeIdx++; gChange++;
			}
		} else {
			TUnitReply rp;
			OTMemzero(&rp, sizeof(rp));
			rp.udata.buf = gProbeBuf; rp.udata.maxlen = sizeof(gProbeBuf);
			flags = 0;
			res = OTRcvUReply(gAtpEp, &rp, &flags);
			if (res == noErr) {
				if (!AfpInfo(gProbeBuf, (long) rp.udata.len, e->info, sizeof(e->info))) StrCopy(e->info, "(status not readable)", sizeof(e->info));
			} else if (res == kOTLookErr || TickCount() - gProbeT0 > 240) {
				if (res == kOTLookErr && OTLook(gAtpEp) == T_UDERR) OTRcvUDErr(gAtpEp, NULL);
				StrCopy(e->info, "(no answer to ASP GetStatus)", sizeof(e->info));
				OTCloseProvider(gAtpEp); gAtpEp = OpenAtEp(kATPName);	/* drop what is still outstanding */
			} else return;
			gProbeWait = false; gProbeIdx++; gChange++;
		}
		return;
	}
	while (gProbePass != PROBE_DONE) {
		if (gProbeIdx >= gNEnt) { gProbePass++; gProbeIdx = 0; continue; }
		e = &gEnt[gProbeIdx];
		if (gProbePass == PROBE_ECHO) {
			DDPAddress to;
			UInt8 msg[4];
			if (!gDdpEp || e->rttUs != -2) { gProbeIdx++; continue; }	/* this node has answered already */
			OTInitDDPAddress(&to, e->net, e->node, 4, 4);			/* the echoer, DDP type 4 */
			msg[0] = 1; msg[1] = 'M'; msg[2] = 'N'; msg[3] = 'S';	/* 1: echo request */
			OTMemzero(&ud, sizeof(ud));
			ud.addr.buf = (UInt8 *) &to; ud.addr.len = sizeof(to);
			ud.udata.buf = msg; ud.udata.len = sizeof(msg);
			OTGetTimeStamp(&gProbeStamp);
			if (OTSndUData(gDdpEp, &ud) != noErr) { SetNodeRtt(e->net, e->node, -1); gProbeIdx++; continue; }
		} else {
			DDPAddress to;
			TUnitRequest rq;
			UInt8 ub[4];
			if (!gAtpEp || !StrEq(e->type, "AFPServer")) { gProbeIdx++; continue; }
			OTInitDDPAddress(&to, e->net, e->node, e->socket, 3);	/* ATP to the session listening socket */
			ub[0] = 3; ub[1] = ub[2] = ub[3] = 0;					/* the user bytes: SPGetStatus */
			OTMemzero(&rq, sizeof(rq));
			rq.addr.buf = (UInt8 *) &to; rq.addr.len = sizeof(to);
			rq.udata.buf = ub; rq.udata.len = sizeof(ub);
			rq.sequence = ++gAspSeq;								/* ours to choose; 0 is kOTBadSequenceErr */
			{
				OSStatus err = OTSndURequest(gAtpEp, &rq, 0);
				if (err != noErr) {
					char nb[12];
					StrCopy(e->info, "(ASP request failed, OT ", sizeof(e->info));
					if (err < 0) { StrCat(e->info, "-"); err = -err; }
					UToStr((unsigned long) err, nb); StrCat(e->info, nb); StrCat(e->info, ")");
					gProbeIdx++; continue;
				}
			}
		}
		gProbeWait = true;
		gProbeT0 = TickCount();
		return;
	}
	ProbeEnd();
}

void NC_NbpStart(void)
{
	OSStatus err;
	ProbeEnd();
	if (!gEnt) gEnt = (NCEntity *) NewPtrClear((long) NC_MAXHOSTS * sizeof(NCEntity));
	gNEnt = 0;
	gNbpZone = 0;
	gNbpTotal = NC_ZoneCount();
	if (gNbpTotal == 0) gNbpTotal = 1;					/* flat network: "*" only */
	if (!gMapper) gMapper = OTOpenMapper(OTCreateConfiguration(kNBPName), 0, &err);
	gNbpRunning = (gEnt != NULL && gMapper != NULL);
}

Boolean NC_NbpIdle(void)
{
	if (gNbpRunning) {
		NbpLookupZone(gNZones > 0 ? gZones[gNbpZone] : "*");
		gChange++;
		if (++gNbpZone >= gNbpTotal) { gNbpRunning = false; ProbeBegin(); }
		return true;
	}
	if (gProbePass == PROBE_DONE) return false;
	ProbeStep();
	return true;												/* one more call reports the end */
}

void NC_NbpProgress(short *done, short *total)					/* zones, then each entity twice: echo, ASP */
{
	*total = (short) (gNbpTotal + 2 * gNEnt);
	*done = gNbpRunning ? gNbpZone : gProbePass == PROBE_DONE ? *total : (short) (gNbpTotal + gProbePass * gNEnt + gProbeIdx);
}

	/* PBXGetVolInfo (System 7.5.2 on): sizes in 64 bits - the 16-bit block counts of PBHGetVInfo stop at 2 GB. The
	   1994 headers lack it; this is its declaration from later Files.h, the layout of an XVolumeParam. */
typedef struct {
	QElemPtr		qLink;
	short			qType, ioTrap;
	Ptr				ioCmdAddr;
	ProcPtr			ioCompletion;
	OSErr			ioResult;
	StringPtr		ioNamePtr;
	short			ioVRefNum;
	unsigned long	ioXVersion;
	short			ioVolIndex;
	unsigned long	ioVCrDate, ioVLsMod;
	short			ioVAtrb;
	unsigned short	ioVNmFls, ioVBitMap, ioAllocPtr, ioVNmAlBlks;
	unsigned long	ioVAlBlkSiz, ioVClpSiz;
	unsigned short	ioAlBlSt;
	unsigned long	ioVNxtCNID;
	unsigned short	ioVFrBlk, ioVSigWord;
	short			ioVDrvInfo, ioVDRefNum, ioVFSID;
	unsigned long	ioVBkUp;
	short			ioVSeqNum;
	unsigned long	ioVWrCnt, ioVFilCnt, ioVDirCnt;
	long			ioVFndrInfo[8];
	unsigned long	ioVTotalHi, ioVTotalLo, ioVFreeHi, ioVFreeLo;
} XVolParam;
#pragma parameter __D0 MNSXGetVolInfo(__A0)
pascal OSErr MNSXGetVolInfo(XVolParam *pb) = { 0x7012, 0xA260 };	/* MOVEQ #$12,D0; _HFSDispatch */

	/* the mounted volumes: an AppleShare volume tells its server's AppleTalk address through GetVolParms */
static NCVolume gVol[16];
static short gNVol = 0;

void NC_VolumeRead(void)
{
	HParamBlockRec pb;
	GetVolParmsInfoBuffer vp;
	Str255 name;
	short i, k;
	gNVol = 0;
	for (i = 1; gNVol < 16; i++) {
		OTMemzero(&pb, sizeof(pb));
		name[0] = 0;
		pb.volumeParam.ioNamePtr = name;
		pb.volumeParam.ioVolIndex = i;
		if (PBHGetVInfoSync(&pb) != noErr) break;
		for (k = 0; k < name[0] && k < 31; k++) gVol[gNVol].name[k] = (char) name[k + 1];
		gVol[gNVol].name[k] = 0;
		gVol[gNVol].totalK = (long) pb.volumeParam.ioVNmAlBlks * (pb.volumeParam.ioVAlBlkSiz / 512) / 2;
		gVol[gNVol].freeK = (long) pb.volumeParam.ioVFrBlk * (pb.volumeParam.ioVAlBlkSiz / 512) / 2;
		gVol[gNVol].serverAdr = 0;
		gVol[gNVol].locked = (Boolean) ((pb.volumeParam.ioVAtrb & 0x8080) != 0);	/* hardware or software lock */
		{
			XVolParam xp;
			OTMemzero(&xp, sizeof(xp));
			xp.ioVRefNum = pb.volumeParam.ioVRefNum;
			if (MNSXGetVolInfo(&xp) == noErr && (xp.ioVTotalHi || xp.ioVTotalLo)) {	/* bytes to KB */
				gVol[gNVol].totalK = (long) ((xp.ioVTotalHi << 22) | (xp.ioVTotalLo >> 10));
				gVol[gNVol].freeK = (long) ((xp.ioVFreeHi << 22) | (xp.ioVFreeLo >> 10));
			}
		}
		OTMemzero(&vp, sizeof(vp));
		pb.ioParam.ioNamePtr = NULL;
		pb.ioParam.ioBuffer = (Ptr) &vp;
		pb.ioParam.ioReqCount = sizeof(vp);
		if (PBHGetVolParmsSync(&pb) == noErr) gVol[gNVol].serverAdr = (unsigned long) vp.vMServerAdr;
		gNVol++;
	}
}

short NC_VolumeCount(void) { return gNVol; }

const NCVolume *NC_Volume(short i) { return (i >= 0 && i < gNVol) ? &gVol[i] : NULL; }
short NC_EntityCount(void) { return gNEnt; }
const NCEntity *NC_Entity(short i) { return (gEnt && i >= 0 && i < gNEnt) ? &gEnt[i] : NULL; }

/* ------------------------------------------------------------------ tools */

#define MAXLINES	32
enum { TOOL_PING = 1, TOOL_DNS, TOOL_TRACE };

static short		gTool = 0, gToolState = NC_TOOL_IDLE;
static char			gToolHost[80], gToolMsg[256];
static InetHost		gToolIP = 0;
static UInt16		gToolPort = 80;
static short		gToolCount = 8, gToolSeq = 0;
static NCToolLine	gLines[MAXLINES];
static short		gNLines = 0;
static long			gToolStart = 0;
static Boolean		gToolStop = false;

static InetSvcRef		gTSvc = NULL;					/* forward and reverse lookups for the tools */
static volatile Boolean	gTSvcDone = false;
static volatile OTResult gTSvcResult = 0;
static Boolean			gTSvcBusy = false;
static InetHostInfo		gTHostInfo;
static InetDomainName	gTName;

static EndpointRef			gPingEp = NULL;
static volatile OTEventCode	gPingEv = 0;
static OTTimeStamp			gPingT0, gPingT1;			/* connect issued / answered (notifier) */
static EndpointRef			gRaw = NULL;				/* ICMP for traceroute */
static OTTimeStamp			gRawT0, gRawT1;				/* probe sent / first datagram arrived (notifier) */
static volatile Boolean		gRawGot = false;
static short				gStep = 0;				/* 0 = start the next round, 1 = waiting, 2 = naming the hop */

static pascal void TSvcNotifier(void *ctx, OTEventCode code, OTResult r, void *ck)
{
	if (ctx || ck) {}
	if (code == T_DNRSTRINGTOADDRCOMPLETE || code == T_DNRADDRTONAMECOMPLETE) { gTSvcResult = r; gTSvcDone = true; }
}

static pascal void PingNotifier(void *ctx, OTEventCode code, OTResult r, void *ck)
{
	if (ctx || r || ck) {}
	if ((code == T_CONNECT || code == T_DISCONNECT) && gPingEv == 0) { OTGetTimeStamp(&gPingT1); gPingEv = code; }
}

static pascal void RawNotifier(void *ctx, OTEventCode code, OTResult r, void *ck)
{
	if (ctx || r || ck) {}
	if (code == T_DATA && !gRawGot) { OTGetTimeStamp(&gRawT1); gRawGot = true; }
}

static Boolean OpenTSvc(void)
{
	OSStatus err;
	if (gTSvc) return true;
	gTSvc = OTOpenInternetServices(kDefaultInternetServicesPath, 0, &err);
	if (err != noErr || gTSvc == NULL) { gTSvc = NULL; return false; }
	if (OTInstallNotifier(gTSvc, TSvcNotifier, NULL) != noErr || OTSetAsynchronous(gTSvc) != noErr) {
		OTCloseProvider(gTSvc); gTSvc = NULL; return false;
	}
	return true;
}

static void ClosePing(void)
{
	if (!gPingEp) return;
	OTRemoveNotifier(gPingEp);
	OTCloseProvider(gPingEp);
	gPingEp = NULL;
}

static void ToolBegin(short tool, const char *host)
{
	NC_ToolStop();
	gTool = tool;
	StrCopy(gToolHost, host, sizeof(gToolHost));
	gToolMsg[0] = 0;
	gNLines = 0; gToolSeq = 0; gStep = 0; gToolStop = false;
	gToolIP = 0;										/* not the last target's: the status line shows it */
	if (ParseDotted(host, &gToolIP)) { gToolState = (tool == TOOL_DNS) ? NC_TOOL_RESOLVING : NC_TOOL_RUNNING; }
	else gToolState = NC_TOOL_RESOLVING;
	if (gToolState == NC_TOOL_RESOLVING) {
		if (gTSvcBusy || !OpenTSvc()) { gToolState = NC_TOOL_FAILED; StrCopy(gToolMsg, "DNS is not available.", 256); return; }
		OTMemzero(&gTHostInfo, sizeof(gTHostInfo));
		gTSvcDone = false;
		if (tool == TOOL_DNS && ParseDotted(host, &gToolIP)) {
			gTName[0] = 0;
			if (OTInetAddressToName(gTSvc, gToolIP, gTName) == noErr) gTSvcBusy = true;
		} else if (OTInetStringToAddress(gTSvc, gToolHost, &gTHostInfo) == noErr) gTSvcBusy = true;
		if (!gTSvcBusy) { gToolState = NC_TOOL_FAILED; StrCopy(gToolMsg, "Lookup could not start.", 256); }
		gToolStart = TickCount();
	}
}

void NC_PingStart(const char *host, UInt16 port, short count)
{
	gToolPort = port ? port : 80;
	gToolCount = (count > 0 && count <= MAXLINES) ? count : 8;
	ToolBegin(TOOL_PING, host);
}
void NC_DnsStart(const char *host) { ToolBegin(TOOL_DNS, host); }
void NC_TraceStart(const char *host) { gToolCount = 30; ToolBegin(TOOL_TRACE, host); }

void NC_ToolStop(void)
{
	gToolStop = true;
	ClosePing();
	if (gRaw) { OTCloseProvider(gRaw); gRaw = NULL; }
	if (gToolState == NC_TOOL_RESOLVING || gToolState == NC_TOOL_RUNNING) gToolState = NC_TOOL_DONE;
}

static Boolean PingSend(void)
{
	OSStatus err;
	InetAddress addr, local;
	TCall call;
	TBind bindReq;
	gPingEp = OTOpenEndpoint(OTCreateConfiguration(kTCPName), 0, NULL, &err);
	if (err != noErr || gPingEp == NULL) { gPingEp = NULL; return false; }
	OTMemzero(&local, sizeof(local)); OTInitInetAddress(&local, 0, kOTAnyInetAddress);
	bindReq.addr.buf = (UInt8 *) &local; bindReq.addr.len = sizeof(local); bindReq.qlen = 0;
	if (OTBind(gPingEp, &bindReq, NULL) != noErr) { OTCloseProvider(gPingEp); gPingEp = NULL; return false; }
	gPingEv = 0;
	if (OTInstallNotifier(gPingEp, PingNotifier, NULL) != noErr) { OTCloseProvider(gPingEp); gPingEp = NULL; return false; }
	OTSetAsynchronous(gPingEp);
	OTMemzero(&addr, sizeof(addr)); OTInitInetAddress(&addr, gToolPort, gToolIP);
	OTMemzero(&call, sizeof(call)); call.addr.buf = (UInt8 *) &addr; call.addr.len = sizeof(addr);
	OTGetTimeStamp(&gPingT0);
	err = OTConnect(gPingEp, &call, NULL);
	if (err != noErr && err != kOTNoDataErr) { ClosePing(); return false; }
	return true;
}

static UInt16 ICMPChecksum(UInt8 *p, short n)
{
	long sum = 0;
	short i;
	for (i = 0; i + 1 < n; i += 2) sum += ((long) p[i] << 8) | p[i + 1];
	if (i < n) sum += (long) p[i] << 8;
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	return (UInt16) (~sum);
}

static void SetTTL(EndpointRef ep, short ttl)
{
	struct { UInt32 len; UInt32 level; UInt32 name; UInt32 status; UInt32 value; } opt;
	TOptMgmt req, ret;
	opt.len = sizeof(opt); opt.level = INET_IP; opt.name = IP_TTL; opt.status = 0; opt.value = ttl;
	req.opt.buf = (UInt8 *) &opt; req.opt.len = sizeof(opt); req.flags = T_NEGOTIATE;
	ret.opt.buf = (UInt8 *) &opt; ret.opt.maxlen = sizeof(opt);
	OTOptionManagement(ep, &req, &ret);
}

static Boolean IcmpSend(short ttl, UInt16 seq)
{
	OSStatus err;
	InetAddress to, local;
	TBind bindReq;
	TUnitData snd;
	UInt8 msg[40];
	short k;
	UInt16 ck;
	if (!gRaw) {
		gRaw = OTOpenEndpoint(OTCreateConfiguration(kRawIPName), 0, NULL, &err);
		if (err != noErr || gRaw == NULL) { gRaw = NULL; return false; }
		OTMemzero(&local, sizeof(local)); OTInitInetAddress(&local, 0, kOTAnyInetAddress);
		bindReq.addr.buf = (UInt8 *) &local; bindReq.addr.len = sizeof(local); bindReq.qlen = 0;
		if (OTBind(gRaw, &bindReq, NULL) != noErr) { OTCloseProvider(gRaw); gRaw = NULL; return false; }
		OTSetNonBlocking(gRaw);
		OTInstallNotifier(gRaw, RawNotifier, NULL);		/* only stamps arrivals; reading stays with IcmpPoll */
	}
	SetTTL(gRaw, ttl);
	OTMemzero(msg, sizeof(msg));
	msg[0] = 8; msg[1] = 0;
	msg[4] = 0x49; msg[5] = 0x54;
	msg[6] = (UInt8) (seq >> 8); msg[7] = (UInt8) seq;
	for (k = 8; k < 40; k++) msg[k] = (UInt8) k;
	ck = ICMPChecksum(msg, 40); msg[2] = (UInt8) (ck >> 8); msg[3] = (UInt8) ck;
	OTMemzero(&to, sizeof(to)); OTInitInetAddress(&to, 0, gToolIP);
	OTMemzero(&snd, sizeof(snd));
	snd.addr.buf = (UInt8 *) &to; snd.addr.len = sizeof(to);
	snd.udata.buf = msg; snd.udata.len = 40;
	gRawGot = false;
	OTGetTimeStamp(&gRawT0);
	return OTSndUData(gRaw, &snd) == noErr;
}

/* an ICMP reply if one is there: its type (0 echo reply, 11 time exceeded), -1 if none */
static short IcmpPoll(InetHost *from)
{
	UInt8 rep[256];
	InetAddress f;
	TUnitData rcv;
	OTFlags flags;
	OTResult res;
	short off;
	if (!gRaw) return -1;
	OTMemzero(&rcv, sizeof(rcv)); OTMemzero(&f, sizeof(f));
	rcv.addr.buf = (UInt8 *) &f; rcv.addr.maxlen = sizeof(f);
	rcv.udata.buf = rep; rcv.udata.maxlen = sizeof(rep); flags = 0;
	res = OTRcvUData(gRaw, &rcv, &flags);
	if (res == noErr) {
		if (!gRawGot) OTGetTimeStamp(&gRawT1);		/* no notifier stamp: the read itself is the latest it arrived */
		gRawGot = false;
		off = ((rep[0] & 0xF0) == 0x40) ? (short) ((rep[0] & 0x0F) * 4) : 0;
		*from = f.fHost;
		return rep[off];
	}
	if (res == kOTLookErr && OTLook(gRaw) == T_UDERR) OTRcvUDErr(gRaw, NULL);
	return -1;
}

static NCToolLine *NewLine(void)
{
	NCToolLine *l;
	if (gNLines >= MAXLINES) return &gLines[MAXLINES - 1];
	l = &gLines[gNLines++];
	OTMemzero(l, sizeof(NCToolLine));
	l->rttUs = -1;
	return l;
}

static void DnsAnswer(void)
{
	short i;
	char ab[20];
	gToolMsg[0] = 0;
	if (gTSvcResult != noErr) { StrCopy(gToolMsg, "Lookup failed.", 256); gToolState = NC_TOOL_FAILED; return; }
	if (ParseDotted(gToolHost, &gToolIP)) {				/* reverse: the name */
		NCToolLine *l = NewLine();
		l->ip = gToolIP;
		StrCopy(l->name, gTName, NC_NAMELEN);
		StrCopy(gToolMsg, gTName, 256);
	} else {
		StrCopy(gToolMsg, gTHostInfo.name, 256);
		gToolIP = gTHostInfo.addrs[0];						/* the first answer is the target */
		for (i = 0; i < kMaxHostAddrs && gTHostInfo.addrs[i]; i++) {
			NCToolLine *l = NewLine();
			l->seq = i + 1; l->ip = gTHostInfo.addrs[i];
			NC_IPToStr(l->ip, ab); StrCopy(l->name, ab, NC_NAMELEN);
		}
	}
	gToolState = NC_TOOL_DONE;
}

short NC_ToolIdle(void)
{
	if (gToolState == NC_TOOL_RESOLVING) {
		if (!gTSvcDone) {
			if (TickCount() - gToolStart > 20 * TICKS_PER_SEC) { gToolState = NC_TOOL_FAILED; StrCopy(gToolMsg, "Lookup timed out.", 256); }
			return gToolState;
		}
		gTSvcBusy = false;
		if (gTool == TOOL_DNS) { DnsAnswer(); return gToolState; }
		if (gTSvcResult != noErr || gTHostInfo.addrs[0] == 0) {
			gToolState = NC_TOOL_FAILED; StrCopy(gToolMsg, "Cannot resolve that host.", 256); return gToolState;
		}
		gToolIP = gTHostInfo.addrs[0];
		gToolState = NC_TOOL_RUNNING;
	}
	if (gToolState != NC_TOOL_RUNNING) return gToolState;
	if (gToolStop) { NC_ToolStop(); return gToolState; }

	if (gTool == TOOL_PING) {
		if (gStep == 0) {
			if (gToolSeq >= gToolCount) { gToolState = NC_TOOL_DONE; return gToolState; }
			if (TickCount() - gToolStart < 30 && gToolSeq > 0) return gToolState;	/* half a second apart */
			gToolSeq++;
			gToolStart = TickCount();
			if (!PingSend()) { NCToolLine *l = NewLine(); l->seq = gToolSeq; l->ip = gToolIP; gToolStart = TickCount(); return gToolState; }
			gStep = 1;
		} else {
			long el = TickCount() - gToolStart;
			if (gPingEv == T_CONNECT || gPingEv == T_DISCONNECT || el > 120) {
				NCToolLine *l = NewLine();
				l->seq = gToolSeq; l->ip = gToolIP;
				if (gPingEv) { l->rttUs = StampUs(&gPingT0, &gPingT1); l->alive = true; gActivity++; }
				if (gPingEv == T_CONNECT) OTSndDisconnect(gPingEp, NULL);
				else if (gPingEv == T_DISCONNECT) OTRcvDisconnect(gPingEp, NULL);
				else OTSndDisconnect(gPingEp, NULL);
				ClosePing();
				gStep = 0; gToolStart = TickCount();
			}
		}
	} else if (gTool == TOOL_TRACE) {
		if (gStep == 0) {
			if (gToolSeq >= gToolCount) { gToolState = NC_TOOL_DONE; return gToolState; }
			gToolSeq++;
			gToolStart = TickCount();
			if (!IcmpSend(gToolSeq, (UInt16) gToolSeq)) {
				gToolState = NC_TOOL_FAILED; StrCopy(gToolMsg, "ICMP is not available.", 256); return gToolState;
			}
			gStep = 1;
		} else if (gStep == 1) {
			InetHost from = 0;
			short type = IcmpPoll(&from);
			long el = TickCount() - gToolStart;
			if (type >= 0 || el > 180) {
				NCToolLine *l = NewLine();
				l->seq = gToolSeq;
				if (type >= 0) {
					l->ip = from; l->rttUs = StampUs(&gRawT0, &gRawT1); gActivity++;
					if (!gTSvcBusy && OpenTSvc()) {
						gTName[0] = 0; gTSvcDone = false;
						if (OTInetAddressToName(gTSvc, from, gTName) == noErr) { gTSvcBusy = true; gStep = 2; gToolStart = TickCount(); }
					}
					if (from == gToolIP || type == 0) gToolCount = gToolSeq;	/* reached: stop after naming */
				}
				if (gStep == 1) gStep = 0;
				if (gStep == 0 && gToolCount == gToolSeq) gToolState = NC_TOOL_DONE;
			}
		} else {
			if (gTSvcDone || TickCount() - gToolStart > 120) {
				if (gTSvcDone) {
					gTSvcBusy = false;
					if (gTSvcResult == noErr && gNLines > 0) StrCopy(gLines[gNLines - 1].name, gTName, NC_NAMELEN);
				}
				gStep = 0;
				if (gToolCount == gToolSeq) gToolState = NC_TOOL_DONE;
			}
		}
	}
	return gToolState;
}

short NC_ToolState(void) { return gToolState; }
const char *NC_ToolHost(void) { return gToolHost; }
short NC_ToolLineCount(void) { return gNLines; }
const NCToolLine *NC_ToolLine(short i) { return (i >= 0 && i < gNLines) ? &gLines[i] : NULL; }
InetHost NC_ToolTarget(void) { return gToolIP; }
const char *NC_ToolMessage(void) { return gToolMsg; }

/* ------------------------------------------------------------------ listen: what reaches this Mac anyway */

/* Passive: Ethernet endpoints bound to ARP, IPv4, IPv6, LLDP, and AppleTalk and AARP over 802.2 SNAP, read without
   blocking. Measured under Basilisk II (MacNetScan2/probe/sniff_main.c, six runs): binds and receives are safe beside
   the TCP/IP stack; OPT_SETRAWMODE and OPT_SETPROMISCUOUS answer TBADOPT at level LNK_ENET and NEVER RETURN at LNK_TPI,
   and the I_OTSetRawMode ioctl never returns either - both froze the guest. They would add nothing: etherhelper reads
   the host card promiscuously and Basilisk hands on every frame. Open Transport does drop multicast groups nobody
   joined (the multicast meter stayed 0 beside mDNS on the wire); OPT_ADDMCAST at LNK_TPI joins one - noErr, T_SUCCESS,
   no hang (run 6, 2026-10-28) - and mDNS, IPv6 multicast and LLDP arrive. Frames come without their MAC header: the
   sender's MAC is the receive address, the protocol the bound SAP. */

#define NC_MAXSTATIONS	128
#define NC_MAXEDGES		256
#define NC_EVENTLEN		80
#define LS_BUFSIZE		1600

enum { LS_ARP = 0, LS_IP, LS_DDP, LS_AARP, LS_IP6, LS_LLDP, LS_COUNT };
static const UInt16 kLsSap[LS_COUNT] = { 0x0806, 0x0800, 0x00AA, 0x00AA, 0x86DD, 0x88CC };
static const UInt8 kLsSnap[LS_COUNT][5] = {
	{ 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
	{ 0x08, 0x00, 0x07, 0x80, 0x9B },				/* AppleTalk Phase 2 */
	{ 0x00, 0x00, 0x00, 0x80, 0xF3 },				/* AARP */
	{ 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 }
};

static const struct { short ep; UInt8 group[6]; } kLsJoin[] = {
	{ LS_IP,   { 0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB } },		/* mDNS 224.0.0.251 */
	{ LS_IP6,  { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 } },		/* IPv6 all nodes */
	{ LS_IP6,  { 0x33, 0x33, 0x00, 0x00, 0x00, 0xFB } },		/* mDNS ff02::fb */
	{ LS_LLDP, { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E } },		/* LLDP nearest bridge */
	{ LS_DDP,  { 0x09, 0x00, 0x07, 0xFF, 0xFF, 0xFF } },		/* AppleTalk broadcast: RTMP, NBP, ZIP */
	{ LS_AARP, { 0x09, 0x00, 0x07, 0xFF, 0xFF, 0xFF } }		/* AARP probes and requests */
};

static EndpointRef		gLsEp[LS_COUNT];
static Boolean			gListening = false;
static NCStation		*gStations = NULL;
static short			gNStations = 0;
static char				(*gEvents)[NC_EVENTLEN] = NULL;
static long				gNEvents = 0;
static NCListenStats	gLs;
static NCEdge			*gEdges = NULL;
static short			gNEdges = 0;
static UInt8			*gLsBuf = NULL;
static UInt8			gLsMyMAC[6];
static unsigned long	gLsStart = 0;
static NCAddr			gLastConflict = 0;

void NC_MACToStr(const unsigned char *m, char *s)
{
	static const char hx[] = "0123456789abcdef";
	short i, o = 0;
	for (i = 0; i < 6; i++) {
		if (i) s[o++] = ':';
		s[o++] = hx[m[i] >> 4]; s[o++] = hx[m[i] & 15];
	}
	s[o] = 0;
}

static void LsEvent(const char *text)
{
	char *l, nb[12];
	short i = 0, j;
	if (!gEvents) return;
	l = gEvents[gNEvents % NC_MAXEVENTS];
	UToStr((unsigned long) ((TickCount() - gLsStart) / TICKS_PER_SEC), nb);	/* "  42s  " */
	for (j = 0; nb[j]; j++) ;
	for (j = (short) (4 - j); j > 0; j--) l[i++] = ' ';
	for (j = 0; nb[j]; j++) l[i++] = nb[j];
	l[i++] = 's'; l[i++] = ' '; l[i++] = ' ';
	for (j = 0; text[j] && i < NC_EVENTLEN - 1; j++) l[i++] = text[j];
	l[i] = 0;
	gNEvents++;
	gChange++;
}

static Boolean SameMAC(const UInt8 *a, const UInt8 *b)
{
	short i;
	for (i = 0; i < 6; i++) if (a[i] != b[i]) return false;
	return true;
}

static NCStation *LsStation(const UInt8 *mac)
{
	NCStation *st;
	short i;
	char s[40], m[20];
	for (i = 0; i < gNStations; i++) if (SameMAC(gStations[i].mac, mac)) return &gStations[i];
	if (gNStations >= NC_MAXSTATIONS) return NULL;
	st = &gStations[gNStations++];
	OTMemzero(st, sizeof(*st));
	BlockMove(mac, st->mac, 6);
	st->firstTick = TickCount();
	if (SameMAC(mac, gLsMyMAC)) st->seen |= NC_SEEN_SELF;
	else { NC_MACToStr(mac, m); s[0] = 0; StrCat(s, "new station "); StrCat(s, m); LsEvent(s); }
	return st;
}

	/* one more frame from this station to that destination: a group, or an IPv4 address for unicast */
static void LsEdge(const NCStation *st, char to, NCAddr dst)
{
	NCEdge *e;
	short i, from;
	if (!st || !gEdges) return;
	from = (short) (st - gStations);
	for (i = 0; i < gNEdges; i++) {
		e = &gEdges[i];
		if (e->from == from && e->to == to && e->dst == dst) break;
	}
	if (i == gNEdges) {
		if (gNEdges >= NC_MAXEDGES) return;
		e = &gEdges[gNEdges++];
		e->from = from; e->to = to; e->dst = dst; e->packets = 0;
	}
	e->packets++;
	e->lastTick = TickCount();
}

static void LsTouch(NCStation *st, char what)
{
	if (!st) return;
	st->seen |= what;
	st->packets++;
	st->lastTick = TickCount();
}

	/* an address of the own /24 seen from this MAC: note it, and say so when another MAC already has it */
static void LsClaim(NCStation *st, NCAddr ip)
{
	short i;
	char s[NC_EVENTLEN], a[20], m1[20], m2[20];
	if (!st || ip == 0 || (ip & 0xFFFFFF00UL) != gBase) return;
	for (i = 0; i < gNStations; i++) {
		NCStation *o = &gStations[i];
		if (o != st && o->ip == ip && ip != gLastConflict) {
			gLastConflict = ip;
			gLs.conflicts++;
			NC_IPToStr(ip, a); NC_MACToStr(o->mac, m1); NC_MACToStr(st->mac, m2);
			s[0] = 0; StrCat(s, "IP CONFLICT "); StrCat(s, a); StrCat(s, " "); StrCat(s, m1); StrCat(s, " / "); StrCat(s, m2);
			LsEvent(s);
		}
	}
	if (st->ip != ip) st->ip = ip;
}

static void LsArp(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	NCAddr spa, tpa;
	char s[NC_EVENTLEN], a[20];
	if (n < 28) return;
	gLs.arp++;
	st = LsStation(p + 8);								/* the sender hardware address in the packet */
	LsTouch(st, NC_SEEN_ARP);
	spa = ((NCAddr) p[14] << 24) | ((NCAddr) p[15] << 16) | ((NCAddr) p[16] << 8) | p[17];
	tpa = ((NCAddr) p[24] << 24) | ((NCAddr) p[25] << 16) | ((NCAddr) p[26] << 8) | p[27];
	LsClaim(st, spa);
	if (p[7] == 1) LsEdge(st, NC_TO_BCAST, 0);			/* a request is broadcast, a reply goes to the asker */
	else LsEdge(st, NC_TO_UNICAST, tpa);
	if (spa != 0 && spa == tpa) {
		NC_IPToStr(spa, a); s[0] = 0; StrCat(s, "gratuitous ARP for "); StrCat(s, a); LsEvent(s);
	}
	if (mac) {}
}

static void LsIp(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	NCAddr src, dst;
	short ihl;
	char s[NC_EVENTLEN], a[20], m[20];
	if (n < 20 || (p[0] >> 4) != 4) return;
	ihl = (short) ((p[0] & 15) * 4);
	src = ((NCAddr) p[12] << 24) | ((NCAddr) p[13] << 16) | ((NCAddr) p[14] << 8) | p[15];
	dst = ((NCAddr) p[16] << 24) | ((NCAddr) p[17] << 16) | ((NCAddr) p[18] << 8) | p[19];
	if (p[16] >= 224 && p[16] <= 239) gLs.ipMulticast++;
	else if (dst == 0xFFFFFFFFUL || (dst & 0xFF) == 0xFF) gLs.ipBroadcast++;
	else gLs.ipUnicast++;
	st = LsStation(mac);
	LsTouch(st, NC_SEEN_IP);
	LsClaim(st, src);
	if (p[16] >= 224 && p[16] <= 239) LsEdge(st, (char) (dst == 0xE00000FBUL ? NC_TO_MDNS : NC_TO_MCAST), 0);
	else if (dst == 0xFFFFFFFFUL || (dst & 0xFF) == 0xFF) LsEdge(st, NC_TO_BCAST, 0);
	else LsEdge(st, NC_TO_UNICAST, dst);
	if (p[9] == 17 && n >= ihl + 8) {					/* UDP */
		UInt16 sp = (UInt16) ((p[ihl] << 8) | p[ihl + 1]), dp = (UInt16) ((p[ihl + 2] << 8) | p[ihl + 3]);
		if ((sp == 67 || sp == 68) && (dp == 67 || dp == 68) && n >= ihl + 8 + 1) {
			gLs.dhcp++;
			NC_MACToStr(mac, m);
			s[0] = 0;
			StrCat(s, p[ihl + 8] == 1 ? "DHCP request from " : "DHCP answer from ");
			StrCat(s, m);
			if (src) { NC_IPToStr(src, a); StrCat(s, " ("); StrCat(s, a); StrCat(s, ")"); }
			LsEvent(s);
		}
		if (sp == 137 || sp == 138 || dp == 137 || dp == 138) gLs.netbios++;
	}
}

	/* AppleTalk traffic: what each DDP type and each sending node amounts to */
#define AT_NODES	32
static NCATTraffic	gATT;
static NCATNode		gATN[AT_NODES];
static short		gNATN = 0;

static void ATCount(NCATCount *c, short len)
{
	c->packets++;
	c->bytes += len;
	if (c->minLen == 0 || len < c->minLen) c->minLen = len;
	if (len > c->maxLen) c->maxLen = len;
}

static void ATTraffic(UInt16 net, UInt8 node, short type, short len)
{
	short i;
	unsigned long now = TickCount();
	ATCount(&gATT.type[type], len);
	gATT.sizes[len < 64 ? 0 : len < 128 ? 1 : len < 256 ? 2 : len < 512 ? 3 : 4]++;
	if (gATT.firstTick == 0) gATT.firstTick = now;
	gATT.lastTick = now;
	if (net == 0 && node == 0) return;
	for (i = 0; i < gNATN; i++) if (gATN[i].net == net && gATN[i].node == node) break;
	if (i == gNATN) {
		if (gNATN >= AT_NODES) return;
		OTMemzero(&gATN[i], sizeof(NCATNode));
		gATN[i].net = net; gATN[i].node = node;
		gNATN++;
	}
	gATN[i].types |= (UInt8) (1 << type);
	ATCount(&gATN[i].c, len);
	gATN[i].lastTick = now;
}

void NC_ATTraffic(NCATTraffic *t) { *t = gATT; }

	/* RTMP data (DDP type 1): the router's network, an ID, then tuples - extended ones carry a range end and $82 */
#define AT_ROUTERS	8
#define AT_ROUTES	32
static NCATRouter	gATR[AT_ROUTERS];
static short		gNATR = 0;
static NCATRoute	gATRt[AT_ROUTES];
static short		gNATRt = 0;
static unsigned long gLocalTick = 0;							/* when NC_ATLocalZones last asked; 0: ask */

static void ATRoute(short router, UInt16 lo, UInt16 hi, UInt8 dist)
{
	short i;
	for (i = 0; i < gNATRt; i++) if (gATRt[i].rangeLo == lo && gATRt[i].rangeHi == hi) break;
	if (i == gNATRt) {												/* a network not seen before */
		if (gNATRt >= AT_ROUTES) return;
		OTMemzero(&gATRt[i], sizeof(NCATRoute));
		gNATRt++;
	} else if (gATRt[i].distance < dist || router < 0) return;		/* a shorter way is known; ZIP names no router */
	gATRt[i].rangeLo = lo; gATRt[i].rangeHi = hi; gATRt[i].distance = dist; gATRt[i].router = router;
}

static void LsRtmp(const UInt8 *d, long n)						/* d: the DDP data, after the 13-byte header */
{
	UInt16 net;
	UInt8 node, idLen;
	short r, tuples = 0;
	long o;
	if (n < 4) return;
	net = (UInt16) ((d[0] << 8) | d[1]); idLen = d[2]; node = d[3];
	if (idLen != 8) return;
	for (r = 0; r < gNATR; r++) if (gATR[r].net == net && gATR[r].node == node) break;
	if (r == gNATR) {
		if (gNATR >= AT_ROUTERS) return;
		OTMemzero(&gATR[r], sizeof(NCATRouter));
		gATR[r].net = net; gATR[r].node = node;
		gNATR++;
		gLocalTick = 0;
		{ char s[NC_EVENTLEN], nb[8]; s[0] = 0; StrCat(s, "AppleTalk router ");
		  UToStr(net, nb); StrCat(s, nb); StrCat(s, "."); UToStr(node, nb); StrCat(s, nb); StrCat(s, " announces routes"); LsEvent(s); }
	}
	gATR[r].lastTick = TickCount();
	for (o = 4; o + 3 <= n; ) {
		UInt16 lo = (UInt16) ((d[o] << 8) | d[o + 1]), hi = lo;
		UInt8 dist = d[o + 2];
		if (dist & 0x80) {											/* extended: range end, then $82 */
			if (o + 6 > n) break;
			hi = (UInt16) ((d[o + 3] << 8) | d[o + 4]);
			o += 6;
		} else o += 3;
		dist &= 0x1F;
		if (lo == 0) continue;										/* a non-extended network's version tuple */
		if (dist == 0) { gATR[r].rangeLo = lo; gATR[r].rangeHi = hi; }
		ATRoute(r, lo, hi, dist);
		tuples++;
	}
	gATR[r].routes = tuples;
	gChange++;
}

	/* ZIP (DDP type 6): replies name the zones of networks - Reply/Extended Reply list net + zone, GetNetInfo Reply
	   gives the range and the zone of this cable */
static void ATZone(UInt16 net, const UInt8 *z, short len)
{
	short i, k;
	for (i = 0; i < gNATRt; i++)
		if (net >= gATRt[i].rangeLo && net <= gATRt[i].rangeHi && gATRt[i].zone[0] == 0) {
			for (k = 0; k < len && k < 33; k++) gATRt[i].zone[k] = (char) z[k];
			gATRt[i].zone[k] = 0;
		}
}

static void LsZip(const UInt8 *d, long n)
{
	long o;
	short count, i;
	if (n < 2) return;
	if (d[0] == 2 || d[0] == 8) {								/* Reply, Extended Reply: count, (net, zone)... */
		count = d[1];
		for (o = 2, i = 0; i < count && o + 3 <= n && o + 3 + d[o + 2] <= n; i++) {
			ATZone((UInt16) ((d[o] << 8) | d[o + 1]), d + o + 3, d[o + 2]);
			o += 3 + d[o + 2];
		}
	} else if (d[0] == 6 && n >= 7 && 7 + d[6] <= n) {			/* GetNetInfo Reply: flags, lo, hi, zone */
		UInt16 lo = (UInt16) ((d[2] << 8) | d[3]), hi = (UInt16) ((d[4] << 8) | d[5]);
		ATRoute(-1, lo, hi, 0);
		ATZone(lo, d + 7, d[6]);
	}
	gChange++;
}

	/* Nobody may ask ZIP for this cable's zones while we listen, so Open Transport is asked - only once a router has
	   spoken (without one the call waits out ZIP's retries), then every 30 s */
void NC_ATLocalZones(void)
{
	TNetbuf zb;
	char buf[400];
	long p;
	short i, k, o = 0;
	for (i = 0; i < gNATRt; i++) if (gATRt[i].distance == 0 && gATRt[i].router >= 0) break;
	if (i == gNATRt || (gLocalTick != 0 && TickCount() - gLocalTick < 1800)) return;
	gLocalTick = TickCount();
	if (!OpenAT()) return;
	zb.buf = (UInt8 *) buf; zb.maxlen = sizeof(buf); zb.len = 0;
	if (OTATalkGetLocalZones(gAT, &zb) != noErr) return;
	for (p = 0; p < (long) zb.len; p += 1 + ((unsigned char *) buf)[p]) {	/* length-prefixed names -> "Pit, ApfelNetz" */
		short len = ((unsigned char *) buf)[p];
		if (len == 0) break;
		if (o > 0) {
			if (o >= 31) break;
			gATRt[i].zone[o++] = ','; gATRt[i].zone[o++] = ' ';
		}
		for (k = 0; k < len && o < 33 && p + 1 + k < (long) zb.len; k++) gATRt[i].zone[o++] = buf[p + 1 + k];
	}
	if (o > 0) gATRt[i].zone[o] = 0;
}

short NC_ATRouterCount(void) { return gNATR; }
const NCATRouter *NC_ATRouter(short i) { return (i >= 0 && i < gNATR) ? &gATR[i] : NULL; }
short NC_ATRouteCount(void) { return gNATRt; }
const NCATRoute *NC_ATRoute(short i) { return (i >= 0 && i < gNATRt) ? &gATRt[i] : NULL; }
short NC_ATNodeCount(void) { return gNATN; }
const NCATNode *NC_ATNode(short i) { return (i >= 0 && i < gNATN) ? &gATN[i] : NULL; }
const char *NC_ATTypeName(short type)
{
	static const char *kName[NC_ATT_COUNT] = { "RTMP", "NBP", "ATP", "AEP", "ZIP", "ADSP", "DDP other", "AARP" };
	return (type >= 0 && type < NC_ATT_COUNT) ? kName[type] : "?";
}

static void LsDdp(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	gLs.ddp++;
	if (n >= 13) {										/* DDP type 12; the datagram's length in 0-1 */
		short len = (short) (((p[0] & 3) << 8) | p[1]), t;
		if (len == 0 || len > n) len = (short) n;
		switch (p[12]) {
			case 1: case 5:	t = NC_ATT_RTMP; break;
			case 2:			t = NC_ATT_NBP; break;
			case 3:			t = NC_ATT_ATP; break;
			case 4:			t = NC_ATT_AEP; break;
			case 6:			t = NC_ATT_ZIP; break;
			case 7:			t = NC_ATT_ADSP; break;
			default:		t = NC_ATT_OTHER; break;
		}
		ATTraffic((UInt16) ((p[6] << 8) | p[7]), p[9], t, len);
		if (p[12] == 1) LsRtmp(p + 13, len - 13);				/* RTMP data: a router speaks */
		else if (p[12] == 6) LsZip(p + 13, len - 13);
	}
	st = LsStation(mac);
	LsTouch(st, NC_SEEN_AT);
	LsEdge(st, NC_TO_ATALK, 0);
	if (st && n >= 13) {								/* long DDP header: source network 6-7, node 9 */
		UInt16 net = (UInt16) ((p[6] << 8) | p[7]);
		if (net != 0) { st->atNet = net; st->atNode = p[9]; }
	}
}

static void LsAarp(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	gLs.aarp++;
	if (n < 18) return;
	ATTraffic((UInt16) ((p[15] << 8) | p[16]), p[17], NC_ATT_AARP, (short) n);
	st = LsStation(p + 8);								/* sender hardware address; protocol address: 0, net, node */
	LsTouch(st, NC_SEEN_AT);
	LsEdge(st, NC_TO_ATALK, 0);
	if (st) { st->atNet = (UInt16) ((p[15] << 8) | p[16]); st->atNode = p[17]; }
	if (mac) {}
}

static void LsIp6(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	if (n < 40 || (p[0] >> 4) != 6) return;
	gLs.ipv6++;
	if (p[24] == 0xFF) gLs.ipMulticast++;				/* destination ff00::/8 */
	st = LsStation(mac);
	LsTouch(st, NC_SEEN_IP6);
	if (p[24] == 0xFF)									/* ff02::fb is mDNS; IPv6 unicast has no IPv4 end */
		LsEdge(st, (char) (p[25] == 0x02 && p[38] == 0 && p[39] == 0xFB ? NC_TO_MDNS : NC_TO_IP6MC), 0);
}

	/* LLDP: TLVs of a 7-bit type and a 9-bit length; 5 is the system name, 4 the port description */
static void LsLldp(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	char port[24], s[NC_EVENTLEN];
	long o = 0;
	short t, len, i;
	gLs.lldp++;
	st = LsStation(mac);
	LsTouch(st, NC_SEEN_LLDP);
	LsEdge(st, NC_TO_LLDP, 0);
	if (!st) return;
	port[0] = 0;
	s[0] = 0;											/* the name as sent, to compare */
	while (o + 2 <= n) {
		t = (short) (p[o] >> 1); len = (short) (((p[o] & 1) << 8) | p[o + 1]);
		o += 2;
		if (t == 0 || o + len > n) break;
		if (t == 5 || t == 4) {
			char *d = (t == 5) ? s : port;
			for (i = 0; i < len && i < 23; i++) d[i] = (char) (p[o + i] >= ' ' ? p[o + i] : '.');
			d[i] = 0;
		}
		o += len;
	}
	if (s[0] && !StrEqual(s, st->name)) {
		StrCopy(st->name, s, sizeof(st->name));
		s[0] = 0; StrCat(s, "LLDP: "); StrCat(s, st->name);
		if (port[0]) { StrCat(s, ", "); StrCat(s, port); }
		LsEvent(s);
	}
}

	/* OPT_ADDMCAST at LNK_TPI: a TOption whose value is the 6-byte group; at LNK_ENET it is TBADOPT */
static OSStatus LsJoin(EndpointRef ep, const UInt8 *group)
{
	struct { UInt32 len; UInt32 level; UInt32 name; UInt32 status; UInt8 addr[6]; UInt8 pad[2]; } opt;
	TOptMgmt req, ret;
	OSStatus err;
	short i;
	opt.len = 22; opt.level = LNK_TPI; opt.name = OPT_ADDMCAST; opt.status = 0;
	for (i = 0; i < 6; i++) opt.addr[i] = group[i];
	opt.pad[0] = opt.pad[1] = 0;
	req.opt.buf = (UInt8 *) &opt; req.opt.len = 22; req.flags = T_NEGOTIATE;
	ret.opt.buf = (UInt8 *) &opt; ret.opt.maxlen = sizeof(opt);
	err = OTOptionManagement(ep, &req, &ret);
	return (err == noErr && opt.status != T_SUCCESS) ? (OSStatus) -1 : err;
}

/* ------------------------------------------------------------------ frames: the capture (the dissector is frames.c) */

static NCFrame			*gFrames = NULL;
static long				gNFrames = 0;
static OTTimeStamp		gLsStamp;
static unsigned long	gLsEpoch = 0;
static const UInt16 kLsType[LS_COUNT] = { 0x0806, 0x0800, 0x809B, 0x80F3, 0x86DD, 0x88CC };

static void LsCapture(short k, const UInt8 *mac, const UInt8 *p, long n)
{
	NCFrame *f;
	OTTimeStamp now;
	if (!gFrames || n <= 0) return;
	f = &gFrames[gNFrames % NC_MAXFRAMES];
	OTGetTimeStamp(&now);
	f->us = (unsigned long) StampUs(&gLsStamp, &now);
	BlockMove(mac, f->src, 6);
	f->type = kLsType[k];
	f->len = (short) (n > 32767 ? 32767 : n);
	f->caplen = (short) (n > NC_SNAPLEN ? NC_SNAPLEN : n);
	BlockMove(p, f->data, f->caplen);
	gNFrames++;
}

long NC_FrameTotal(void) { return gNFrames; }
unsigned long NC_FrameEpoch(void) { return gLsEpoch; }

static unsigned long UnixNow(void)			/* the Mac clock is local time since 1904; pcap wants UTC since 1970 */
{
	unsigned long secs;
	MachineLocation loc;
	long delta;
	GetDateTime(&secs);
	ReadLocation(&loc);
	delta = loc.gmtFlags.gmtDelta & 0x00FFFFFFL;						/* 24 bits, signed */
	if (delta & 0x00800000L) delta |= 0xFF000000L;
	return secs - 2082844800UL - (unsigned long) delta;
}
const NCFrame *NC_Frame(long i)
{
	if (!gFrames || i < 0 || i >= gNFrames || i < gNFrames - NC_MAXFRAMES) return NULL;
	return &gFrames[i % NC_MAXFRAMES];
}

long NC_ListenStart(void)
{
	struct T8022Address a, got;
	TBind req, ret;
	OSStatus err, last = noErr;
	short k, i, opened = 0;
	if (gListening) return noErr;
	if (!gStations) gStations = (NCStation *) NewPtrClear((long) NC_MAXSTATIONS * sizeof(NCStation));
	if (!gEvents) gEvents = (char (*)[NC_EVENTLEN]) NewPtrClear((long) NC_MAXEVENTS * NC_EVENTLEN);
	if (!gLsBuf) gLsBuf = (UInt8 *) NewPtr(LS_BUFSIZE);
	if (!gEdges) gEdges = (NCEdge *) NewPtrClear((long) NC_MAXEDGES * sizeof(NCEdge));
	if (!gFrames) gFrames = (NCFrame *) NewPtr((long) NC_MAXFRAMES * sizeof(NCFrame));	/* ~160 KB; the view does without */
	if (!gStations || !gEvents || !gLsBuf || !gEdges) return memFullErr;
	for (k = 0; k < LS_COUNT; k++) {
		gLsEp[k] = OTOpenEndpoint(OTCreateConfiguration(kEnetName), 0, NULL, &err);
		if (err != noErr || gLsEp[k] == NULL) { gLsEp[k] = NULL; last = err; continue; }
		OTMemzero(&a, sizeof(a)); OTMemzero(&got, sizeof(got));
		a.fAddrFamily = AF_8022; a.fSAP = kLsSap[k];
		for (i = 0; i < 5; i++) a.fSNAP[i] = kLsSnap[k][i];
		req.addr.buf = (UInt8 *) &a;
		req.addr.len = (kLsSap[k] == 0x00AA) ? k8022SNAPAddressLength : k8022BasicAddressLength;
		req.qlen = 0;
		ret.addr.buf = (UInt8 *) &got; ret.addr.maxlen = sizeof(got);
		err = OTBind(gLsEp[k], &req, &ret);
		if (err != noErr) { OTCloseProvider(gLsEp[k]); gLsEp[k] = NULL; last = err; continue; }
		if (k == LS_ARP) BlockMove(got.fHWAddr, gLsMyMAC, 6);
		opened++;
	}
	if (opened == 0) return last != noErr ? last : -1;
	gLs.joined = 0;
	for (k = 0; k < (short) (sizeof(kLsJoin) / sizeof(kLsJoin[0])); k++)	/* still blocking, as SniffProbe measured */
		if (gLsEp[kLsJoin[k].ep] && LsJoin(gLsEp[kLsJoin[k].ep], kLsJoin[k].group) == noErr) gLs.joined++;
	for (k = 0; k < LS_COUNT; k++) if (gLsEp[k]) OTSetNonBlocking(gLsEp[k]);
	gListening = true;
	gLsStart = TickCount();
	OTGetTimeStamp(&gLsStamp);								/* a new capture: frame times count from here */
	gLsEpoch = UnixNow();
	gNFrames = 0;
	{
		char s[NC_EVENTLEN], nb[8];
		UToStr((unsigned long) gLs.joined, nb);
		s[0] = 0; StrCat(s, "listening, "); StrCat(s, nb); StrCat(s, " multicast groups joined");
		LsEvent(s);
	}
	return noErr;
}

void NC_ListenStop(void)
{
	short k;
	for (k = 0; k < LS_COUNT; k++) if (gLsEp[k]) { OTCloseProvider(gLsEp[k]); gLsEp[k] = NULL; }
	if (gListening) { gListening = false; LsEvent("stopped"); }
}

Boolean NC_Listening(void) { return gListening; }

void NC_ListenIdle(void)
{
	struct T8022Address src;
	TUnitData rcv;
	OTFlags flags;
	OTResult res;
	short k, i;
	if (!gListening) return;
	for (k = 0; k < LS_COUNT; k++) {
		if (!gLsEp[k]) continue;
		for (i = 0; i < 24; i++) {						/* a bounded slice: the application must keep yielding */
			OTMemzero(&rcv, sizeof(rcv));
			rcv.addr.buf = (UInt8 *) &src; rcv.addr.maxlen = sizeof(src);
			rcv.udata.buf = gLsBuf; rcv.udata.maxlen = LS_BUFSIZE;
			flags = 0;
			res = OTRcvUData(gLsEp[k], &rcv, &flags);
			if (res == kOTLookErr) { if (OTLook(gLsEp[k]) == T_UDERR) OTRcvUDErr(gLsEp[k], NULL); break; }
			if (res != noErr) break;					/* kOTNoDataErr: nothing more for now */
			gLs.total++;
			gActivity++;
			LsCapture(k, src.fHWAddr, gLsBuf, (long) rcv.udata.len);
			switch (k) {
				case LS_ARP:	LsArp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_IP:		LsIp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_DDP:	LsDdp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_AARP:	LsAarp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_IP6:	LsIp6(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_LLDP:	LsLldp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
			}
		}
	}
}

void NC_ListenGetStats(NCListenStats *s) { *s = gLs; }
short NC_StationCount(void) { return gNStations; }
const NCStation *NC_Station(short i) { return (gStations && i >= 0 && i < gNStations) ? &gStations[i] : NULL; }
short NC_EdgeCount(void) { return gNEdges; }
const NCEdge *NC_Edge(short i) { return (gEdges && i >= 0 && i < gNEdges) ? &gEdges[i] : NULL; }
long NC_EventTotal(void) { return gNEvents; }
const char *NC_EventLine(long i)
{
	if (!gEvents || i < 0 || i >= gNEvents || i < gNEvents - NC_MAXEVENTS) return "";
	return gEvents[i % NC_MAXEVENTS];
}

/* ------------------------------------------------------------------ shutdown */

	/* the Listen view as text: what the meters counted, the stations, the events kept */
long NC_BuildListenReport(char *buf, long max)
{
	long o = 0, i, first;
	short k;
	char nb[16], t[24];
	unsigned long now = TickCount();
	App(buf, &o, max, "MacNetScan Listen  stations="); UToStr((unsigned long) gNStations, nb); App(buf, &o, max, nb);
	App(buf, &o, max, "  packets="); UToStr((unsigned long) gLs.total, nb); App(buf, &o, max, nb);
	App(buf, &o, max, CR "ARP\tBroadcast\tMulticast\tDHCP\tNetBIOS\tIPv6\tLLDP\tAppleTalk\tAARP" CR);
	{
		long v[9];
		v[0] = gLs.arp; v[1] = gLs.ipBroadcast; v[2] = gLs.ipMulticast; v[3] = gLs.dhcp; v[4] = gLs.netbios;
		v[5] = gLs.ipv6; v[6] = gLs.lldp; v[7] = gLs.ddp; v[8] = gLs.aarp;
		for (k = 0; k < 9; k++) { UToStr((unsigned long) v[k], nb); App(buf, &o, max, nb); App(buf, &o, max, k < 8 ? "\t" : CR); }
	}
	App(buf, &o, max, CR "MAC\tIP\tAppleTalk\tLLDP name\tHeard\tPackets\tLast heard (s ago)" CR);
	for (i = 0; gStations && i < gNStations; i++) {
		const NCStation *st = &gStations[i];
		NC_MACToStr(st->mac, t); App(buf, &o, max, t); App(buf, &o, max, "\t");
		if (st->ip) { NC_IPToStr(st->ip, t); App(buf, &o, max, t); }
		App(buf, &o, max, "\t");
		if (st->atNet) { UToStr(st->atNet, nb); App(buf, &o, max, nb); App(buf, &o, max, "."); UToStr(st->atNode, nb); App(buf, &o, max, nb); }
		App(buf, &o, max, "\t"); App(buf, &o, max, st->name); App(buf, &o, max, "\t");
		if (st->seen & NC_SEEN_SELF) App(buf, &o, max, "this Mac ");
		if (st->seen & NC_SEEN_ARP) App(buf, &o, max, "ARP ");
		if (st->seen & NC_SEEN_IP) App(buf, &o, max, "IP ");
		if (st->seen & NC_SEEN_IP6) App(buf, &o, max, "IPv6 ");
		if (st->seen & NC_SEEN_LLDP) App(buf, &o, max, "LLDP ");
		if (st->seen & NC_SEEN_AT) App(buf, &o, max, "AppleTalk");
		App(buf, &o, max, "\t"); UToStr((unsigned long) st->packets, nb); App(buf, &o, max, nb);
		App(buf, &o, max, "\t"); UToStr((now - st->lastTick) / TICKS_PER_SEC, nb); App(buf, &o, max, nb);
		App(buf, &o, max, CR);
	}
	App(buf, &o, max, CR "Events (seconds since Scan)" CR);
	first = gNEvents > NC_MAXEVENTS ? gNEvents - NC_MAXEVENTS : 0;
	for (i = first; i < gNEvents; i++) { App(buf, &o, max, NC_EventLine(i)); App(buf, &o, max, CR); }
	return o;
}

	/* the AppleTalk view as text: this Mac's node and zone, then every NBP entity found */
long NC_BuildATReport(char *buf, long max)
{
	long o = 0;
	short i;
	char nb[16];
	NCATInfo ai;
	App(buf, &o, max, "MacNetScan AppleTalk  entities="); UToStr((unsigned long) gNEnt, nb); App(buf, &o, max, nb); App(buf, &o, max, CR);
	if (NC_ATInfo(&ai) == noErr) {
		App(buf, &o, max, "This Mac\t"); App(buf, &o, max, ai.address);
		App(buf, &o, max, "\tzone "); App(buf, &o, max, ai.zone[0] ? ai.zone : "*");
		if (ai.router[0]) { App(buf, &o, max, "\trouter "); App(buf, &o, max, ai.router); }
		App(buf, &o, max, ai.isExtended ? "\textended network" CR : "\tLocalTalk-style network" CR);
	}
	App(buf, &o, max, CR "Object\tType\tZone\tAddress\tEcho ms\tServer" CR);
	for (i = 0; gEnt && i < gNEnt; i++) {
		App(buf, &o, max, gEnt[i].object); App(buf, &o, max, "\t"); App(buf, &o, max, gEnt[i].type); App(buf, &o, max, "\t");
		App(buf, &o, max, gEnt[i].zone); App(buf, &o, max, "\t"); App(buf, &o, max, gEnt[i].address); App(buf, &o, max, "\t");
		if (gEnt[i].rttUs != -2) { NC_RttToStr(gEnt[i].rttUs, nb); App(buf, &o, max, nb); }
		App(buf, &o, max, "\t"); App(buf, &o, max, gEnt[i].info); App(buf, &o, max, CR);
	}
	if (gNATRt > 0) {
		NC_ATLocalZones();
		App(buf, &o, max, CR "Network\tHops\tVia router\tZone" CR);
		for (i = 0; i < gNATRt; i++) {
			UToStr(gATRt[i].rangeLo, nb); App(buf, &o, max, nb);
			if (gATRt[i].rangeHi != gATRt[i].rangeLo) { App(buf, &o, max, "-"); UToStr(gATRt[i].rangeHi, nb); App(buf, &o, max, nb); }
			App(buf, &o, max, "\t"); UToStr(gATRt[i].distance, nb); App(buf, &o, max, nb); App(buf, &o, max, "\t");
			if (gATRt[i].router >= 0 && gATRt[i].router < gNATR) {
				UToStr(gATR[gATRt[i].router].net, nb); App(buf, &o, max, nb); App(buf, &o, max, ".");
				UToStr(gATR[gATRt[i].router].node, nb); App(buf, &o, max, nb);
			}
			App(buf, &o, max, "\t"); App(buf, &o, max, gATRt[i].zone); App(buf, &o, max, CR);
		}
	}
	if (gATT.firstTick) {
		short k;
		App(buf, &o, max, CR "Protocol\tPackets\tBytes\tMin\tMax" CR);
		for (k = 0; k < NC_ATT_COUNT; k++) {
			const NCATCount *c = &gATT.type[k];
			if (c->packets == 0) continue;
			App(buf, &o, max, NC_ATTypeName(k));
			App(buf, &o, max, "\t"); UToStr((unsigned long) c->packets, nb); App(buf, &o, max, nb);
			App(buf, &o, max, "\t"); UToStr((unsigned long) c->bytes, nb); App(buf, &o, max, nb);
			App(buf, &o, max, "\t"); UToStr((unsigned long) c->minLen, nb); App(buf, &o, max, nb);
			App(buf, &o, max, "\t"); UToStr((unsigned long) c->maxLen, nb); App(buf, &o, max, nb); App(buf, &o, max, CR);
		}
		App(buf, &o, max, CR "Node\tPackets\tBytes\tProtocols" CR);
		for (i = 0; i < gNATN; i++) {
			UToStr(gATN[i].net, nb); App(buf, &o, max, nb); App(buf, &o, max, ".");
			UToStr(gATN[i].node, nb); App(buf, &o, max, nb);
			App(buf, &o, max, "\t"); UToStr((unsigned long) gATN[i].c.packets, nb); App(buf, &o, max, nb);
			App(buf, &o, max, "\t"); UToStr((unsigned long) gATN[i].c.bytes, nb); App(buf, &o, max, nb); App(buf, &o, max, "\t");
			for (k = 0; k < NC_ATT_COUNT; k++)
				if (gATN[i].types & (1 << k)) { App(buf, &o, max, NC_ATTypeName(k)); App(buf, &o, max, " "); }
			App(buf, &o, max, CR);
		}
	}
	NC_VolumeRead();
	App(buf, &o, max, CR "Volume\tServer\tSize KB\tFree KB" CR);
	for (i = 0; i < NC_VolumeCount(); i++) {
		const NCVolume *v = NC_Volume(i);
		App(buf, &o, max, v->name); App(buf, &o, max, "\t");
		if (v->serverAdr) {
			UToStr(v->serverAdr >> 16, nb); App(buf, &o, max, nb); App(buf, &o, max, ".");
			UToStr((v->serverAdr >> 8) & 0xFF, nb); App(buf, &o, max, nb); App(buf, &o, max, ":");
			UToStr(v->serverAdr & 0xFF, nb); App(buf, &o, max, nb);
		}
		App(buf, &o, max, "\t"); UToStr((unsigned long) v->totalK, nb); App(buf, &o, max, nb);
		App(buf, &o, max, "\t"); UToStr((unsigned long) v->freeK, nb); App(buf, &o, max, nb); App(buf, &o, max, CR);
	}
	return o;
}

void NC_Shutdown(void)
{
	short i;
	ProbeEnd();
	for (i = 0; i < NC_MAXSLOTS; i++)
		if (gSlots[i].busy && gSlots[i].ep) { OTRemoveNotifier(gSlots[i].ep); OTCloseProvider(gSlots[i].ep); gSlots[i].busy = false; }
	ClosePing();
	NC_ListenStop();
	if (gStations) { DisposePtr((Ptr) gStations); gStations = NULL; gNStations = 0; }
	if (gEvents) { DisposePtr((Ptr) gEvents); gEvents = NULL; gNEvents = 0; }
	if (gLsBuf) { DisposePtr((Ptr) gLsBuf); gLsBuf = NULL; }
	if (gEdges) { DisposePtr((Ptr) gEdges); gEdges = NULL; gNEdges = 0; }
	if (gFrames) { DisposePtr((Ptr) gFrames); gFrames = NULL; gNFrames = 0; }
	if (gRaw) { OTCloseProvider(gRaw); gRaw = NULL; }
	if (gUdp) { OTCloseProvider(gUdp); gUdp = NULL; }
	if (gSvc) { OTCloseProvider(gSvc); gSvc = NULL; }
	if (gTSvc) { OTCloseProvider(gTSvc); gTSvc = NULL; }
	if (gMapper) { OTCloseProvider(gMapper); gMapper = NULL; }
	if (gAT) { OTCloseProvider(gAT); gAT = NULL; }
	if (gEnt) { DisposePtr((Ptr) gEnt); gEnt = NULL; }
	if (gHosts) { DisposePtr((Ptr) gHosts); gHosts = NULL; }
	if (gOld) { DisposePtr((Ptr) gOld); gOld = NULL; }
	CloseOpenTransport();
	gNHosts = 0;
	gPhase = NC_SWEEP_IDLE;
}

/* the linker stubs Open Transport's libraries need under Symantec C++ (see there): with them here the project needs
   one engine file, not two */
#include "otstubs.c"
