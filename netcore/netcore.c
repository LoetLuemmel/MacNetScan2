/* netcore.c - MacNetScan 2's network engine (see netcore.h). The probing, packet building and parsing come from
   MacNetScan 1's ipscan.c unchanged in substance; what changed is the control flow: every loop that waited (the sweep,
   the UDP name queries, DNS, ping, traceroute) is now a state that the next Idle call continues, so the application
   keeps calling WaitNextEvent. NBP lookups stay synchronous (one zone per call, 1 s): OT 1.1's SDK has no asynchronous
   mapper sample to go by. Plain C, 68K. */

#include "OTCompat.h"
#include <Events.h>						/* TickCount: in the TCL project a .c file has no MacHeaders prefix */
#include <Memory.h>						/* NewPtr, NewPtrClear, DisposePtr, BlockMove */
#include <Errors.h>						/* memFullErr */
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
			off += (rec + 3) & ~3L;
		}
	}
	DisposePtr(rbuf);
}

void NC_NbpStart(void)
{
	OSStatus err;
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
	if (!gNbpRunning) return false;
	NbpLookupZone(gNZones > 0 ? gZones[gNbpZone] : "*");
	if (++gNbpZone >= gNbpTotal) gNbpRunning = false;
	return gNbpRunning;
}

void NC_NbpProgress(short *done, short *total) { *done = gNbpZone; *total = gNbpTotal; }
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

/* Passive: Ethernet endpoints bound to ARP, IPv4, and AppleTalk and AARP over 802.2 SNAP, read without blocking.
   Measured 2026-10-27 under Basilisk II (MacNetScan2/probe/sniff_main.c, five runs): binds and receives are safe beside
   the TCP/IP stack; OPT_SETRAWMODE and OPT_SETPROMISCUOUS answer TBADOPT at level LNK_ENET and NEVER RETURN at LNK_TPI,
   and the I_OTSetRawMode ioctl never returns either - both froze the guest. So nothing but OTOpenEndpoint, OTBind and
   OTRcvUData is ever called here. Frames come without their MAC header: the sender's MAC is the receive address, the
   protocol the bound SAP. What arrives: this Mac's own traffic, broadcasts, and what the host's network card hands on. */

#define NC_MAXSTATIONS	128
#define NC_EVENTLEN		80
#define LS_BUFSIZE		1600

enum { LS_ARP = 0, LS_IP, LS_DDP, LS_AARP, LS_COUNT };
static const UInt16 kLsSap[LS_COUNT] = { 0x0806, 0x0800, 0x00AA, 0x00AA };
static const UInt8 kLsSnap[LS_COUNT][5] = {
	{ 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0 },
	{ 0x08, 0x00, 0x07, 0x80, 0x9B },				/* AppleTalk Phase 2 */
	{ 0x00, 0x00, 0x00, 0x80, 0xF3 }				/* AARP */
};

static EndpointRef		gLsEp[LS_COUNT];
static Boolean			gListening = false;
static NCStation		*gStations = NULL;
static short			gNStations = 0;
static char				(*gEvents)[NC_EVENTLEN] = NULL;
static long				gNEvents = 0;
static NCListenStats	gLs;
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

static void LsDdp(const UInt8 *mac, const UInt8 *p, long n)
{
	NCStation *st;
	gLs.ddp++;
	st = LsStation(mac);
	LsTouch(st, NC_SEEN_AT);
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
	st = LsStation(p + 8);								/* sender hardware address; protocol address: 0, net, node */
	LsTouch(st, NC_SEEN_AT);
	if (st) { st->atNet = (UInt16) ((p[15] << 8) | p[16]); st->atNode = p[17]; }
	if (mac) {}
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
	if (!gStations || !gEvents || !gLsBuf) return memFullErr;
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
		OTSetNonBlocking(gLsEp[k]);
		opened++;
	}
	if (opened == 0) return last != noErr ? last : -1;
	gListening = true;
	gLsStart = TickCount();
	LsEvent("listening");
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
			switch (k) {
				case LS_ARP:	LsArp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_IP:		LsIp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_DDP:	LsDdp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
				case LS_AARP:	LsAarp(src.fHWAddr, gLsBuf, (long) rcv.udata.len); break;
			}
		}
	}
}

void NC_ListenGetStats(NCListenStats *s) { *s = gLs; }
short NC_StationCount(void) { return gNStations; }
const NCStation *NC_Station(short i) { return (gStations && i >= 0 && i < gNStations) ? &gStations[i] : NULL; }
long NC_EventTotal(void) { return gNEvents; }
const char *NC_EventLine(long i)
{
	if (!gEvents || i < 0 || i >= gNEvents || i < gNEvents - NC_MAXEVENTS) return "";
	return gEvents[i % NC_MAXEVENTS];
}

/* ------------------------------------------------------------------ shutdown */

void NC_Shutdown(void)
{
	short i;
	for (i = 0; i < NC_MAXSLOTS; i++)
		if (gSlots[i].busy && gSlots[i].ep) { OTRemoveNotifier(gSlots[i].ep); OTCloseProvider(gSlots[i].ep); gSlots[i].busy = false; }
	ClosePing();
	NC_ListenStop();
	if (gStations) { DisposePtr((Ptr) gStations); gStations = NULL; gNStations = 0; }
	if (gEvents) { DisposePtr((Ptr) gEvents); gEvents = NULL; gNEvents = 0; }
	if (gLsBuf) { DisposePtr((Ptr) gLsBuf); gLsBuf = NULL; }
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
