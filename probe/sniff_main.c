/* SniffProbe - MacNetScan 2 spike: can an application under Open Transport 1.1 receive whole Ethernet frames, and
   which ones reach the guest? The 802.2 Dev. Note of the OT 1.1 SDK documents OPT_SETRAWMODE (frames with their MAC
   header) and OPT_SETPROMISCUOUS (DLPI levels PHYS / SAP / MULTI) on an endpoint opened with kEnetName.
   Five endpoints run side by side: unbound in DL_PROMISC_PHYS (all traffic on the wire, if OT allows it unbound), ARP
   0x0806, IPv4 0x0800 (shares the SAP with the TCP/IP stack - does OT allow it?), AppleTalk and AARP over 802.2 SNAP.
   Each shows what every call returned and how many frames it got; the decoder classes every frame by destination
   (to me / foreign unicast / multicast / broadcast) and protocol. "foreign unicast" > 0 means the guest sees traffic
   not addressed to it. A click quits and writes "SniffProbe log" next to the application.
   Project as OTProbe (MacTraps, CPlusLib, the four OT .o, Far CODE); OpenTptLinks.h copied from the SDK.
   Run 1 (2026-10-27): every bind succeeded, the IPv4 one beside the TCP/IP stack without disturbing it (the bridge
   answered throughout); both options as OPT_ at level LNK_ENET returned TBADOPT (-3151), so frames came without their
   MAC header, and the unbound endpoint cannot receive (TOUTSTATE). Run 2 tries raw mode as the I_OTSetRawMode ioctl
   (value and pointer form), promiscuous mode at three levels, and decodes header-less payloads by the bound SAP.
   Run 2/3: the ioctl (value form, on the unbound endpoint) never returns - the guest hangs at 100 % CPU. Run 4 drops
   it and keeps the trail: one flushed line per call in "SniffProbe trail". Run 4: OPT_SETPROMISCUOUS at LNK_TPI hangs
   the same way. Run 5: binds and receives only (the safe part of run 1); the unbound endpoint is gone. */

#define OTSTUBS_NO_ANSI
#include "OTCompat.h"
#include <OpenTransport.h>
#include <OpenTptLinks.h>
#include <OpenTptInternet.h>
#include "otstubs.c"

#define DL_PROMISC_PHYS		0x01		/* DLPI values; OpenTptLinks.h defines only DL_PROMISC_OFF */
#define DL_PROMISC_SAP		0x02
#define DL_PROMISC_MULTI	0x03
#define NLINES				200
#define LINELEN				96

typedef struct {
	const char	*label;
	Boolean		bind;
	UInt16		sap;
	Boolean		hasSnap;
	UInt8		snap[5];
	EndpointRef	ep;
	OSStatus	openErr, bindErr, rcvErr;
	SInt32		rawV, rawP;							/* I_OTSetRawMode: data as value / as pointer (1 = not tried) */
	OSStatus	prom[3];							/* OPT_SETPROMISCUOUS at LNK_ENET, LNK_TPI, XTI_GENERIC */
	UInt32		promSt[3];
	long		frames, rawFrames;
} Ep;

static Ep gEp[] = {
	{ "ARP ", true,  0x0806, false, { 0 } },
	{ "IPv4", true,  0x0800, false, { 0 } },
	{ "DDP ", true,  0x00AA, true,  { 0x08, 0x00, 0x07, 0x80, 0x9B } },
	{ "AARP", true,  0x00AA, true,  { 0x00, 0x00, 0x00, 0x80, 0xF3 } }
};
#define NEP ((short) (sizeof(gEp) / sizeof(gEp[0])))

static WindowPtr	gWin;
static UInt8		gMyMAC[6];
static InetHost		gMyIP = 0;
static Boolean		gHaveMAC = false;
static long			gUni = 0, gForeign = 0, gMulti = 0, gBroad = 0;
static long			gArp = 0, gIPv4 = 0, gIPv6 = 0, gAT = 0, gAarp = 0, gOther = 0;
static char			(*gLines)[LINELEN] = NULL;			/* heap: 19 KB would crowd the A5 globals */
static long			gNLine = 0;
static long			gStart;

/* ------------------------------------------------------------------ text helpers */

static void Cat(char *d, const char *s) { while (*d) d++; while (*s) *d++ = *s++; *d = 0; }

static void CatNum(char *d, long n)
{
	char t[12];
	short i = 0;
	while (*d) d++;
	if (n < 0) { *d++ = '-'; n = -n; }
	do { t[i++] = (char) ('0' + n % 10); n /= 10; } while (n);
	while (i) *d++ = t[--i];
	*d = 0;
}

static void CatHex(char *d, unsigned long v, short digits)
{
	static const char hx[] = "0123456789abcdef";
	while (*d) d++;
	while (digits--) *d++ = hx[(v >> (4 * digits)) & 15];
	*d = 0;
}

static void CatIP(char *d, const UInt8 *p)
{
	short i;
	for (i = 0; i < 4; i++) { if (i) Cat(d, "."); CatNum(d, p[i]); }
}

static void CatMAC(char *d, const UInt8 *p)
{
	short i;
	for (i = 0; i < 6; i++) { if (i) Cat(d, ":"); CatHex(d, p[i], 2); }
}

static void AddLine(const char *s)
{
	char *l;
	short i = 0;
	if (!gLines) return;
	l = gLines[gNLine % NLINES];
	while (s[i] && i < LINELEN - 1) { l[i] = s[i]; i++; }
	l[i] = 0;
	gNLine++;
}

/* ------------------------------------------------------------------ trail: one flushed line before every call, so a
   hang leaves the last call begun on disk (run 2 froze the guest at launch and left no trace) */

#define NOVAL 0x7FFFFFFFL
static short gTrail = 0, gTrailVol = 0;

static void TrailOpen(void)
{
	FSSpec sp;
	if (FSMakeFSSpec(0, 0, "\pSniffProbe trail", &sp) == fnfErr) FSpCreate(&sp, 'ttxt', 'TEXT', smSystemScript);
	if (FSpOpenDF(&sp, fsRdWrPerm, &gTrail) != noErr) { gTrail = 0; return; }
	SetEOF(gTrail, 0);
	gTrailVol = sp.vRefNum;
}

static void Crumb(const char *a, const char *b, long n)
{
	char s[120];
	long len = 0;
	if (!gTrail) return;
	s[0] = 0; Cat(s, a);
	if (b) { Cat(s, " "); Cat(s, b); }
	if (n != NOVAL) { Cat(s, " = "); CatNum(s, n); }
	Cat(s, "\r");
	while (s[len]) len++;
	FSWrite(gTrail, &len, s);
	FlushVol(NULL, gTrailVol);
}

/* ------------------------------------------------------------------ endpoints */

static const UInt32 kLevels[3] = { LNK_ENET, LNK_TPI, XTI_GENERIC };

static OSStatus SetLinkOpt(EndpointRef ep, UInt32 level, UInt32 name, UInt32 value, UInt32 *status)
{
	struct { UInt32 len; UInt32 level; UInt32 name; UInt32 status; UInt32 value; } opt;
	TOptMgmt req, ret;
	OSStatus err;
	opt.len = sizeof(opt); opt.level = level; opt.name = name; opt.status = 0; opt.value = value;
	req.opt.buf = (UInt8 *) &opt; req.opt.len = sizeof(opt); req.flags = T_NEGOTIATE;
	ret.opt.buf = (UInt8 *) &opt; ret.opt.maxlen = sizeof(opt);
	err = OTOptionManagement(ep, &req, &ret);
	*status = opt.status;
	return err;
}

static void OpenEp(Ep *e)
{
	OSStatus err;
	struct T8022Address a, got;
	TBind req, ret;
	short i;

	Crumb("open", e->label, NOVAL);
	e->ep = OTOpenEndpoint(OTCreateConfiguration(kEnetName), 0, NULL, &err);
	e->openErr = err;
	Crumb("  open", e->label, err);
	if (err != noErr || e->ep == NULL) { e->ep = NULL; return; }
	e->bindErr = 1;										/* "not tried" */
	if (e->bind) {
		OTMemzero(&a, sizeof(a)); OTMemzero(&got, sizeof(got));
		a.fAddrFamily = AF_8022; a.fSAP = e->sap;
		if (e->hasSnap) for (i = 0; i < 5; i++) a.fSNAP[i] = e->snap[i];
		req.addr.buf = (UInt8 *) &a;
		req.addr.len = e->hasSnap ? k8022SNAPAddressLength : k8022BasicAddressLength;
		req.qlen = 0;
		ret.addr.buf = (UInt8 *) &got; ret.addr.maxlen = sizeof(got);
		Crumb("  bind", e->label, NOVAL);
		e->bindErr = OTBind(e->ep, &req, &ret);
		Crumb("  bind", e->label, e->bindErr);
		if (e->bindErr == noErr && !gHaveMAC) {
			for (i = 0; i < 6; i++) gMyMAC[i] = got.fHWAddr[i];
			gHaveMAC = true;
		}
	}
	e->rawV = e->rawP = 1;
	/* raw mode as the I_OTSetRawMode ioctl hangs Basilisk II for good (run 3, proven by the trail): never call it */
	e->rawV = e->rawP = 1;
	/* OPT_SETPROMISCUOUS: TBADOPT at LNK_ENET, and at LNK_TPI it never returns (run 4, trail) - whatever reaches
	   Basilisk II's emulated Ethernet driver hangs it. Only binds and receives are safe; no option is set. */
	for (i = 0; i < 3; i++) e->prom[i] = 1;
	OTSetNonBlocking(e->ep);
}

static void CloseEp(Ep *e)
{
	UInt32 st;
	short i;
	if (!e->ep) return;
	for (i = 0; i < 3; i++) if (e->prom[i] == noErr) SetLinkOpt(e->ep, kLevels[i], OPT_SETPROMISCUOUS, DL_PROMISC_OFF, &st);
	OTCloseProvider(e->ep);
	e->ep = NULL;
}

/* ------------------------------------------------------------------ decoding */

static const char *UdpName(UInt16 port)
{
	switch (port) {
		case 53:   return "DNS";
		case 67:   case 68: return "DHCP";
		case 123:  return "NTP";
		case 137:  return "NBNS";
		case 138:  return "NBDGM";
		case 1900: return "SSDP";
		case 5353: return "mDNS";
		case 5355: return "LLMNR";
	}
	return NULL;
}

/* destination class from the IP address when the frame came without its MAC header */
static char KindOfIP(const UInt8 *d)
{
	InetHost ip = ((InetHost) d[0] << 24) | ((InetHost) d[1] << 16) | ((InetHost) d[2] << 8) | d[3];
	if (d[0] >= 224 && d[0] <= 239) { gMulti++; return 'M'; }
	if (ip == 0xFFFFFFFFUL || d[3] == 255) { gBroad++; return 'B'; }
	if (ip == gMyIP) { gUni++; return 'U'; }
	gForeign++; return 'F';
}

/* type: Ethernet type, or 1 = DDP, 2 = AARP (SNAP); p/n: the layer-3 packet; kind: destination class or 0 */
static void DecodeL3(const Ep *e, UInt16 type, const UInt8 *p, long n, const UInt8 *srcMAC, char kind)
{
	char s[LINELEN + 40];
	s[0] = 0; Cat(s, e->label); Cat(s, "   "); s[7] = 0;
	if (type == 0x0806 && n >= 28) {
		gArp++;
		if (!kind) { kind = p[7] == 1 ? 'B' : 'U'; if (kind == 'B') gBroad++; else gUni++; }
		if (p[7] == 1) { Cat(s, "ARP who-has "); CatIP(s, p + 24); Cat(s, " tell "); CatIP(s, p + 14); }
		else { Cat(s, "ARP "); CatIP(s, p + 14); Cat(s, " is-at"); }
		Cat(s, " "); CatMAC(s, p + 8);
	} else if (type == 0x0800 && n >= 20) {
		short ihl = (short) ((p[0] & 15) * 4);
		UInt8 proto = p[9];
		gIPv4++;
		if (!kind) kind = KindOfIP(p + 16);
		if (proto == 17 && n >= ihl + 4) {
			UInt16 sp = (UInt16) ((p[ihl] << 8) | p[ihl + 1]), dp = (UInt16) ((p[ihl + 2] << 8) | p[ihl + 3]);
			const char *nm = UdpName(dp);
			if (!nm) nm = UdpName(sp);
			Cat(s, "UDP "); Cat(s, nm ? nm : "?"); Cat(s, " ");
			CatIP(s, p + 12); Cat(s, ":"); CatNum(s, sp); Cat(s, " > "); CatIP(s, p + 16); Cat(s, ":"); CatNum(s, dp);
		} else {
			Cat(s, proto == 6 ? "TCP " : proto == 1 ? "ICMP " : proto == 2 ? "IGMP " : "IP ");
			if (proto != 6 && proto != 1 && proto != 2) { CatNum(s, proto); Cat(s, " "); }
			CatIP(s, p + 12); Cat(s, " > "); CatIP(s, p + 16);
		}
		if (kind == 'U') { s[5] = kind; return; }		/* the bridge's own traffic: counted, not listed */
	} else if (type == 0x86DD) {
		gIPv6++; Cat(s, "IPv6");
	} else if (type == 1) {
		gAT++; Cat(s, "DDP");
		if (n >= 13) { Cat(s, " type "); CatNum(s, p[12]); Cat(s, " net "); CatNum(s, (p[6] << 8) | p[7]); Cat(s, "."); CatNum(s, p[11]); }
	} else if (type == 2) {
		gAarp++; Cat(s, "AARP");
	} else {
		gOther++; Cat(s, "type "); CatHex(s, type, 4);
	}
	s[5] = kind ? kind : '?';
	Cat(s, "  from "); CatMAC(s, srcMAC);
	AddLine(s);
}

static void Decode(Ep *e, const UInt8 *f, long n, const struct T8022Address *src)
{
	Boolean raw;
	if (n < 1) return;
	if (e->hasSnap) raw = (Boolean) (n >= 22 && f[14] == 0xAA && f[15] == 0xAA);
	else raw = (Boolean) (n >= 14 && (UInt16) ((f[12] << 8) | f[13]) == e->sap);
	if (raw) {
		char kind;
		short i;
		Boolean bc = true, mine = gHaveMAC;
		e->rawFrames++;
		for (i = 0; i < 6; i++) { if (f[i] != 0xFF) bc = false; if (gHaveMAC && f[i] != gMyMAC[i]) mine = false; }
		if (bc) { kind = 'B'; gBroad++; }
		else if (f[0] & 1) { kind = 'M'; gMulti++; }
		else if (mine) { kind = 'U'; gUni++; }
		else { kind = 'F'; gForeign++; }
		if (e->hasSnap) DecodeL3(e, (UInt16) (e->snap[4] == 0x9B ? 1 : 2), f + 22, n - 22, f + 6, kind);
		else DecodeL3(e, e->sap, f + 14, n - 14, f + 6, kind);
	} else if (e->hasSnap)
		DecodeL3(e, (UInt16) (e->snap[4] == 0x9B ? 1 : 2), f, n, src->fHWAddr, 0);
	else
		DecodeL3(e, e->sap, f, n, src->fHWAddr, 0);
}

static void Poll(Ep *e)
{
	static UInt8 buf[1600];
	struct T8022Address src;
	TUnitData rcv;
	OTFlags flags;
	OTResult res;
	short k;
	if (!e->ep) return;
	for (k = 0; k < 16; k++) {
		OTMemzero(&rcv, sizeof(rcv));
		rcv.addr.buf = (UInt8 *) &src; rcv.addr.maxlen = sizeof(src);
		rcv.udata.buf = buf; rcv.udata.maxlen = sizeof(buf);
		flags = 0;
		res = OTRcvUData(e->ep, &rcv, &flags);
		if (res == noErr) { e->frames++; Decode(e, buf, (long) rcv.udata.len, &src); continue; }
		if (res == kOTNoDataErr) return;
		if (res == kOTLookErr) { if (OTLook(e->ep) == T_UDERR) OTRcvUDErr(e->ep, NULL); return; }
		e->rcvErr = res;
		return;
	}
}

/* ------------------------------------------------------------------ display and log */

static void EpStatus(const Ep *e, char *s)
{
	short i;
	s[0] = 0; Cat(s, e->label); Cat(s, " open "); CatNum(s, e->openErr);
	Cat(s, "  bind "); if (e->bindErr == 1) Cat(s, "-"); else CatNum(s, e->bindErr);
	Cat(s, "  rawioctl "); CatNum(s, e->rawV); Cat(s, "/"); CatNum(s, e->rawP);
	Cat(s, "  promisc"); for (i = 0; i < 3; i++) { Cat(s, " "); if (e->prom[i] == 1) Cat(s, "-"); else CatNum(s, e->prom[i]); }
	Cat(s, "  rcv "); CatNum(s, e->rcvErr); Cat(s, "  frames "); CatNum(s, e->frames); Cat(s, " raw "); CatNum(s, e->rawFrames);
}

static void Totals(char *s)
{
	s[0] = 0; Cat(s, "to me "); CatNum(s, gUni); Cat(s, "  FOREIGN unicast "); CatNum(s, gForeign);
	Cat(s, "  multicast "); CatNum(s, gMulti); Cat(s, "  broadcast "); CatNum(s, gBroad);
	Cat(s, "  |  ARP "); CatNum(s, gArp); Cat(s, " IPv4 "); CatNum(s, gIPv4); Cat(s, " IPv6 "); CatNum(s, gIPv6);
	Cat(s, " DDP "); CatNum(s, gAT); Cat(s, " AARP "); CatNum(s, gAarp); Cat(s, " other "); CatNum(s, gOther);
}

static void Show(short y, const char *c)
{
	Str255 p;
	short n = 0;
	while (c[n] && n < 255) { p[n + 1] = (unsigned char) c[n]; n++; }
	p[0] = (unsigned char) n;
	MoveTo(8, y);
	DrawString(p);
}

static void Draw(void)
{
	char s[200];
	short i, y;
	long k, first;
	Rect r;
	SetPort(gWin);
	r = gWin->portRect;
	EraseRect(&r);
	TextFont(4); TextSize(9);
	s[0] = 0; Cat(s, "my MAC "); if (gHaveMAC) CatMAC(s, gMyMAC); else Cat(s, "?");
	Cat(s, "  IP "); { UInt8 b[4]; b[0] = (UInt8) (gMyIP >> 24); b[1] = (UInt8) (gMyIP >> 16); b[2] = (UInt8) (gMyIP >> 8); b[3] = (UInt8) gMyIP; CatIP(s, b); }
	Cat(s, "   seconds "); CatNum(s, (TickCount() - gStart) / 60L); Cat(s, "   click to quit");
	Show(12, s);
	for (i = 0; i < NEP; i++) { EpStatus(&gEp[i], s); Show((short) (26 + 11 * i), s); }
	Totals(s); Show((short) (30 + 11 * NEP), s);
	y = (short) (48 + 11 * NEP);
	first = gNLine > 26 ? gNLine - 26 : 0;
	for (k = first; k < gNLine; k++, y += 11) Show(y, gLines[k % NLINES]);
}

static void WriteLog(void)
{
	FSSpec spec;
	short ref, i;
	long n, k, first;
	char s[200];
	if (FSMakeFSSpec(0, 0, "\pSniffProbe log", &spec) == fnfErr) FSpCreate(&spec, 'ttxt', 'TEXT', smSystemScript);
	if (FSpOpenDF(&spec, fsRdWrPerm, &ref) != noErr) return;
	SetEOF(ref, 0);
#define PUT(str) { char *q = (str); Cat(q, "\r"); n = 0; while (q[n]) n++; FSWrite(ref, &n, q); }
	s[0] = 0; Cat(s, "SniffProbe  my MAC "); if (gHaveMAC) CatMAC(s, gMyMAC); Cat(s, "  seconds ");
	CatNum(s, (TickCount() - gStart) / 60L); PUT(s);
	for (i = 0; i < NEP; i++) { EpStatus(&gEp[i], s); PUT(s); }
	Totals(s); PUT(s);
	first = gNLine > NLINES ? gNLine - NLINES : 0;
	for (k = first; k < gNLine; k++) { s[0] = 0; Cat(s, gLines[k % NLINES]); PUT(s); }
	FSClose(ref);
}

void main(void)
{
	Rect r;
	EventRecord ev;
	long lastDraw = 0;
	short i;

	InitGraf((Ptr) &qd.thePort);
	InitFonts(); InitWindows(); InitMenus(); FlushEvents(everyEvent, 0); TEInit(); InitDialogs(0L); InitCursor();
	SetRect(&r, 20, 44, 700, 470);
	gWin = NewWindow(NULL, &r, "\pSniffProbe - raw Ethernet", true, documentProc, (WindowPtr) -1L, false, 0);
	gLines = (char (*)[LINELEN]) NewPtrClear((long) NLINES * LINELEN);
	TrailOpen();
	Crumb("InitOpenTransport", NULL, NOVAL);
	if (InitOpenTransport() != noErr || !gLines) {
		SetPort(gWin); Show(14, "Open Transport failed - click to quit");
		while (!Button()) ;
		return;
	}
	Crumb("OTInetGetInterfaceInfo", NULL, NOVAL);
	{ InetInterfaceInfo info; if (OTInetGetInterfaceInfo(&info, 0) == noErr) gMyIP = info.fAddress; }
	Crumb("  done", NULL, NOVAL);
	Draw();
	for (i = 0; i < NEP; i++) { OpenEp(&gEp[i]); Draw(); }
	Crumb("event loop", NULL, NOVAL);
	gStart = TickCount();
	for (;;) {
		if (WaitNextEvent(everyEvent, &ev, 2, NULL)) {		/* the update event must be answered (see OTProbe) */
			if (ev.what == mouseDown) break;
			if (ev.what == updateEvt) { BeginUpdate((WindowPtr) ev.message); Draw(); EndUpdate((WindowPtr) ev.message); }
		}
		for (i = 0; i < NEP; i++) Poll(&gEp[i]);
		if (TickCount() - lastDraw > 30) { Draw(); lastDraw = TickCount(); }
	}
	for (i = 0; i < NEP; i++) CloseEp(&gEp[i]);
	WriteLog();
	Crumb("quit", NULL, NOVAL);
	if (gTrail) FSClose(gTrail);
	CloseOpenTransport();
}
