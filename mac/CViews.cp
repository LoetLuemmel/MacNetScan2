/******************************************************************************
 CViews.c

	MacNetScan 2's Listen, Map, Frames and Tools views (phase 4); AppleTalk is CATView.cp.
	Pit Förster with Claude Code via AppleBridge, 2026-10-27.

	Every view draws straight from the engine's tables (netcore.h): nothing
	is copied, so a redraw is always the current state. The source is plain
	ASCII; characters outside it are MacRoman escapes.

 ******************************************************************************/

#include "CMain.h"
#include "CViews.h"
#include "netcore.h"
#include "Look.h"

#include <CScrollPane.h>
#include <Memory.h>
#include <Dialogs.h>
#include <Files.h>
#include <Folders.h>
#include <Resources.h>
#include <ToolUtils.h>
#include <Script.h>
#include <Errors.h>

/******************************************************************************
 Demo mode - made-up names, MACs and IPv6 interface IDs for public screenshots

	A registry maps each real name the engine knows (hosts, NBP objects, LLDP
	systems, zones, volumes) to a made-up one, in the order they turn up, so a
	device keeps its name in every view. The hosts become the E-Maculation
	regulars' Macs - "emendelson's Quadra 950" - a joke for the forum, and plainly
	no real device. MACs and IPv6 interface IDs are hashed into invented ones,
	the same input always giving the same output. Display only: Export, Copy and
	the pcap file stay real.

 ******************************************************************************/

Boolean gDemo = FALSE;

#define kDemoMax	160
#define kDemoLen	48
typedef struct { char real[kDemoLen]; char fake[kDemoLen]; short len; } DemoEntry;

static DemoEntry		*gDemoReg = NULL;
static short			gDemoN = 0, gDemoKindN[3] = { 0, 0, 0 };
static long				gDemoSig = -1;
static unsigned long	gDemoTick = 0;

static const char *kDemoWho[] = { "Ronald P. Regensburg", "emendelson", "adespoton", "KnuddlMac", "Mabam",
	"marciot42", "kanjitalk755", "Cat_7" };
static const char *kDemoModel[] = { "Quadra 950", "PowerBook 170", "Centris 650", "LC III", "IIci", "SE/30",
	"Performa 6200", "Power Mac 8100", "Color Classic", "PowerBook Duo 230", "Quadra 700", "IIfx", "Classic II",
	"PowerBook 540c" };
static const char *kDemoZoneName[] = { "Engineering", "Marketing", "Lab", "Basement" };
static const char *kDemoVolName[] = { "Macintosh HD", "Projects", "Archive", "Developer CD", "System Disk",
	"Applications", "Scratch", "Install CD" };
#define kDemoWhoN	8
#define kDemoModelN	14

static Boolean DemoAlnum(char c)
{
	return (Boolean) ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'));
}

static Boolean DemoHex(char c)
{
	return (Boolean) ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
}

static unsigned long DemoHash(const char *s, short n)		/* FNV-1a, case folded */
{
	unsigned long h = 2166136261UL;
	short i;
	for (i = 0; i < n; i++) {
		char c = s[i];
		if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
		h = (h ^ (unsigned char) c) * 16777619UL;
	}
	return h;
}

static void DemoPut(const char *real, short n, const char *fake)
{
	short i;
	for (i = 0; i < gDemoN; i++)
		if (gDemoReg[i].len == n) {
			short k = 0;
			while (k < n && gDemoReg[i].real[k] == real[k]) k++;
			if (k == n) return;									/* known: keeps its name */
		}
	if (gDemoN >= kDemoMax) return;
	for (i = 0; i < n; i++) gDemoReg[gDemoN].real[i] = real[i];
	gDemoReg[gDemoN].real[n] = '\0';
	gDemoReg[gDemoN].len = n;
	gDemoReg[gDemoN].fake[0] = '\0';
	CCat(gDemoReg[gDemoN].fake, fake);
	gDemoN++;
}

static short DemoFind(const char *real, short n)
{
	short i, k;
	for (i = 0; i < gDemoN; i++)
		if (gDemoReg[i].len == n) {
			for (k = 0; k < n && gDemoReg[i].real[k] == real[k]; k++) ;
			if (k == n) return i;
		}
	return -1;
}

void DemoAdd(const char *real, short kind)
{
	char fake[kDemoLen];
	short n = CLen(real), k, dot;

	if (gDemoReg == NULL) {
		gDemoReg = (DemoEntry *) NewPtrClear((Size) sizeof(DemoEntry) * kDemoMax);
		if (gDemoReg == NULL) return;
	}
	if (n < 3 || n >= kDemoLen || real[0] == '?' || DemoFind(real, n) >= 0) return;
	for (k = 0; k < n && ((real[k] >= '0' && real[k] <= '9') || real[k] == '.'); k++) ;
	if (k == n) return;										/* an address, not a name */
	k = gDemoKindN[kind]++;
	fake[0] = '\0';
	if (kind == kDemoHost) {
		CCat(fake, kDemoWho[k % kDemoWhoN]); CCat(fake, "'s "); CCat(fake, kDemoModel[(k / kDemoWhoN) % kDemoModelN]);
		if (k >= kDemoWhoN * kDemoModelN) { CCat(fake, " "); CCatNum(fake, k / (kDemoWhoN * kDemoModelN) + 1); }
	} else if (kind == kDemoZone) {
		if (k < 4) CCat(fake, kDemoZoneName[k]); else { CCat(fake, "Zone "); CCatNum(fake, k + 1); }
	} else {
		if (k < 8) CCat(fake, kDemoVolName[k]); else { CCat(fake, "Volume "); CCatNum(fake, k + 1); }
	}
	DemoPut(real, n, fake);
	if (kind == kDemoHost) {								/* "unifi" of "unifi.localdomain": the same Mac */
		for (dot = 0; dot < n && real[dot] != '.'; dot++) ;
		if (dot >= 3 && dot < n) DemoPut(real, dot, fake);
	}
}

static void DemoCollect(void)							/* what the engine knows, when it changed */
{
	long sig = NC_ChangeCount() + NC_HostCount() * 7L + NC_EntityCount() * 131L + NC_StationCount() * 1031L
			   + NC_VolumeCount() * 7919L + NC_ATRouteCount() * 30011L;
	short i;
	if (sig == gDemoSig && TickCount() - gDemoTick < 120) return;
	gDemoSig = sig;
	gDemoTick = TickCount();
	for (i = 0; i < NC_HostCount(); i++) DemoAdd(NC_Host(i)->name, kDemoHost);
	for (i = 0; i < NC_EntityCount(); i++) {
		const NCEntity *e = NC_Entity(i);
		if (e == NULL) continue;
		DemoAdd(e->object, kDemoHost);
		DemoAdd(e->zone, kDemoZone);
	}
	for (i = 0; i < NC_ATRouteCount(); i++) { const NCATRoute *rt = NC_ATRoute(i); if (rt) DemoAdd(rt->zone, kDemoZone); }
	for (i = 0; i < NC_StationCount(); i++) DemoAdd(NC_Station(i)->name, kDemoHost);
	for (i = 0; i < NC_VolumeCount(); i++) DemoAdd(NC_Volume(i)->name, kDemoVol);
}

static void DemoOut(char *out, short *o, short max, const char *s)
{
	while (*s && *o < max - 1) out[(*o)++] = *s++;
}

static void DemoHexOut(char *out, short *o, short max, unsigned long v, short digits)
{
	static const char hx[] = "0123456789abcdef";
	short d;
	for (d = (short) (digits - 1); d >= 0; d--) if (*o < max - 1) out[(*o)++] = hx[(v >> (d * 4)) & 15];
}

void DemoText(const char *in, char *out, short max)
{
	short i = 0, o = 0, n = CLen(in), j, L, best, bestLen, colons;
	unsigned long h;

	DemoCollect();
	while (i < n && o < max - 1) {
		if (i == 0 || !DemoAlnum(in[i - 1])) {
			/* a MAC: six pairs of hex digits */
			if (n - i >= 17 && (n - i == 17 || !DemoAlnum(in[i + 17]))) {
				for (j = 0; j < 17; j++) if ((j % 3 == 2) ? in[i + j] != ':' : !DemoHex(in[i + j])) break;
				if (j == 17) {
					h = DemoHash(in + i, 17);
					DemoOut(out, &o, max, "02:00:00:");
					DemoHexOut(out, &o, max, h >> 16 & 0xFF, 2); DemoOut(out, &o, max, ":");
					DemoHexOut(out, &o, max, h >> 8 & 0xFF, 2); DemoOut(out, &o, max, ":");
					DemoHexOut(out, &o, max, h & 0xFF, 2);
					i = (short) (i + 17);
					continue;
				}
			}
			/* IPv6: hex digits and colons, "::" or seven colons; well-known multicast and loopback stay */
			for (L = 0, colons = 0; i + L < n && (DemoHex(in[i + L]) || in[i + L] == ':'); L++) if (in[i + L] == ':') colons++;
			if (colons >= 2 && L >= 4 && (i + L == n || !DemoAlnum(in[i + L]))) {
				Boolean dbl = FALSE;
				for (j = 0; j + 1 < L; j++) if (in[i + j] == ':' && in[i + j + 1] == ':') dbl = TRUE;
				if (dbl || colons == 7) {
					Boolean keep = (Boolean) ((in[i] == 'f' || in[i] == 'F') && (in[i + 1] == 'f' || in[i + 1] == 'F'));
					if (keep) { for (j = 0; j < L; j++) if (o < max - 1) out[o++] = in[i + j]; }
					else {
						h = DemoHash(in + i, L);
						if ((in[i] == 'f' || in[i] == 'F') && (in[i + 1] == 'e' || in[i + 1] == 'E')) DemoOut(out, &o, max, "fe80::");
						else DemoOut(out, &o, max, "fd00::");
						DemoHexOut(out, &o, max, h >> 16, 4); DemoOut(out, &o, max, ":"); DemoHexOut(out, &o, max, h & 0xFFFF, 4);
					}
					i = (short) (i + L);
					continue;
				}
			}
			/* an ip6.arpa reverse name: single hex digits between dots ("1.e.7.3.5..."), an IPv6 address backwards */
			for (L = 0, colons = 0; i + L + 1 < n && DemoHex(in[i + L]) && in[i + L + 1] == '.'; L += 2) colons++;
			if (colons >= 8) {
				static const char hx[] = "0123456789abcdef";
				Boolean last = (Boolean) (i + L < n && DemoHex(in[i + L]) && (i + L + 1 == n || !DemoAlnum(in[i + L + 1])));
				h = DemoHash(in + i, L);
				for (j = 0; j < colons; j++) {
					h = h * 1103515245UL + 12345UL;					/* a stream of made-up nibbles */
					if (o < max - 2) { out[o++] = hx[(h >> 16) & 15]; out[o++] = '.'; }
				}
				if (last) {											/* a final digit without its dot */
					h = h * 1103515245UL + 12345UL;
					if (o < max - 1) out[o++] = hx[(h >> 16) & 15];
					L++;
				}
				i = (short) (i + L);
				continue;
			}
			/* an mDNS instance or host name: "name.local", "name._service" - a name the engine may not list */
			if (in[i] != '_' && (i == 0 || in[i - 1] == ' ')) {		/* not "link" of "_companion-link._tcp" */
				for (L = 0; i + L < n && (DemoAlnum(in[i + L]) || in[i + L] == '-'); L++) ;
				if (L >= 3 && L < kDemoLen && i + L + 1 < n && in[i + L] == '.'
					&& (in[i + L + 1] == '_' || (n - i - L >= 6 && in[i + L + 1] == 'l' && in[i + L + 2] == 'o'
						&& in[i + L + 3] == 'c' && in[i + L + 4] == 'a' && in[i + L + 5] == 'l'))) {
					char t[kDemoLen];
					for (j = 0; j < L; j++) t[j] = in[i + j];
					t[L] = '\0';
					DemoAdd(t, kDemoHost);
				}
			}
			/* a registered name, the longest that matches here */
			for (j = 0, best = -1, bestLen = 0; j < gDemoN; j++) {
				short k;
				L = gDemoReg[j].len;
				if (L <= bestLen || L > n - i || (i + L < n && DemoAlnum(in[i + L]))) continue;
				for (k = 0; k < L && in[i + k] == gDemoReg[j].real[k]; k++) ;
				if (k == L) { best = j; bestLen = L; }
			}
			if (best >= 0) {
				DemoOut(out, &o, max, gDemoReg[best].fake);
				i = (short) (i + bestLen);
				continue;
			}
		}
		out[o++] = in[i++];
	}
	out[o] = '\0';
}

static const RGBColor kConflict   = { 0xCCCC, 0x3333, 0x3333 };
static const RGBColor kBox        = { 0xFFFF, 0xFFFF, 0xFFFF };

static Boolean StartsWith(const char *s, const char *p)
{
	while (*p) if (*s++ != *p++) return FALSE;
	return TRUE;
}

static Boolean HasText(const char *s, const char *p)
{
	for (; *s; s++) if (StartsWith(s, p)) return TRUE;
	return FALSE;
}

static void SectionTitle(short x, short y, const char *t)
{
	TextFont(kGeneva); TextSize(9); TextFace(bold);
	RGBForeColor(&kInkSoft);
	MoveTo(x, y);
	DrawC(t);
	TextFace(normal);
}

/******************************************************************************
 CListenPane

 ******************************************************************************/

#define kMeters	9
static const char *kMeterName[kMeters] = { "ARP", "Broadcast", "Multicast", "DHCP", "NetBIOS", "IPv6", "LLDP",
										   "AppleTalk", "AARP" };
static const RGBColor kMeterColour[kMeters] = {				/* one family: ochre, steel, petrol, green, sky, */
	{ 0xCCCC, 0x9999, 0x3333 }, { 0x3333, 0x6666, 0x9999 }, { 0x3333, 0x9999, 0x9999 }, { 0x3333, 0x9999, 0x6666 },
	{ 0x6666, 0x9999, 0xCCCC }, { 0x6666, 0x9999, 0x3333 }, { 0xCCCC, 0x6666, 0x3333 },	/* olive, rust,	*/
	{ 0x9999, 0x3333, 0x6666 }, { 0x9999, 0x6666, 0x9999 }								/* plum, mauve	*/
};

static void MeterValues(long v[kMeters])
{
	NCListenStats s;
	NC_ListenGetStats(&s);
	v[0] = s.arp; v[1] = s.ipBroadcast; v[2] = s.ipMulticast; v[3] = s.dhcp;
	v[4] = s.netbios; v[5] = s.ipv6; v[6] = s.lldp; v[7] = s.ddp; v[8] = s.aarp;
}

CListenPane::CListenPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight,
						 short aHEncl, short aVEncl)
	: CPane(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizELASTIC, sizELASTIC)
{
	short i;
	for (i = 0; i < kMeters; i++) { last[i] = 0; litUntil[i] = 0; lit[i] = FALSE; }
}

void CListenPane::DrawMeters(Boolean all)
{
	Rect r, k, cell;
	long v[kMeters];
	char s[24];
	short i, x;
	unsigned long now = TickCount();

	FrameToQDR(&frame, &r);
	MeterValues(v);
	for (i = 0; i < kMeters; i++) {
		Boolean on = (Boolean) (now < litUntil[i]);
		if (!all && on == lit[i] && v[i] == last[i]) continue;
		lit[i] = on;
		x = (short) (r.left + 14 + i * 77);
		SetRect(&cell, x, (short) (r.top + 8), (short) (x + 73), (short) (r.top + 44));
		RGBForeColor(&kBox);
		PaintRoundRect(&cell, 8, 8);
		RGBForeColor(&kStatusLn);
		FrameRoundRect(&cell, 8, 8);
		SetRect(&k, (short) (x + 6), (short) (r.top + 14), (short) (x + 18), (short) (r.top + 26));
		DrawLed(&k, &kMeterColour[i], on);
		TextFont(kGeneva); TextSize(9); TextFace(normal);
		RGBForeColor(&kInkSoft);
		MoveTo((short) (x + 22), (short) (r.top + 24));
		DrawC(kMeterName[i]);
		s[0] = '\0'; CCatNum(s, v[i]);
		TextFace(bold);
		RGBForeColor(&kInk);
		MoveTo((short) (x + 22), (short) (r.top + 38));
		DrawC(s);
		TextFace(normal);
	}
	RGBForeColor(&kBlackC);
}

void CListenPane::Pulse()
{
	long v[kMeters];
	short i;
	unsigned long now = TickCount();
	Boolean changed = FALSE;
	MeterValues(v);
	for (i = 0; i < kMeters; i++) {
		if (v[i] != last[i]) litUntil[i] = now + 8;
		if (v[i] != last[i] || (Boolean) (now < litUntil[i]) != lit[i]) changed = TRUE;
	}
	if (changed && ReallyVisible()) {
		TextMode(srcOr);
		Prepare();
		DrawMeters(FALSE);
	}
	for (i = 0; i < kMeters; i++) last[i] = v[i];
}

void CListenPane::Draw(Rect *area)
{
	Rect r, k, row;
	char s[64], m[20];
	short i, j, n, y, shown, order[16];
	long first, e;
	unsigned long now = TickCount();
	Boolean used[128];

	TextMode(srcOr);
	FrameToQDR(&frame, &r);
	RGBForeColor(&kViewBg);
	PaintRect(&r);
	DrawMeters(TRUE);

	n = NC_StationCount();
	y = (short) (r.top + 66);
	s[0] = '\0'; CCat(s, "Stations seen  "); CCatNum(s, n);
	SectionTitle((short) (r.left + 14), y, s);
	SectionTitle((short) (r.left + 160), y, "IP address");
	SectionTitle((short) (r.left + 270), y, "AppleTalk/LLDP");
	SectionTitle((short) (r.left + 360), y, "Heard");
	SectionTitle((short) (r.left + 470), y, "Packets");
	SectionTitle((short) (r.left + 560), y, "Last heard");
	RGBForeColor(&kStatusLn);
	MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));

	for (i = 0; i < n && i < 128; i++) used[i] = FALSE;			/* the most recently heard first */
	for (shown = 0; shown < 11 && shown < n; shown++) {
		short best = -1;
		for (i = 0; i < n && i < 128; i++)
			if (!used[i] && (best < 0 || NC_Station(i)->lastTick > NC_Station(best)->lastTick)) best = i;
		if (best < 0) break;
		used[best] = TRUE;
		order[shown] = best;
	}
	y = (short) (y + 20);
	TextFont(kGeneva); TextSize(9);
	for (j = 0; j < shown; j++, y += 16) {
		const NCStation *st = NC_Station(order[j]);
		static const short kStCols[] = { 160, 270, 360, 470, 560 };
		SetRect(&row, (short) (r.left + 8), (short) (y - 12), (short) (r.right - 8), (short) (y + 4));
		GridRow(&row, r.left, kStCols, 5);
		SetRect(&k, (short) (r.left + 12), (short) (y - 10), (short) (r.left + 22), y);
		DrawLed(&k, &kAlive, (Boolean) (now - st->lastTick < 180));	/* lit: heard in the last 3 s */
		TextFont(kMonaco);
		RGBForeColor(&kInk);
		NC_MACToStr(st->mac, m);
		MoveTo((short) (r.left + 28), y); DrawC(m);
		s[0] = '\0';
		if (st->ip) NC_IPToStr(st->ip, s);
		MoveTo((short) (r.left + 160), y); DrawC(s);
		s[0] = '\0';
		if (st->atNet) { CCatNum(s, st->atNet); CCat(s, "."); CCatNum(s, st->atNode); }
		MoveTo((short) (r.left + 270), y);
		if (s[0] || !st->name[0]) DrawC(s);
		else { TextFont(kGeneva); DrawTrunc(st->name, 86); }	/* a switch has a name, not a node */
		TextFont(kGeneva);
		s[0] = '\0';
		if (st->seen & NC_SEEN_SELF) CCat(s, "this Mac ");
		if (st->seen & NC_SEEN_ARP) CCat(s, "ARP ");
		if (st->seen & NC_SEEN_IP) CCat(s, "IP ");
		if (st->seen & NC_SEEN_IP6) CCat(s, "IPv6 ");
		if (st->seen & NC_SEEN_LLDP) CCat(s, "LLDP ");
		if (st->seen & NC_SEEN_AT) CCat(s, "AppleTalk");
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 360), y); DrawC(s);
		s[0] = '\0'; CCatNum(s, st->packets);
		RGBForeColor(&kInk);
		MoveTo((short) (r.left + 470), y); DrawC(s);
		s[0] = '\0'; CCatNum(s, (long) ((now - st->lastTick) / 60)); CCat(s, " s ago");
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 560), y); DrawC(s);
	}
	if (n == 0) {
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 28), y);
		DrawC(NC_Listening() ? "Listening - nothing heard yet." :
			  "Press Scan to listen. MacNetScan sends nothing; it hears ARP, broadcasts, multicast, IPv6, LLDP and AppleTalk.");
	}

	y = (short) (r.top + 272);
	SectionTitle((short) (r.left + 14), y, "Events");
	SetRect(&row, (short) (r.left + 8), (short) (y + 6), (short) (r.right - 8), (short) (r.bottom - 8));
	RGBForeColor(&kBox);
	PaintRect(&row);
	RGBForeColor(&kStatusLn);
	FrameRect(&row);
	e = NC_EventTotal();
	first = e > 6 ? e - 6 : 0;
	y = (short) (y + 20);
	TextFont(kMonaco); TextSize(9);
	for (; first < e; first++, y += 13) {
		const char *l = NC_EventLine(first);
		RGBForeColor(HasText(l, "CONFLICT") ? &kConflict : &kInk);
		MoveTo((short) (r.left + 16), y);
		DrawTrunc(l, (short) (r.right - r.left - 40));
	}
	RGBForeColor(&kBlackC);
}

/******************************************************************************
 CMapPane - who sends to whom

 ******************************************************************************/

#define MAP_STATIONS	20									/* the busiest stations on the outer ring		*/
#define MAP_OUTER		kMapNodes							/* and addresses only ever seen as destinations	*/

static const char *kGroupName[NC_TO_COUNT] = { "Unicast", "Broadcast", "mDNS", "IPv6 multicast", "LLDP",
											   "Multicast", "AppleTalk" };
static const RGBColor kMcOther = { 0x9999, 0x9999, 0x9999 };
static const RGBColor *kEdgeColour[NC_TO_COUNT] = { &kInkSoft, &kMeterColour[1], &kMeterColour[2], &kMeterColour[5],
													&kMeterColour[6], &kMcOther, &kMeterColour[7] };
static const short kSin16[17] = { 0, 98, 195, 290, 383, 471, 556, 634, 707, 773, 831, 882, 924, 957, 981, 995, 1000 };

static short SinStep(short a)									/* a in 64ths of a turn; thousandths	*/
{
	short r = (short) (a & 15);
	switch ((a & 63) >> 4) {
		case 0:  return kSin16[r];
		case 1:  return kSin16[16 - r];
		case 2:  return (short) -kSin16[r];
	}
	return (short) -kSin16[16 - r];
}

static void RingPoint(short i, short n, short cx, short cy, short rx, short ry, Point *pt)	/* i of n, from the top */
{
	short a = (short) (i * 64 / n);
	pt->h = (short) (cx + (long) rx * SinStep(a) / 1000);
	pt->v = (short) (cy - (long) ry * SinStep((short) (a + 16)) / 1000);
}

CMapPane::CMapPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight,
				   short aHEncl, short aVEncl)
	: CPane(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizELASTIC, sizELASTIC)
{
	offscreen = NULL;
	nodes = 0;
	selected = FALSE;
	selSt = -1;
	selIP = 0;
	SetWantsClicks(TRUE);
}

	/* a node within 8 px selects it, anywhere else clears the selection */
void CMapPane::DoClick(Point hitPt, short modifierKeys, long when)
{
	LongPt lp;
	Point q;
	short i;
	lp.h = hitPt.h; lp.v = hitPt.v;
	FrameToQD(&lp, &q);
	for (i = 0; i < nodes; i++)
		if (q.h >= nodePt[i].h - 8 && q.h <= nodePt[i].h + 8 && q.v >= nodePt[i].v - 8 && q.v <= nodePt[i].v + 8) break;
	selected = (Boolean) (i < nodes);
	if (selected) { selSt = nodeSt[i]; selIP = nodeIP[i]; }
	Update();
}

CMapPane::~CMapPane()
{
	if (offscreen != NULL) DisposeGWorld(offscreen);
}

void CMapPane::Update()
{
	if (!ReallyVisible()) return;
	Prepare();
	Draw(NULL);
}

	/* into the GWorld, then one CopyBits: a redraw replaces the picture instead of wiping and repainting it */
void CMapPane::Draw(Rect *area)
{
	Rect r, b;
	CGrafPtr port;
	GDHandle dev;
	PixMapHandle pm;

	FrameToQDR(&frame, &r);
	if (offscreen != NULL) {									/* the window changed size: a new one */
		b = ((GrafPtr) offscreen)->portRect;
		if (b.left != r.left || b.top != r.top || b.right != r.right || b.bottom != r.bottom) {
			DisposeGWorld(offscreen);
			offscreen = NULL;
		}
	}
	if (offscreen == NULL && NewGWorld(&offscreen, 0, &r, NULL, NULL, 0) != noErr) offscreen = NULL;
	if (offscreen == NULL || !LockPixels(pm = GetGWorldPixMap(offscreen))) { DrawMap(&r); return; }
	GetGWorld(&port, &dev);
	SetGWorld(offscreen, NULL);
	DrawMap(&r);
	SetGWorld(port, dev);
	RGBForeColor(&kBlackC);										/* CopyBits colours by fore and back */
	RGBBackColor(&kWhiteC);
	CopyBits(&((GrafPtr) offscreen)->portBits, &((GrafPtr) port)->portBits, &r, &r, srcCopy, NULL);
	UnlockPixels(pm);
}

void CMapPane::DrawMap(Rect *rp)
{
	Rect r = *rp, k;
	Point outerPt[MAP_OUTER], groupPt[NC_TO_COUNT], to;
	NCAddr outerIP[MAP_OUTER];
	short outerSt[MAP_OUTER];									/* station index, -1: an address only	*/
	Boolean shown[128], groupUsed[NC_TO_COUNT];
	short n, e, i, j, g, a, b, m = 0, ng = 0, cx, cy, rx, ry, w, x, y, sel = -1, pass;
	char s[40];
	unsigned long now = TickCount();

	TextMode(srcOr);
	RGBForeColor(&kViewBg);
	PaintRect(&r);
	TextFont(kGeneva); TextSize(9); TextFace(normal);
	n = NC_StationCount();
	e = NC_EdgeCount();
	if (n > 128) n = 128;
	if (n == 0 || e == 0) {
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 28), (short) (r.top + 30));
		DrawC(NC_Listening() ? "Listening - nothing heard yet." :
			  "Press Scan to listen. The map draws who sends to whom, from what reaches this Mac.");
		RGBForeColor(&kBlackC);
		return;
	}

	for (i = 0; i < n; i++) shown[i] = FALSE;
	if (selected && nodes > 0) {								/* a selection freezes the ring: the nodes stay */
		for (i = 0; i < nodes; i++) {							/* where they were, under the pointer         */
			outerSt[m] = nodeSt[i];
			outerIP[m] = nodeIP[i];
			if (nodeSt[i] >= 0 && nodeSt[i] < n) shown[nodeSt[i]] = TRUE;
			m++;
		}
	} else {													/* the outer ring: busiest stations first */
		while (m < MAP_STATIONS) {
			short best = -1;
			for (i = 0; i < n; i++)
				if (!shown[i] && (best < 0 || NC_Station(i)->packets > NC_Station(best)->packets)) best = i;
			if (best < 0) break;
			shown[best] = TRUE;
			outerSt[m] = best; outerIP[m] = NC_Station(best)->ip; m++;
		}
		for (j = 0; j < e && m < MAP_OUTER; j++) {					/* then destinations no station claims */
			const NCEdge *ed = NC_Edge(j);
			if (ed->to != NC_TO_UNICAST || ed->dst == 0 || ed->from >= n || !shown[ed->from]) continue;
			for (i = 0; i < n && NC_Station(i)->ip != ed->dst; i++) ;
			if (i < n) continue;									/* a station: on the ring, or not busy enough */
			for (i = 0; i < m && outerIP[i] != ed->dst; i++) ;
			if (i < m) continue;
			outerSt[m] = -1; outerIP[m] = ed->dst; m++;
		}
		for (i = 1; i < m; i++) {									/* clockwise by address: a node keeps its place */
			short st0 = outerSt[i];
			NCAddr ip0 = outerIP[i];
			NCAddr key = ip0 ? ip0 : 0xFFFFFFFFUL;					/* MAC only: at the end, first heard first */
			for (j = i; j > 0; j--) {
				NCAddr k0 = outerIP[j - 1] ? outerIP[j - 1] : 0xFFFFFFFFUL;
				if (k0 < key || (k0 == key && outerSt[j - 1] <= st0)) break;
				outerSt[j] = outerSt[j - 1];
				outerIP[j] = outerIP[j - 1];
			}
			outerSt[j] = st0;
			outerIP[j] = ip0;
		}
	}
	for (g = 0; g < NC_TO_COUNT; g++) groupUsed[g] = FALSE;
	for (j = 0; j < e; j++) {
		const NCEdge *ed = NC_Edge(j);
		if (ed->to != NC_TO_UNICAST && ed->from < n && shown[ed->from]) groupUsed[ed->to] = TRUE;
	}
	for (g = 1; g < NC_TO_COUNT; g++) if (groupUsed[g]) ng++;

	cx = (short) ((r.left + r.right) / 2);						/* geometry: room for labels and the legend */
	cy = (short) ((r.top + r.bottom) / 2 - 8);
	rx = (short) ((r.right - r.left) / 2 - 110);
	ry = (short) ((r.bottom - r.top) / 2 - 40);
	for (g = 1, j = 0; g < NC_TO_COUNT; g++) if (groupUsed[g]) {
		if (ng == 1) { groupPt[g].h = cx; groupPt[g].v = cy; }
		else RingPoint(j, ng, cx, cy, (short) (rx * 4 / 10), (short) (ry * 4 / 10), &groupPt[g]);
		j++;
	}
	for (i = 0; i < m; i++) {
		RingPoint(i, m, cx, cy, rx, ry, &outerPt[i]);
		nodePt[i] = outerPt[i];									/* for the click */
		nodeSt[i] = outerSt[i];
		nodeIP[i] = outerIP[i];
		if (selected && (selSt >= 0 ? outerSt[i] == selSt : (outerSt[i] < 0 && outerIP[i] == selIP))) sel = i;
	}
	nodes = m;

	for (pass = 0; pass < 2; pass++)							/* edges: colour by target, width by packets;	*/
	for (j = 0; j < e; j++) {									/* a selection's own drawn last, others pale	*/
		const NCEdge *ed = NC_Edge(j);
		Boolean mine;
		if (ed->from >= n || !shown[ed->from]) continue;
		for (a = 0; a < m && outerSt[a] != ed->from; a++) ;
		if (a == m) continue;
		b = -1;
		if (ed->to == NC_TO_UNICAST) {
			for (b = 0; b < m && (outerIP[b] != ed->dst || b == a); b++) ;
			if (b == m) continue;
			to = outerPt[b];
		} else to = groupPt[ed->to];
		mine = (Boolean) (sel >= 0 && (a == sel || b == sel));
		if (pass != (mine ? 1 : 0)) continue;
		w = (short) (1 + (ed->packets >= 10) + (ed->packets >= 100) + (ed->packets >= 1000));
		if (sel >= 0 && !mine) w = 1;
		PenSize(w, w);
		RGBForeColor(sel >= 0 && !mine ? &kStatusLn : kEdgeColour[ed->to]);
		MoveTo((short) (outerPt[a].h - w / 2), (short) (outerPt[a].v - w / 2));
		LineTo((short) (to.h - w / 2), (short) (to.v - w / 2));
	}
	PenSize(1, 1);

	for (g = 1; g < NC_TO_COUNT; g++) if (groupUsed[g]) {		/* group nodes */
		w = (short) (WidthC(kGroupName[g]) + 14);
		SetRect(&k, (short) (groupPt[g].h - w / 2), (short) (groupPt[g].v - 9),
				(short) (groupPt[g].h + w / 2), (short) (groupPt[g].v + 9));
		RGBForeColor(&kBox);
		PaintRoundRect(&k, 14, 14);
		PenSize(2, 2);
		RGBForeColor(kEdgeColour[g]);
		FrameRoundRect(&k, 14, 14);
		PenSize(1, 1);
		RGBForeColor(&kInk);
		MoveTo((short) (k.left + 7), (short) (groupPt[g].v + 3));
		DrawC(kGroupName[g]);
	}
	for (i = 0; i < m; i++) {									/* station nodes: filled, lit when just heard */
		Boolean self = FALSE;
		SetRect(&k, (short) (outerPt[i].h - 6), (short) (outerPt[i].v - 6), (short) (outerPt[i].h + 6),
				(short) (outerPt[i].v + 6));
		s[0] = '\0';
		if (outerSt[i] >= 0) {
			const NCStation *st = NC_Station(outerSt[i]);
			RGBForeColor((now - st->lastTick < 180) ? &kAlive : &kStatusLn);
			PaintOval(&k);
			self = (Boolean) ((st->seen & NC_SEEN_SELF) || (st->ip != 0 && st->ip == NC_LocalIP()));
			if (self) CCat(s, "this Mac");
			else if (st->name[0]) CCat(s, st->name);
			else if (st->ip) NC_IPToStr(st->ip, s);
			else NC_MACToStr(st->mac, s);
		} else {												/* hollow: only ever a destination */
			RGBForeColor(&kBox);
			PaintOval(&k);
			self = (Boolean) (outerIP[i] == NC_LocalIP());
			if (self) CCat(s, "this Mac");
			else NC_IPToStr(outerIP[i], s);
		}
		RGBForeColor(&kInk);
		FrameOval(&k);
		if (i == sel) {											/* the selection: a ring in the accent colour */
			InsetRect(&k, -4, -4);
			PenSize(2, 2);
			RGBForeColor(&kAccent);
			FrameOval(&k);
			PenSize(1, 1);
		}
		if (self) { TextFace(bold); TextSize(12); }					/* the one node the reader looks for */
		w = WidthC(s);
		if (w > 110) w = 110;
		if (outerPt[i].h > cx + 12) { x = (short) (outerPt[i].h + 10); y = (short) (outerPt[i].v + 3); }
		else if (outerPt[i].h < cx - 12) { x = (short) (outerPt[i].h - 10 - w); y = (short) (outerPt[i].v + 3); }
		else { x = (short) (outerPt[i].h - w / 2); y = (short) (outerPt[i].v < cy ? outerPt[i].v - 9 : outerPt[i].v + 17); }
		RGBForeColor(outerSt[i] >= 0 || self ? &kInk : &kInkSoft);
		MoveTo(x, y);
		DrawTrunc(s, 110);
		if (self) { TextFace(normal); TextSize(9); }
	}

	x = (short) (r.left + 14);									/* legend */
	y = (short) (r.bottom - 10);
	for (g = 0; g < NC_TO_COUNT; g++) {
		PenSize(2, 2);
		RGBForeColor(kEdgeColour[g]);
		MoveTo(x, (short) (y - 4)); LineTo((short) (x + 14), (short) (y - 4));
		PenSize(1, 1);
		RGBForeColor(&kInkSoft);
		MoveTo((short) (x + 18), y);
		DrawC(kGroupName[g]);
		x = (short) (x + 18 + WidthC(kGroupName[g]) + 8);
	}
	MoveTo(x, y);
	DrawC("width = packets, hollow = destination only");
	if (selected) DrawInfo(&r, sel >= 0 ? &outerPt[sel] : (const Point *) NULL);
	RGBForeColor(&kBlackC);
}

	/* what is known about the selection: Listen's station, the map's edges, the IP scan's host */
#define INFO_LINES	22
#define INFO_LEN	48
void CMapPane::DrawInfo(Rect *rp, const Point *node)
{
	char line[INFO_LINES][INFO_LEN], s[INFO_LEN], t[20];
	short nl = 0, i, j, p, y, n = NC_StationCount(), e = NC_EdgeCount(), shownTo = 0, shownFrom = 0;
	const NCStation *st = (selSt >= 0 && selSt < n) ? NC_Station(selSt) : NULL;
	unsigned long ip = st ? st->ip : selIP, now = TickCount();
	const NCHost *h = ip ? HostByIP(ip) : NULL;
	const char *nm;
	const RGBColor *c;
	Rect k;

#define ADD(str)	{ if (nl < INFO_LINES) { line[nl][0] = '\0'; CCat(line[nl], str); nl++; } }
	s[0] = '\0';												/* line 0: the title */
	if (ip != 0 && ip == NC_LocalIP()) CCat(s, "this Mac");
	else if (st && st->name[0]) CCat(s, st->name);
	else if (h && h->name[0] && h->name[0] != '?') CCat(s, h->name);
	else if (ip) NC_IPToStr(ip, s);
	else if (st) NC_MACToStr(st->mac, s);
	ADD(s);
	if (ip) { s[0] = '\0'; CCat(s, "IP  "); NC_IPToStr(ip, t); CCat(s, t); ADD(s); }
	if (st) {
		s[0] = '\0'; CCat(s, "MAC  "); NC_MACToStr(st->mac, t); CCat(s, t); ADD(s);
		if (st->atNet) { s[0] = '\0'; CCat(s, "AppleTalk  "); CCatNum(s, st->atNet); CCat(s, "."); CCatNum(s, st->atNode); ADD(s); }
		if (st->name[0]) { s[0] = '\0'; CCat(s, "LLDP  "); CCat(s, st->name); ADD(s); }
		s[0] = '\0'; CCat(s, "Heard  ");
		if (st->seen & NC_SEEN_ARP) CCat(s, "ARP ");
		if (st->seen & NC_SEEN_IP) CCat(s, "IP ");
		if (st->seen & NC_SEEN_IP6) CCat(s, "IPv6 ");
		if (st->seen & NC_SEEN_LLDP) CCat(s, "LLDP ");
		if (st->seen & NC_SEEN_AT) CCat(s, "AppleTalk");
		ADD(s);
		s[0] = '\0'; CCat(s, "Packets  "); CCatNum(s, st->packets);
		CCat(s, ", last "); CCatNum(s, (long) ((now - st->lastTick) / 60)); CCat(s, " s ago"); ADD(s);
	} else ADD("Never heard sending");
	if (h) {													/* from the IP scan */
		if (h->name[0] && h->name[0] != '?') {
			s[0] = '\0'; CCat(s, "Name  "); CCat(s, h->name);
			CCat(s, h->nameSource == 'N' ? " (NetBIOS)" : h->nameSource == 'M' ? " (mDNS)" : h->nameSource == 'D' ? " (DNS)" : "");
			ADD(s);
		}
		if (h->rttUs >= 0) { s[0] = '\0'; CCat(s, "Round trip  "); NC_RttToStr(h->rttUs, t); CCat(s, t); CCat(s, " ms"); ADD(s); }
		s[0] = '\0'; CCat(s, "Open ");
		for (p = 0; p < NC_PortCount(); p++)
			if (h->openMask & (1UL << p)) { SvcFor(p, &nm, &c); CCat(s, " "); CCat(s, nm); }
		if (h->openMask == 0) CCat(s, " -");
		ADD(s);
	}
	if (st) {													/* where it sends */
		ADD("\001Sends to");
		for (j = 0; j < e && shownTo < 6; j++) {
			const NCEdge *ed = NC_Edge(j);
			if (ed->from != selSt) continue;
			s[0] = '\0'; CCat(s, "  ");
			if (ed->to == NC_TO_UNICAST) { NC_IPToStr(ed->dst, t); CCat(s, t); } else CCat(s, kGroupName[ed->to]);
			CCat(s, "  "); CCatNum(s, ed->packets); ADD(s);
			shownTo++;
		}
	}
	if (ip) {													/* who sends to it */
		for (j = 0; j < e && shownFrom < 5; j++) {
			const NCEdge *ed = NC_Edge(j);
			const NCStation *f;
			if (ed->to != NC_TO_UNICAST || ed->dst != ip || ed->from >= n) continue;
			if (shownFrom == 0) ADD("\001Heard from");
			f = NC_Station(ed->from);
			s[0] = '\0'; CCat(s, "  ");
			if (f->ip) NC_IPToStr(f->ip, t); else NC_MACToStr(f->mac, t);
			CCat(s, t); CCat(s, "  "); CCatNum(s, ed->packets); ADD(s);
			shownFrom++;
		}
	}
#undef ADD

	{															/* the corner across from the node, above the legend */
		short hgt = (short) (26 + (nl - 1) * 12 + 8), l, t;
		Boolean left = (Boolean) (node != NULL && node->h > (rp->left + rp->right) / 2);
		Boolean low = (Boolean) (node != NULL && node->v < (rp->top + rp->bottom) / 2);
		l = (short) (left ? rp->left + 10 : rp->right - 236);
		t = (short) (low ? rp->bottom - 24 - hgt : rp->top + 10);
		SetRect(&k, l, t, (short) (l + 226), (short) (t + hgt));
	}
	RGBForeColor(&kBox);
	PaintRoundRect(&k, 10, 10);
	PenSize(2, 2);
	RGBForeColor(&kAccent);
	FrameRoundRect(&k, 10, 10);
	PenSize(1, 1);
	TextFont(kGeneva); TextSize(12); TextFace(bold);
	RGBForeColor(&kInk);
	MoveTo((short) (k.left + 10), (short) (k.top + 18));
	DrawTrunc(line[0], (short) (k.right - k.left - 20));
	TextSize(9);
	for (i = 1, y = (short) (k.top + 34); i < nl; i++, y += 12) {
		Boolean head = (Boolean) (line[i][0] == '\001');
		TextFace(head ? bold : normal);
		RGBForeColor(head ? &kInk : &kInkSoft);
		MoveTo((short) (k.left + 10), y);
		DrawTrunc(head ? line[i] + 1 : line[i], (short) (k.right - k.left - 20));
	}
	TextFace(normal);
}

/******************************************************************************
 CFrameList - the capture, one row a frame

 ******************************************************************************/

enum { kFcNo = 6, kFcTime = 46, kFcSrc = 108, kFcDst = 232, kFcProto = 356, kFcLen = 414, kFcInfo = 450 };
static const short kFcCols[] = { kFcTime, kFcSrc, kFcDst, kFcProto, kFcLen, kFcInfo };	/* the grid's columns */

static const RGBColor *ProtoColour(unsigned short type)		/* the Listen meters' colours */
{
	switch (type) {
		case 0x0806: return &kMeterColour[0];
		case 0x86DD: return &kMeterColour[5];
		case 0x88CC: return &kMeterColour[6];
		case 0x809B: return &kMeterColour[7];
		case 0x80F3: return &kMeterColour[8];
	}
	return &kMeterColour[1];
}

static void CatTime(char *s, unsigned long us)					/* "12.345" */
{
	unsigned long ms = (us / 1000UL) % 1000UL;
	CCatNum(s, (long) (us / 1000000UL));
	CCat(s, ms < 10 ? ".00" : ms < 100 ? ".0" : ".");
	CCatNum(s, (long) ms);
}

CFrameList::CFrameList(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight)
	: CPanorama(anEnclosure, aSupervisor, aWidth, aHeight, 0, 0, sizELASTIC, sizELASTIC)
{
	first = rows = 0;
	sel = -1;
	SetScales(1, kFrameRow);									/* scrolls a row at a time		*/
	SetWantsClicks(TRUE);
	Update();
}

void CFrameList::Update()
{
	LongRect b;
	LongPt pos;
	short w, h;
	long total = NC_FrameTotal(), vis;
	if (sel >= 0) return;										/* a selection holds the list still */
	rows = total < NC_MAXFRAMES ? total : NC_MAXFRAMES;
	first = total - rows;
	GetLengths(&w, &h);
	vis = h / kFrameRow;										/* follow the newest */
	pos.h = 0; pos.v = rows > vis ? rows - vis : 0;
	if (pos.v < position.v) ScrollTo(&pos, FALSE);				/* shrinking (a new capture): back up first, */
	b.left = 0; b.top = 0; b.right = w; b.bottom = rows;		/* SetBounds asserts position.v <= bottom	 */
	SetBounds(&b);
	if (itsScrollPane != NULL) itsScrollPane->AdjustScrollMax();
	ScrollTo(&pos, FALSE);
	if (itsScrollPane != NULL) itsScrollPane->Calibrate();
	Refresh();
}

void CFrameList::Draw(Rect *area)
{
	LongRect lr;
	Rect r, cut;
	char src[48], dst[48], proto[16], info[96], s[16];
	short w, h, y;
	long i;

	TextMode(srcOr);
	RGBForeColor(&kWhiteC);
	PaintRect(area);
	TextFont(kGeneva); TextSize(9); TextFace(normal);
	GetLengths(&w, &h);
	if (gShowGrid) {										/* the grid on below the last frame */
		for (i = rows; ; i++) {
			lr.top = i * kFrameRow; lr.bottom = lr.top + kFrameRow;
			lr.left = 0; lr.right = frame.right - frame.left;
			FrameToQDR(&lr, &r);
			if (r.top > area->bottom) break;
			if (r.bottom >= area->top) GridRow(&r, r.left, kFcCols, 6);
		}
	}
	for (i = 0; i < rows; i++) {
		const NCFrame *f = NC_Frame(first + i);
		lr.top = i * kFrameRow; lr.bottom = lr.top + kFrameRow;
		lr.left = 0; lr.right = w;
		FrameToQDR(&lr, &r);
		if (!SectRect(&r, area, &cut)) continue;
		if (first + i == sel) { RGBForeColor(&kSelRow); PaintRect(&r); }
		GridRow(&r, r.left, kFcCols, 6);
		y = (short) (r.top + 10);
		RGBForeColor(&kInkSoft);
		s[0] = '\0'; CCatNum(s, first + i + 1);
		MoveTo((short) (r.left + kFcNo), y); DrawC(s);
		if (f == NULL) { MoveTo((short) (r.left + kFcTime), y); DrawC("(overwritten)"); continue; }
		NC_FrameSummary(f, src, dst, proto, info);
		s[0] = '\0'; CatTime(s, f->us);
		MoveTo((short) (r.left + kFcTime), y); DrawC(s);
		RGBForeColor(&kInk);
		MoveTo((short) (r.left + kFcSrc), y); DrawTrunc(src, kFcDst - kFcSrc - 6);
		MoveTo((short) (r.left + kFcDst), y); DrawTrunc(dst, kFcProto - kFcDst - 6);
		RGBForeColor(ProtoColour(f->type));
		TextFace(bold);
		MoveTo((short) (r.left + kFcProto), y); DrawTrunc(proto, kFcLen - kFcProto - 4);
		TextFace(normal);
		RGBForeColor(&kInkSoft);
		s[0] = '\0'; CCatNum(s, f->len);
		MoveTo((short) (r.left + kFcLen), y); DrawC(s);
		RGBForeColor(&kInk);
		MoveTo((short) (r.left + kFcInfo), y); DrawTrunc(info, (short) (r.right - r.left - kFcInfo - 4));
	}
	RGBForeColor(&kBlackC);
}

void CFrameList::DoClick(Point hitPt, short modifierKeys, long when)
{
	long row = hitPt.v / kFrameRow;
	if (row < 0 || row >= rows) return;
	sel = (first + row == sel) ? -1 : first + row;				/* the selected one again: follow again */
	if (itsSupervisor != NULL) ((CMain *) itsSupervisor)->FrameSelected(sel);
	if (sel < 0) Update(); else Refresh();
}

/******************************************************************************
 CFramesPane - column titles above the list, protocol tree and bytes below

 ******************************************************************************/

CFramesPane::CFramesPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight,
						 short aHEncl, short aVEncl)
	: CPane(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizELASTIC, sizELASTIC)
{
	frameNo = -1;
}

void CFramesPane::SetFrame(long aFrame)
{
	frameNo = aFrame;
	Refresh();
}

#define FP_LINES	30
void CFramesPane::Draw(Rect *area)
{
	Rect r;
	char lines[FP_LINES][NC_DETAILLEN], s[64];
	const NCFrame *f = frameNo >= 0 ? NC_Frame(frameNo) : NULL;
	short y, top, x, i, nl, hexX, rows;
	long off, shown;

	TextMode(srcOr);
	FrameToQDR(&frame, &r);
	RGBForeColor(&kViewBg);
	PaintRect(&r);
	y = (short) (r.top + 12);									/* the list's column titles */
	SectionTitle((short) (r.left + kFcNo), y, "No.");
	SectionTitle((short) (r.left + kFcTime), y, "Time");
	SectionTitle((short) (r.left + kFcSrc), y, "Source");
	SectionTitle((short) (r.left + kFcDst), y, "Destination");
	SectionTitle((short) (r.left + kFcProto), y, "Protocol");
	SectionTitle((short) (r.left + kFcLen), y, "Length");
	SectionTitle((short) (r.left + kFcInfo), y, "Info");

	top = (short) (r.top + kFrameHeader + kFrameListH + 6);		/* below the list */
	RGBForeColor(&kStatusLn);
	MoveTo((short) (r.left + 8), top); LineTo((short) (r.right - 8), top);
	TextFont(kGeneva); TextSize(9); TextFace(normal);
	if (f == NULL) {
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 14), (short) (top + 20));
		if (frameNo >= 0) DrawC("This frame has been overwritten - the last 400 are kept.");
		else {
			s[0] = '\0'; CCatNum(s, NC_FrameTotal()); CCat(s, " frames captured; the last 400 are kept.");
			if (NC_Listening()) DrawC("Capturing. Frames are what Listen hears; nothing is sent.");
			else DrawC(NC_FrameTotal() > 0 ? s : "Press Scan to capture. Frames are what Listen hears; nothing is sent.");
			MoveTo((short) (r.left + 14), (short) (top + 34));
			DrawC("Click a frame for its protocol tree and bytes; click it again to follow the capture live.");
		}
		RGBForeColor(&kBlackC);
		return;
	}

	nl = NC_FrameDetail(f, lines, FP_LINES);					/* the protocol tree, left */
	hexX = (short) (r.right - 336);
	for (i = 0, y = (short) (top + 16); i < nl && y < r.bottom - 4; i++, y += 12) {
		Boolean head = (Boolean) (lines[i][0] == '\001');
		TextFace(head ? bold : normal);
		RGBForeColor(head ? &kInk : &kInkSoft);
		MoveTo((short) (r.left + 14), y);
		DrawTrunc(head ? lines[i] + 1 : lines[i], (short) (hexX - r.left - 28));
	}
	TextFace(normal);
	RGBForeColor(&kStatusLn);									/* the bytes, right */
	MoveTo((short) (hexX - 8), (short) (top + 6)); LineTo((short) (hexX - 8), (short) (r.bottom - 6));
	TextFont(kMonaco); TextSize(9);
	if (gDemo) {												/* raw bytes cannot be made up */
		RGBForeColor(&kInkSoft);
		MoveTo(hexX, (short) (top + 16)); DrawC("Bytes hidden in demo mode.");
		RGBForeColor(&kBlackC);
		return;
	}
	rows = (short) ((r.bottom - 4 - (top + 16)) / 11 + 1);		/* what fits; the last says what does not */
	if ((f->caplen + 15) / 16 > rows) shown = (long) (rows - 1) * 16; else shown = f->caplen;
	for (off = 0, y = (short) (top + 16); off < shown; off += 16, y += 11) {
		static const char hx[] = "0123456789abcdef";
		short o = 0;
		s[o++] = hx[(off >> 12) & 15]; s[o++] = hx[(off >> 8) & 15]; s[o++] = hx[(off >> 4) & 15]; s[o++] = hx[off & 15];
		s[o++] = ' ';
		for (x = 0; x < 16 && off + x < f->caplen; x++) {
			unsigned char b = f->data[off + x];
			if (x == 8) s[o++] = ' ';
			s[o++] = ' '; s[o++] = hx[b >> 4]; s[o++] = hx[b & 15];
		}
		s[o] = '\0';
		RGBForeColor(&kInk);
		MoveTo(hexX, y); DrawC(s);
	}
	if (shown < f->caplen) {
		s[0] = '\0'; CCat(s, "      + "); CCatNum(s, f->caplen - shown); CCat(s, " bytes not shown");
		RGBForeColor(&kInkSoft);
		MoveTo(hexX, y); DrawC(s);
	}
	RGBForeColor(&kBlackC);
}

/******************************************************************************
 CToolsPane

 ******************************************************************************/

CToolsPane::CToolsPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight,
					   short aHEncl, short aVEncl)
	: CPane(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizELASTIC, sizELASTIC)
{
	mode = 0;
}

void CToolsPane::Draw(Rect *area)
{
	Rect r, row;
	char s[96], ip[20];
	short i, n, y, st;
	const char *msg;

	TextMode(srcOr);
	FrameToQDR(&frame, &r);
	RGBForeColor(&kViewBg);
	PaintRect(&r);
	SetRect(&row, (short) (r.left + 12), (short) (r.top + 10), (short) (r.left + 274), (short) (r.top + 36));
	RGBForeColor(&kBox);											/* the host field's frame		*/
	PaintRoundRect(&row, 8, 8);
	RGBForeColor(&kStatusLn);
	FrameRoundRect(&row, 8, 8);
	r.top += 44;													/* the results below the field	*/

	TextFont(kGeneva); TextSize(9);
	st = NC_ToolState();
	s[0] = '\0';
	if (mode == 0) CCat(s, "Type a host name or address, then Ping, DNS or Trace.  Return pings.");
	else {
		CCat(s, mode == 1 ? "Ping " : mode == 2 ? "DNS lookup of " : "Traceroute to ");
		CCat(s, NC_ToolHost());
		if (NC_ToolTarget() && mode != 2) {
			NC_IPToStr(NC_ToolTarget(), ip);
			if (!StartsWith(NC_ToolHost(), ip)) { CCat(s, " ("); CCat(s, ip); CCat(s, ")"); }
		}
		CCat(s, st == NC_TOOL_RESOLVING ? "  - resolving the name" : st == NC_TOOL_RUNNING ? "  - running" :
				st == NC_TOOL_DONE ? "  - done" : st == NC_TOOL_FAILED ? "  - failed" : "");
		if (mode == 1) CCat(s, "   (TCP connect to port 80: an answer or a refusal both count)");
	}
	RGBForeColor(&kInkSoft);
	MoveTo((short) (r.left + 14), (short) (r.top + 16));
	DrawC(s);
	msg = NC_ToolMessage();
	if (msg[0]) {
		RGBForeColor(&kInk);
		TextFace(bold);
		MoveTo((short) (r.left + 14), (short) (r.top + 34));
		DrawTrunc(msg, (short) (r.right - r.left - 28));
		TextFace(normal);
	}
	if (mode != 0) {
		y = (short) (r.top + 58);
		SectionTitle((short) (r.left + 14), y, mode == 3 ? "Hop" : "#");
		SectionTitle((short) (r.left + 50), y, "Address");
		SectionTitle((short) (r.left + 170), y, mode == 1 ? "" : "Name");
		SectionTitle((short) (r.left + 430), y, mode == 2 ? "" : "Round trip");
		RGBForeColor(&kStatusLn);
		MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));
		n = NC_ToolLineCount();
		y = (short) (y + 20);
		for (i = 0; i < n && y < r.bottom - 6; i++, y += 16) {
			const NCToolLine *l = NC_ToolLine(i);
			static const short kToolCols[] = { 50, 170, 430 };
			if (l == NULL) break;
			SetRect(&row, (short) (r.left + 8), (short) (y - 12), (short) (r.right - 8), (short) (y + 4));
			GridRow(&row, r.left, kToolCols, (short) (mode == 2 ? 2 : 3));
			TextFont(kGeneva); RGBForeColor(&kInk);
			s[0] = '\0'; CCatNum(s, l->seq);
			MoveTo((short) (r.left + 14), y); DrawC(s);
			TextFont(kMonaco);
			s[0] = '\0'; if (l->ip) NC_IPToStr(l->ip, s); else CCat(s, "*");
			MoveTo((short) (r.left + 50), y); DrawC(s);
			TextFont(kGeneva);
			MoveTo((short) (r.left + 170), y); DrawTrunc(l->name, 250);
			if (mode == 2) continue;							/* DNS: addresses and names only */
			DrawRtt((short) (r.left + 430), (short) (y + 1), (mode == 1 && !l->alive) ? -1 : l->rttUs);
			s[0] = '\0';
			if (l->rttUs >= 0 && (mode == 3 || l->alive)) { NC_RttToStr(l->rttUs, s); CCat(s, " ms"); }
			else CCat(s, "no answer");
			RGBForeColor(&kInkSoft);
			MoveTo((short) (r.left + 454), y); DrawC(s);
		}
	}
	RGBForeColor(&kBlackC);
}

/******************************************************************************
 CLightButton

 ******************************************************************************/

CLightButton::CLightButton(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHEncl, short aVEncl,
						   const char *aLabel, long aCommand)
	: CPane(anEnclosure, aSupervisor, aWidth, 22, aHEncl, aVEncl, sizFIXEDLEFT, sizFIXEDTOP)
{
	CToPStr(aLabel, label);
	command = aCommand;
	running = FALSE;
	SetWantsClicks(TRUE);
}

void CLightButton::SetRunning(Boolean aRunning)
{
	if (aRunning == running) return;
	running = aRunning;
	if (ReallyVisible()) {								/* hidden: Draw shows it on the next Show */
		Prepare();
		DrawButton(FALSE);
	}
}

void CLightButton::Draw(Rect *area)
{
	DrawButton(FALSE);
}

void CLightButton::DrawButton(Boolean pressed)
{
	Rect r;
	short w, d;
	pressed = (Boolean) (pressed || running);
	TextMode(srcOr);
	FrameToQDR(&frame, &r);
	DrawBevel(&r, pressed, &kViewBg);
	TextFont(kGeneva); TextSize(9); TextFace(bold);
	RGBForeColor(&kInk);
	d = (short) (pressed ? 1 : 0);
	w = StringWidth(label);
	MoveTo((short) ((r.left + r.right - w) / 2 + d), (short) (r.bottom - 7 + d));
	DrawString(label);
	TextFace(normal);
	RGBForeColor(&kBlackC);
}

void CLightButton::DoClick(Point hitPt, short modifierKeys, long when)
{
	Rect r;
	Point pt;
	Boolean in = TRUE, was;
	Prepare();
	FrameToQDR(&frame, &r);
	DrawButton(TRUE);
	while (StillDown()) {
		GetMouse(&pt);
		was = in;
		in = PtInRect(pt, &r);
		if (in != was) DrawButton(in);
	}
	DrawButton(FALSE);
	if (in && itsSupervisor != NULL) itsSupervisor->DoCommand(command);
}

/******************************************************************************
 CHostField

 ******************************************************************************/

CHostField::CHostField(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight,
					   short aHEncl, short aVEncl)
	: CEditText(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizFIXEDLEFT, sizFIXEDTOP, -1, FALSE)
{
	SetFontNumber(kGeneva);
	SetFontSize(12);
	CalcTERects();						/* TE's viewRect still has the port font's 12 px line: clips the selection */
	Specify(kEditable, kSelectable, kNotStylable);
}

void CHostField::DoKeyDown(char theChar, Byte keyCode, EventRecord *macEvent)
{
	if (theChar == 0x0D || theChar == 0x03) {				/* Return or Enter: ping */
		if (itsSupervisor != NULL) itsSupervisor->DoCommand(cmdToolPing);
		return;
	}
	CEditText::DoKeyDown(theChar, keyCode, macEvent);
}

void CHostField::GetHost(char *out, short max)
{
	Handle h = GetTextHandle();
	long n = (h != NULL) ? GetHandleSize(h) : 0, i, o = 0;
	for (i = 0; i < n && o < max - 1; i++) {
		char c = (*h)[i];
		if (c != ' ' && c != '\t' && c != 0x0D) out[o++] = c;
	}
	out[o] = '\0';
}

/******************************************************************************
 About - MacNetScan 1's radar: a fading beam sweeps the logo's screen

 ******************************************************************************/

#define kAboutDLOG		300
#define kAboutPICT		300
#define kAboutLogoItem	3
#define NBEAMS			24
#define ABOUT_TRAIL		6
#define BEAM_TICKS		3

static const short kCos[NBEAMS] = {
	 1024,  989,  887,  724,  512,  265,    0, -265, -512, -724, -887, -989,
	-1024, -989, -887, -724, -512, -265,    0,  265,  512,  724,  887,  989 };
static const short kSin[NBEAMS] = {
	    0,  265,  512,  724,  887,  989, 1024,  989,  887,  724,  512,  265,
	    0, -265, -512, -724, -887, -989,-1024, -989, -887, -724, -512, -265 };

static Rect		gAboutLogo;
static short	gAboutBeam;
static long		gAboutNext;

static void DrawAboutFrame(const Rect *logo, short beam)
{
	PicHandle pic;
	short w = (short) (logo->right - logo->left), h = (short) (logo->bottom - logo->top);
	short cx = (short) (logo->left + (long) w * 127 / 256);		/* the CRT's centre and radius in the picture */
	short cy = (short) (logo->top + (long) h * 109 / 256);
	short rad = (short) ((long) w * 19 / 256);
	short s, idx;
	RGBColor c;
	if (rad < 4) rad = 4;
	pic = GetPicture(kAboutPICT);
	if (pic != NULL) DrawPicture(pic, logo);					/* the base again: no trails */
	PenSize(1, 1);
	c.red = 0x1000; c.blue = 0x2800;
	for (s = ABOUT_TRAIL - 1; s >= 0; s--) {					/* dim tail first, bright head */
		idx = (short) ((beam - s + NBEAMS) % NBEAMS);
		c.green = (unsigned short) (0x3000 + (long) 0xC000 * (ABOUT_TRAIL - 1 - s) / (ABOUT_TRAIL - 1));
		RGBForeColor(&c);
		MoveTo(cx, cy);
		LineTo((short) (cx + (((long) kCos[idx] * rad) >> 10)), (short) (cy + (((long) kSin[idx] * rad) >> 10)));
	}
	PenNormal();
	ForeColor(blackColor);
}

static pascal Boolean AboutFilter(DialogPtr d, EventRecord *ev, short *itemHit)
{
	if (ev->what == nullEvent && TickCount() >= gAboutNext) {
		GrafPtr save;
		GetPort(&save);
		SetPort(d);
		DrawAboutFrame(&gAboutLogo, gAboutBeam);
		SetPort(save);
		gAboutBeam = (short) ((gAboutBeam + 1) % NBEAMS);
		gAboutNext = TickCount() + BEAM_TICKS;
	}
	if (ev->what == keyDown && ((ev->message & charCodeMask) == 0x0D || (ev->message & charCodeMask) == 0x03)) {
		*itemHit = 1;											/* Return or Enter: OK */
		return TRUE;
	}
	return FALSE;
}

void ShowAbout(void)
{
	DialogPtr d;
	short hit, t;
	Handle h;
	d = GetNewDialog(kAboutDLOG, NULL, (WindowPtr) -1L);
	if (d == NULL) { SysBeep(1); return; }
	GetDItem(d, kAboutLogoItem, &t, &h, &gAboutLogo);
	gAboutBeam = 0;
	gAboutNext = 0;
	ShowWindow(d);
	do { ModalDialog((ModalFilterProcPtr) AboutFilter, &hit); } while (hit != 1);
	DisposeDialog(d);
}

/******************************************************************************
 Scan Options and the preferences file

 ******************************************************************************/

#define kOptionsDLOG	301
#define kPrefsName		"\pMacNetScan Prefs"

static void SetField(DialogPtr d, short item, const char *c)
{
	short t;
	Handle h;
	Rect b;
	Str255 p;
	GetDItem(d, item, &t, &h, &b);
	CToPStr(c, p);
	SetIText(h, p);
}

static void GetField(DialogPtr d, short item, char *out, short max)
{
	short t, i;
	Handle h;
	Rect b;
	Str255 p;
	GetDItem(d, item, &t, &h, &b);
	GetIText(h, p);
	for (i = 0; i < p[0] && i < max - 1; i++) out[i] = (char) p[i + 1];
	out[i] = '\0';
}

static long ToNum(const char *s)
{
	long v = 0;
	Boolean any = FALSE;
	for (; *s; s++) if (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); any = TRUE; } else if (any) break;
	return any ? v : -1;
}

static Boolean PrefsSpec(FSSpec *spec)
{
	short vRef;
	long dirID;
	OSErr err;
	if (FindFolder(kOnSystemDisk, kPreferencesFolderType, kCreateFolder, &vRef, &dirID) != noErr) return FALSE;
	err = FSMakeFSSpec(vRef, dirID, kPrefsName, spec);
	return (Boolean) (err == noErr || err == fnfErr);
}

	// "first last timeout slots ports" in one line, CR at the end
static void SavePrefs(void)
{
	FSSpec spec;
	short ref, first, last;
	char s[200], ports[128];
	long n;
	OSErr err;
	if (!PrefsSpec(&spec)) return;
	NC_GetRange(&first, &last);
	s[0] = '\0';
	CCatNum(s, first); CCat(s, " "); CCatNum(s, last); CCat(s, " "); CCatNum(s, NC_TimeoutMs()); CCat(s, " ");
	CCatNum(s, NC_Concurrency()); CCat(s, " ");
	NC_PortsToStr(ports); CCat(s, ports); CCat(s, "\r");
	err = FSpCreate(&spec, 'IPSc', 'pref', smSystemScript);
	if (err != noErr && err != dupFNErr) return;
	if (FSpOpenDF(&spec, fsRdWrPerm, &ref) != noErr) return;
	n = CLen(s);
	SetEOF(ref, 0);
	FSWrite(ref, &n, s);
	FSClose(ref);
}

void LoadPrefs(void)
{
	FSSpec spec;
	short ref, i, k;
	char s[200], *f[5];
	long n = sizeof(s) - 1;
	if (!PrefsSpec(&spec) || FSpOpenDF(&spec, fsRdPerm, &ref) != noErr) return;
	FSRead(ref, &n, s);
	FSClose(ref);
	s[n] = '\0';
	for (i = 0, k = 0; s[i] && k < 5; ) {						/* split at blanks into five fields */
		while (s[i] == ' ') s[i++] = '\0';
		if (!s[i] || s[i] == '\r') break;
		f[k++] = &s[i];
		while (s[i] && s[i] != ' ' && s[i] != '\r') i++;
		if (s[i] == '\r') s[i] = '\0';
	}
	if (k < 5) return;
	if (ToNum(f[0]) >= 1 && ToNum(f[1]) <= 254 && ToNum(f[0]) <= ToNum(f[1]))
		NC_SetRange((short) ToNum(f[0]), (short) ToNum(f[1]));
	if (ToNum(f[2]) >= 100) NC_SetTimeoutMs(ToNum(f[2]));
	if (ToNum(f[3]) >= 1) NC_SetConcurrency((short) ToNum(f[3]));
	NC_ParsePorts(f[4]);
}

Boolean RunOptions(void)
{
	DialogPtr d;
	short hit, first, last;
	char s[128];
	long a, b, t, c;
	d = GetNewDialog(kOptionsDLOG, NULL, (WindowPtr) -1L);
	if (d == NULL) { SysBeep(1); return FALSE; }
	NC_GetRange(&first, &last);
	s[0] = '\0'; CCatNum(s, first); SetField(d, 4, s);
	s[0] = '\0'; CCatNum(s, last); SetField(d, 6, s);
	s[0] = '\0'; CCatNum(s, NC_TimeoutMs()); SetField(d, 8, s);
	s[0] = '\0'; CCatNum(s, NC_Concurrency()); SetField(d, 10, s);
	NC_PortsToStr(s); SetField(d, 12, s);
	SelIText(d, 4, 0, 32767);
	ShowWindow(d);
	for (;;) {
		ModalDialog(NULL, &hit);
		if (hit == 2) { DisposeDialog(d); return FALSE; }
		if (hit != 1) continue;
		GetField(d, 4, s, sizeof(s)); a = ToNum(s);
		GetField(d, 6, s, sizeof(s)); b = ToNum(s);
		GetField(d, 8, s, sizeof(s)); t = ToNum(s);
		GetField(d, 10, s, sizeof(s)); c = ToNum(s);
		if (a < 1 || b > 254 || a > b || t < 100 || t > 10000 || c < 1 || c > 24) {
			SysBeep(1);											/* out of range: stay in the dialog */
			continue;
		}
		NC_SetRange((short) a, (short) b);
		NC_SetTimeoutMs(t);
		NC_SetConcurrency((short) c);
		GetField(d, 12, s, sizeof(s));
		NC_ParsePorts(s);
		DisposeDialog(d);
		SavePrefs();
		return TRUE;
	}
}
