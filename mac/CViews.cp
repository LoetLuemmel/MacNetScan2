/******************************************************************************
 CViews.c

	MacNetScan 2's AppleTalk, Listen and Tools views (phase 4).
	Pit Förster with Claude Code via AppleBridge, 2026-10-27.

	Every view draws straight from the engine's tables (netcore.h): nothing
	is copied, so a redraw is always the current state. The source is plain
	ASCII; characters outside it are MacRoman escapes.

 ******************************************************************************/

#include "CMain.h"
#include "CViews.h"
#include "netcore.h"
#include "Look.h"

#include <Memory.h>
#include <Dialogs.h>
#include <Files.h>
#include <Folders.h>
#include <Resources.h>
#include <ToolUtils.h>
#include <Script.h>
#include <Errors.h>

static const RGBColor kTypeAFP    = { 0xB000, 0x5000, 0xF000 };
static const RGBColor kTypePrint  = { 0xFFFF, 0x8000, 0x1000 };
static const RGBColor kTypeWS     = { 0x2000, 0xD000, 0x5000 };
static const RGBColor kTypeOther  = { 0x7000, 0x9000, 0xC000 };
static const RGBColor kConflict   = { 0xD000, 0x1800, 0x1000 };
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
 CATPane

 ******************************************************************************/

CATPane::CATPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight,
				 short aHEncl, short aVEncl)
	: CPane(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizELASTIC, sizELASTIC)
{
	info[0] = '\0';
	infoTick = 0;
}

void CATPane::Draw(Rect *area)
{
	Rect r, k, row;
	short i, n, y;
	const RGBColor *c;

	TextMode(srcOr);
	FrameToQDR(&frame, &r);
	RGBForeColor(&kViewBg);
	PaintRect(&r);

	if (info[0] == '\0' || TickCount() - infoTick > 1800) {		/* this Mac's node, at most every 30 s */
		NCATInfo ai;
		infoTick = TickCount();
		info[0] = '\0';
		if (!NC_ATAvailable()) CCat(info, "AppleTalk is not active on this Mac.");
		else if (NC_ATInfo(&ai) == 0) {
			CCat(info, "This Mac  "); CCat(info, ai.address);
			CCat(info, "   zone "); CCat(info, ai.zone[0] ? ai.zone : "*");
			if (ai.router[0]) { CCat(info, "   router "); CCat(info, ai.router); }
			CCat(info, ai.isExtended ? "   extended network" : "   LocalTalk-style network");
		}
	}
	TextFont(kChicago); TextSize(12);
	RGBForeColor(&kInk);
	MoveTo((short) (r.left + 14), (short) (r.top + 22));
	DrawC("AppleTalk");
	TextFont(kGeneva); TextSize(9);
	RGBForeColor(&kInkSoft);
	MoveTo((short) (r.left + 14), (short) (r.top + 38));
	DrawC(info);

	y = (short) (r.top + 62);
	SectionTitle((short) (r.left + 30), y, "Name");
	SectionTitle((short) (r.left + 260), y, "Type");
	SectionTitle((short) (r.left + 420), y, "Zone");
	SectionTitle((short) (r.left + 560), y, "Address");
	RGBForeColor(&kStatusLn);
	MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));

	n = NC_EntityCount();
	y = (short) (y + 22);
	TextFont(kGeneva); TextSize(9);
	for (i = 0; i < n && y < r.bottom - 6; i++, y += 18) {
		const NCEntity *e = NC_Entity(i);
		if (e == NULL) break;
		if (i & 1) {
			SetRect(&row, (short) (r.left + 8), (short) (y - 13), (short) (r.right - 8), (short) (y + 5));
			RGBForeColor(&kRowAlt);
			PaintRect(&row);
		}
		if (HasText(e->type, "AFP")) c = &kTypeAFP;
		else if (HasText(e->type, "LaserWriter") || HasText(e->type, "Print")) c = &kTypePrint;
		else if (HasText(e->type, "Workstation") || HasText(e->type, "Macintosh")) c = &kTypeWS;
		else c = &kTypeOther;
		SetRect(&k, (short) (r.left + 12), (short) (y - 10), (short) (r.left + 24), (short) (y + 2));
		DrawLed(&k, c, TRUE);
		RGBForeColor(&kInk);
		MoveTo((short) (r.left + 30), y);  DrawTrunc(e->object, 220);
		MoveTo((short) (r.left + 260), y); DrawTrunc(e->type, 150);
		MoveTo((short) (r.left + 420), y); DrawTrunc(e->zone, 130);
		TextFont(kMonaco);
		MoveTo((short) (r.left + 560), y); DrawC(e->address);
		TextFont(kGeneva);
	}
	if (n == 0) {
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 30), y);
		DrawC("No devices yet - press Scan to look them up with NBP, zone by zone.");
	}
	RGBForeColor(&kBlackC);
}

/******************************************************************************
 CListenPane

 ******************************************************************************/

#define kMeters	9
static const char *kMeterName[kMeters] = { "ARP", "Broadcast", "Multicast", "DHCP", "NetBIOS", "IPv6", "LLDP",
										   "AppleTalk", "AARP" };
static const RGBColor kMeterColour[kMeters] = {
	{ 0xFFFF, 0xB000, 0x2000 }, { 0x3000, 0x8000, 0xFFFF }, { 0x2000, 0xC800, 0xD800 }, { 0x2000, 0xD000, 0x5000 },
	{ 0x6000, 0x9800, 0xFFFF }, { 0x1000, 0xB000, 0xA000 }, { 0xFFFF, 0x7000, 0x5000 },
	{ 0xB000, 0x5000, 0xF000 }, { 0xD000, 0x8000, 0xF000 }
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
		if (j & 1) {
			SetRect(&row, (short) (r.left + 8), (short) (y - 12), (short) (r.right - 8), (short) (y + 4));
			RGBForeColor(&kRowAlt);
			PaintRect(&row);
		}
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
			if (l == NULL) break;
			if (i & 1) {
				SetRect(&row, (short) (r.left + 8), (short) (y - 12), (short) (r.right - 8), (short) (y + 4));
				RGBForeColor(&kRowAlt);
				PaintRect(&row);
			}
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
	short w;
	pressed = (Boolean) (pressed || running);
	TextMode(srcOr);
	FrameToQDR(&frame, &r);
	RGBForeColor(&kViewBg);
	PaintRect(&r);
	RGBForeColor(pressed ? &kAccent : &kBox);
	PaintRoundRect(&r, 10, 10);
	RGBForeColor(pressed ? &kAccent : &kStatusLn);
	FrameRoundRect(&r, 10, 10);
	TextFont(kGeneva); TextSize(9); TextFace(bold);
	RGBForeColor(pressed ? &kWhiteC : &kInk);
	w = StringWidth(label);
	MoveTo((short) ((r.left + r.right - w) / 2), (short) (r.bottom - 7));
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
