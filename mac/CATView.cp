/******************************************************************************
 CATView.cp

	MacNetScan 2's AppleTalk view: this Mac's node, the NBP entities with their
	echo, a box for the one clicked (an AFP server's status, its volumes), the
	mounted volumes - scrolled. Its own file and segment: CViews.cp had come
	within 3 KB of the 32 KB a 68K segment holds.
	Pit Förster with Claude Code via AppleBridge, 2026-10-28.

 ******************************************************************************/

#include "CMain.h"
#include "CViews.h"
#include "netcore.h"
#include "Look.h"

#include <CScrollPane.h>

static const RGBColor kTypeAFP    = { 0x9999, 0x3333, 0x6666 };			/* the Listen family: plum,	*/
static const RGBColor kTypePrint  = { 0xCCCC, 0x6666, 0x3333 };			/* rust,					*/
static const RGBColor kTypeWS     = { 0x3333, 0x9999, 0x6666 };			/* green,					*/
static const RGBColor kTypeOther  = { 0x6666, 0x9999, 0xCCCC };			/* sky						*/
static const RGBColor kLocked     = { 0x9999, 0x9999, 0x9999 };			/* a full CD is no warning	*/
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

static void CatSize(char *s, long k)							/* "512 MB", "1.9 GB" from kilobytes */
{
	if (k >= 1024L * 1024L) { CCatNum(s, k / (1024L * 1024L)); CCat(s, "."); CCatNum(s, (k % (1024L * 1024L)) * 10 / (1024L * 1024L)); CCat(s, " GB"); }
	else if (k >= 1024L) { CCatNum(s, k / 1024L); CCat(s, " MB"); }
	else { CCatNum(s, k); CCat(s, " KB"); }
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
	: CPanorama(anEnclosure, aSupervisor, aWidth, aHeight, aHEncl, aVEncl, sizELASTIC, sizELASTIC)
{
	info[0] = '\0';
	infoTick = 0;
	sel = -1;
	listTop = 0;
	contentH = 0;
	SetScales(1, kATUnit);
	SetWantsClicks(TRUE);
}

	// A scrolled pane redraws whole: the box stays in the visible corner, so a blit of the old picture would drag it.
void CATPane::Scroll(long hDelta, long vDelta, Boolean redraw)
{
	CPanorama::Scroll(hDelta, vDelta, FALSE);
	if (redraw) Refresh();
}

	// The content's height decides the scroll range; before it shrinks, back up (SetBounds asserts the position).
void CATPane::SetContentHeight(short h)
{
	LongRect b;
	LongPt pos;
	short w, fh;
	long units = (h + kATUnit - 1) / kATUnit;
	if (h == contentH) return;
	contentH = h;
	GetLengths(&w, &fh);
	if (units < position.v) { pos.h = 0; pos.v = units; ScrollTo(&pos, FALSE); Refresh(); }
	b.left = 0; b.top = 0; b.right = w; b.bottom = units;
	SetBounds(&b);
	if (itsScrollPane != NULL) { itsScrollPane->AdjustScrollMax(); itsScrollPane->Calibrate(); }
}

void CATPane::DoClick(Point hitPt, short modifierKeys, long when)
{
	long row = (hitPt.v - listTop + 13) / 18;					/* hitPt: content coordinates */
	if (hitPt.v < listTop - 13 || row < 0 || row >= NC_EntityCount()) row = -1;
	sel = (row == sel) ? -1 : (short) row;						/* the same row again: the box closes */
	Refresh();
}

	// One section of an AFP server's status ("Netatalk2.2.2   AFP 1.1 ...   UAM ...   CopyFile, ..."): sections are
	// apart by three blanks.
static void InfoPart(const char *infoStr, short part, char *out, short max)
{
	short i = 0, k = 0, p = 0;
	out[0] = '\0';
	while (infoStr[i] && p < part) {
		if (infoStr[i] == ' ' && infoStr[i + 1] == ' ' && infoStr[i + 2] == ' ') { p++; i += 3; }
		else i++;
	}
	while (infoStr[i] && k < max - 1 && !(infoStr[i] == ' ' && infoStr[i + 1] == ' ' && infoStr[i + 2] == ' '))
		out[k++] = infoStr[i++];
	out[k] = '\0';
}

#define AT_LINES	24
#define AT_LEN		64

	// Add a labelled text to the box's lines, wrapped at blanks to the box's width.
static void AddWrapped(char (*line)[AT_LEN], short *nl, const char *label, const char *text, short width)
{
	char s[AT_LEN];
	short i = 0, k, lastBlank;
	Boolean first = TRUE;
	while (text[i] && *nl < AT_LINES) {
		s[0] = '\0';
		CCat(s, first ? label : "      ");
		k = CLen(s); lastBlank = -1;
		while (text[i] && k < AT_LEN - 1) {
			s[k] = text[i]; s[k + 1] = '\0';
			if (WidthC(s) > width) { s[k] = '\0'; break; }
			if (text[i] == ' ') lastBlank = k;
			k++; i++;
		}
		if (text[i] && lastBlank > 0) { i -= (short) (k - lastBlank - 1); s[lastBlank] = '\0'; }
		CCat(line[*nl], s); (*nl)++;
		first = FALSE;
		while (text[i] == ' ') i++;
	}
}

void CATPane::DrawBox(Rect *vis)
{
	char line[AT_LINES][AT_LEN], s[AT_LEN], t[128];
	short nl = 0, i, j, y, n = NC_EntityCount();
	const NCEntity *e = NC_Entity(sel), *o;
	Rect k;
	if (e == NULL) return;
	for (i = 0; i < AT_LINES; i++) line[i][0] = '\0';
	CCat(line[nl++], e->object);
	s[0] = '\0'; CCat(s, "Type  "); CCat(s, e->type); CCat(line[nl++], s);
	s[0] = '\0'; CCat(s, "Address  "); CCat(s, e->address); CCat(s, "   zone "); CCat(s, e->zone); CCat(line[nl++], s);
	if (e->rttUs != -2) {
		s[0] = '\0'; CCat(s, "Echo  ");
		if (e->rttUs >= 0) { NC_RttToStr(e->rttUs, t); CCat(s, t); CCat(s, " ms"); } else CCat(s, "no answer");
		CCat(line[nl++], s);
	}
	TextFont(kGeneva); TextSize(9);
	if (e->info[0]) {											/* what the AFP server told */
		CCat(line[nl++], "\001AFP server");
		InfoPart(e->info, 0, t, sizeof(t)); AddWrapped(line, &nl, "Machine  ", t, 270);
		InfoPart(e->info, 1, t, sizeof(t));
		if (t[0] == 'A' && t[1] == 'F' && t[2] == 'P' && t[3] == ' ') AddWrapped(line, &nl, "AFP  ", t + 4, 270);
		else AddWrapped(line, &nl, "", t, 270);
		InfoPart(e->info, 2, t, sizeof(t));
		if (t[0] == 'U') AddWrapped(line, &nl, "Login  ", t + 4, 270);
		InfoPart(e->info, 3, t, sizeof(t)); if (t[0]) AddWrapped(line, &nl, "Flags  ", t, 270);
	}
	for (j = 0, i = 0; j < n && nl < AT_LINES; j++) {			/* the rest on that node */
		o = NC_Entity(j);
		if (j == sel || o == NULL || o->net != e->net || o->node != e->node) continue;
		if (i++ == 0) CCat(line[nl++], "\001Same node");
		s[0] = '\0'; CCat(s, "  "); CCat(s, o->type); CCat(s, "  "); CCat(s, o->address); CCat(line[nl++], s);
	}
	for (j = 0, i = 0; j < NC_VolumeCount() && nl < AT_LINES; j++) {	/* what this Mac has mounted from it */
		const NCVolume *v = NC_Volume(j);
		if (v == NULL || !v->serverAdr || (v->serverAdr >> 16) != e->net || ((v->serverAdr >> 8) & 0xFF) != e->node) continue;
		if (i++ == 0) CCat(line[nl++], "\001Mounted here");
		s[0] = '\0'; CCat(s, "  "); CCat(s, v->name); CCat(line[nl++], s);
	}

	{															/* the visible corner across from the row */
		short hgt = (short) (26 + (nl - 1) * 12 + 8), l = (short) (vis->right - 306), top;
		short rowY = (short) (vis->top - (frame.top) + listTop + sel * 18);
		top = (short) (rowY < (vis->top + vis->bottom) / 2 ? vis->bottom - 10 - hgt : vis->top + 10);
		if (top < vis->top + 4) top = (short) (vis->top + 4);
		SetRect(&k, l, top, (short) (l + 296), (short) (top + hgt));
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

void CATPane::Draw(Rect *area)
{
	Rect r, k, row, vis;
	LongRect all;
	short i, n, y, top;
	const RGBColor *c;

	TextMode(srcOr);
	FrameToQDR(&frame, &vis);									/* what shows */
	all.left = 0; all.top = 0; all.right = frame.right - frame.left; all.bottom = 100;
	FrameToQDR(&all, &r);										/* the content, from its top */
	top = r.top;
	RGBForeColor(&kViewBg);
	PaintRect(&vis);

	if (info[0] == '\0' || TickCount() - infoTick > 1800) {		/* this Mac's node, at most every 30 s */
		NCATInfo ai;
		infoTick = TickCount();
		info[0] = '\0';
		NC_VolumeRead();										/* the mounted volumes, as seldom */
		if (!NC_ATAvailable()) CCat(info, "AppleTalk is not active on this Mac.");
		else if (NC_ATInfo(&ai) == 0) {
			CCat(info, "This Mac  "); CCat(info, ai.address);
			CCat(info, "   zone "); CCat(info, ai.zone[0] ? ai.zone : "*");
			CCat(info, ai.isExtended ? "   extended network " : "   LocalTalk-style network ");
			CCatNum(info, ai.cableLow);
			if (ai.cableHigh != ai.cableLow) { CCat(info, "-"); CCatNum(info, ai.cableHigh); }
			if (ai.cableLow == 0 && ai.cableHigh >= 0xFFFE) CCat(info, " (whole range: no router heard)");
			else CCat(info, ai.router[0] ? "   router " : "   no router known to Open Transport");
			if (ai.router[0]) CCat(info, ai.router);
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
	SectionTitle((short) (r.left + 632), y, "Echo");
	RGBForeColor(&kStatusLn);
	MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));

	n = NC_EntityCount();
	y = (short) (y + 22);
	listTop = (short) (y - top);
	if (sel >= n) sel = -1;
	TextFont(kGeneva); TextSize(9);
	for (i = 0; i < n; i++, y += 18) {
		const NCEntity *e = NC_Entity(i);
		if (e == NULL) break;
		if (y - 13 > vis.bottom || y + 5 < vis.top) continue;	/* not in sight */
		SetRect(&row, (short) (r.left + 8), (short) (y - 13), (short) (r.right - 8), (short) (y + 5));
		if (i == sel) { RGBForeColor(&kSelRow); PaintRect(&row); }
		else if (i & 1) { RGBForeColor(&kRowAlt); PaintRect(&row); }
		if (HasText(e->type, "AFP")) c = &kTypeAFP;
		else if (HasText(e->type, "LaserWriter") || HasText(e->type, "Print")) c = &kTypePrint;
		else if (HasText(e->type, "Workstation") || HasText(e->type, "Macintosh")) c = &kTypeWS;
		else c = &kTypeOther;
		SetRect(&k, (short) (r.left + 12), (short) (y - 10), (short) (r.left + 24), (short) (y + 2));
		DrawLed(&k, c, TRUE);
		RGBForeColor(&kInk);
		MoveTo((short) (r.left + 30), y);  DrawTrunc(e->object, 220);
		if (e->info[0]) {										/* an AFP server: its machine, the rest on a click */
			char m[AT_LEN];
			InfoPart(e->info, 0, m, AT_LEN);
			RGBForeColor(&kInkSoft);
			DrawC("  "); DrawTrunc(m, 120);
			RGBForeColor(&kInk);
		}
		MoveTo((short) (r.left + 260), y); DrawTrunc(e->type, 150);
		MoveTo((short) (r.left + 420), y); DrawTrunc(e->zone, 130);
		TextFont(kMonaco);
		MoveTo((short) (r.left + 560), y); DrawC(e->address);
		TextFont(kGeneva);
		if (e->rttUs != -2) {									/* AEP echo: the IP view's meter */
			char ms[16];
			DrawRtt((short) (r.left + 632), (short) (y + 1), e->rttUs);
			NC_RttToStr(e->rttUs, ms);
			RGBForeColor(&kInkSoft);
			MoveTo((short) (r.left + 656), y); DrawC(ms); if (e->rttUs >= 0) DrawC(" ms");
		}
	}
	if (n == 0) {
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 30), y);
		DrawC("No devices yet - press Scan to look them up with NBP, zone by zone.");
		y += 18;
	} else {
		RGBForeColor(&kInkSoft);
		MoveTo((short) (r.left + 30), (short) (y - 2));
		DrawC("Click a device for what is known about it.");
		y += 14;
	}

	{															/* routers and zones, from RTMP and ZIP */
		short k, nr = NC_ATRouterCount(), nt = NC_ATRouteCount();
		char s[96];
		y += 16;
		SectionTitle((short) (r.left + 30), y, "Network & routers");
		SectionTitle((short) (r.left + 260), y, "Network");
		SectionTitle((short) (r.left + 340), y, "Hops");
		SectionTitle((short) (r.left + 420), y, "Via router");
		SectionTitle((short) (r.left + 560), y, "Zone");
		RGBForeColor(&kStatusLn);
		MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));
		y += 22;
		if (nr == 0 && nt == 0) {
			RGBForeColor(&kInkSoft);
			MoveTo((short) (r.left + 30), y);
			DrawC(NC_Listening() ? "No router heard yet - a router announces its routes (RTMP) every 10 s."
								 : "No router heard - Scan in Listen, Map or Frames listens for RTMP and ZIP.");
			y += 18;
		}
		NC_ATLocalZones();
		for (k = 0; k < nt; k++) {								/* every network a router named */
			const NCATRoute *rt = NC_ATRoute(k);
			const NCATRouter *ro = rt ? NC_ATRouter(rt->router) : NULL;
			if (rt == NULL) break;
			if (y - 13 <= vis.bottom && y + 5 >= vis.top) {
				RGBForeColor(&kInk);
				MoveTo((short) (r.left + 30), y); DrawC(rt->distance == 0 ? "this cable" : "remote network");
				s[0] = '\0'; CCatNum(s, rt->rangeLo);
				if (rt->rangeHi != rt->rangeLo) { CCat(s, "-"); CCatNum(s, rt->rangeHi); }
				MoveTo((short) (r.left + 260), y); DrawC(s);
				s[0] = '\0'; CCatNum(s, rt->distance); MoveTo((short) (r.left + 340), y); DrawC(s);
				RGBForeColor(&kInkSoft);
				s[0] = '\0';
				if (ro) {
					short j;
					CCatNum(s, ro->net); CCat(s, "."); CCatNum(s, ro->node);
					for (j = 0; j < NC_EntityCount(); j++) {
						const NCEntity *e = NC_Entity(j);
						if (e && e->net == ro->net && e->node == ro->node) { CCat(s, "  "); CCat(s, e->object); break; }
					}
				} else CCat(s, "(from ZIP)");
				MoveTo((short) (r.left + 420), y); DrawTrunc(s, 134);
				MoveTo((short) (r.left + 560), y); DrawTrunc(rt->zone[0] ? rt->zone : "-", 140);
			}
			y += 16;
		}
		for (k = 0; k < nr; k++) {								/* when each router last spoke */
			const NCATRouter *ro = NC_ATRouter(k);
			if (ro == NULL) break;
			if (y - 13 <= vis.bottom && y + 5 >= vis.top) {
				s[0] = '\0'; CCat(s, "Router "); CCatNum(s, ro->net); CCat(s, "."); CCatNum(s, ro->node);
				CCat(s, " announces "); CCatNum(s, ro->routes); CCat(s, ro->routes == 1 ? " route" : " routes");
				CCat(s, ", last "); CCatNum(s, (long) ((TickCount() - ro->lastTick) / 60)); CCat(s, " s ago");
				RGBForeColor(&kInkSoft);
				MoveTo((short) (r.left + 30), y); DrawC(s);
			}
			y += 14;
		}
	}

	{															/* the AppleTalk traffic Listen has heard */
		NCATTraffic tr;
		long total = 0, totalB = 0;
		short k, j;
		char s[96], t[40];
		NC_ATTraffic(&tr);
		for (k = 0; k < NC_ATT_COUNT; k++) { total += tr.type[k].packets; totalB += tr.type[k].bytes; }
		y += 16;
		s[0] = '\0'; CCat(s, "Traffic heard");
		if (total > 0) {
			CCat(s, "   "); CCatNum(s, total); CCat(s, " packets in ");
			CCatNum(s, (long) ((tr.lastTick - tr.firstTick) / 60)); CCat(s, " s");
		}
		SectionTitle((short) (r.left + 30), y, s);
		SectionTitle((short) (r.left + 260), y, "Packets");
		SectionTitle((short) (r.left + 340), y, "Bytes");
		SectionTitle((short) (r.left + 420), y, "Size min/avg/max");
		SectionTitle((short) (r.left + 560), y, "Share of bytes");
		RGBForeColor(&kStatusLn);
		MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));
		y += 22;
		if (total == 0) {
			RGBForeColor(&kInkSoft);
			MoveTo((short) (r.left + 30), y);
			DrawC("Nothing counted yet - Scan in Listen, Map or Frames counts what AppleTalk sends.");
			y += 18;
		} else {
			for (k = 0; k < NC_ATT_COUNT; k++) {				/* per protocol */
				const NCATCount *c = &tr.type[k];
				Rect bar;
				short share;
				if (c->packets == 0) continue;
				if (y - 13 <= vis.bottom && y + 5 >= vis.top) {
					RGBForeColor(&kInk);
					MoveTo((short) (r.left + 30), y); DrawC(NC_ATTypeName(k));
					s[0] = '\0'; CCatNum(s, c->packets); MoveTo((short) (r.left + 260), y); DrawC(s);
					s[0] = '\0'; CCatNum(s, c->bytes); MoveTo((short) (r.left + 340), y); DrawC(s);
					RGBForeColor(&kInkSoft);
					s[0] = '\0'; CCatNum(s, c->minLen); CCat(s, " / "); CCatNum(s, c->bytes / c->packets);
					CCat(s, " / "); CCatNum(s, c->maxLen);
					MoveTo((short) (r.left + 420), y); DrawC(s);
					share = (short) (totalB > 0 ? c->bytes * 100 / totalB : 0);
					SetRect(&bar, (short) (r.left + 560), (short) (y - 8), (short) (r.left + 660), (short) (y - 1));
					RGBForeColor(&kBarTrack); PaintRect(&bar);
					bar.right = (short) (bar.left + share);
					RGBForeColor(&kBarFill); PaintRect(&bar);
					s[0] = '\0'; CCatNum(s, share); CCat(s, " %");
					RGBForeColor(&kInkSoft);
					MoveTo((short) (r.left + 666), y); DrawC(s);
				}
				y += 16;
			}
			if (y - 13 <= vis.bottom && y + 5 >= vis.top) {	/* how big the packets are */
				static const char *kSize[NC_ATSIZES] = { "< 64", "64-127", "128-255", "256-511", "512+" };
				RGBForeColor(&kInkSoft);
				MoveTo((short) (r.left + 30), y); DrawC("Packet sizes");
				for (k = 0; k < NC_ATSIZES; k++) {
					s[0] = '\0'; CCat(s, kSize[k]); CCat(s, ":  "); CCatNum(s, tr.sizes[k]);
					MoveTo((short) (r.left + 260 + k * 92), y); DrawC(s);
				}
			}
			y += 26;
			SectionTitle((short) (r.left + 30), y, "Sender");
			SectionTitle((short) (r.left + 260), y, "Packets");
			SectionTitle((short) (r.left + 340), y, "Bytes");
			SectionTitle((short) (r.left + 420), y, "Avg size");
			SectionTitle((short) (r.left + 500), y, "Protocols");
			SectionTitle((short) (r.left + 640), y, "Last heard");
			RGBForeColor(&kStatusLn);
			MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));
			y += 22;
			for (i = 0; i < NC_ATNodeCount(); i++) {			/* per sending node */
				const NCATNode *a = NC_ATNode(i);
				if (a == NULL) break;
				if (y - 13 <= vis.bottom && y + 5 >= vis.top) {
					s[0] = '\0'; CCatNum(s, a->net); CCat(s, "."); CCatNum(s, a->node);
					for (j = 0; j < NC_EntityCount(); j++) {		/* its NBP name, if the lookup found one */
						const NCEntity *e = NC_Entity(j);
						if (e && e->net == a->net && e->node == a->node) { CCat(s, "  "); CCat(s, e->object); break; }
					}
					RGBForeColor(&kInk);
					MoveTo((short) (r.left + 30), y); DrawTrunc(s, 220);
					s[0] = '\0'; CCatNum(s, a->c.packets); MoveTo((short) (r.left + 260), y); DrawC(s);
					s[0] = '\0'; CCatNum(s, a->c.bytes); MoveTo((short) (r.left + 340), y); DrawC(s);
					RGBForeColor(&kInkSoft);
					s[0] = '\0'; CCatNum(s, a->c.bytes / a->c.packets); MoveTo((short) (r.left + 420), y); DrawC(s);
					s[0] = '\0';
					for (k = 0; k < NC_ATT_COUNT; k++)
						if (a->types & (1 << k)) { if (s[0]) CCat(s, " "); CCat(s, NC_ATTypeName(k)); }
					MoveTo((short) (r.left + 500), y); DrawTrunc(s, 134);
					t[0] = '\0'; CCatNum(t, (long) ((TickCount() - a->lastTick) / 60)); CCat(t, " s ago");
					MoveTo((short) (r.left + 640), y); DrawC(t);
				}
				y += 16;
			}
		}
	}

	n = NC_VolumeCount();										/* the mounted volumes, AppleShare first */
	y += 16;
	{
		short pass;
		SectionTitle((short) (r.left + 30), y, "Volume");
		SectionTitle((short) (r.left + 260), y, "Server");
		SectionTitle((short) (r.left + 420), y, "Size");
		SectionTitle((short) (r.left + 500), y, "Used");
		RGBForeColor(&kStatusLn);
		MoveTo((short) (r.left + 8), (short) (y + 5)); LineTo((short) (r.right - 8), (short) (y + 5));
		y += 22;
		for (pass = 0; pass < 2; pass++)
			for (i = 0; i < n; i++) {
				const NCVolume *v = NC_Volume(i);
				char s[48];
				short j, used;
				Rect bar;
				if (v == NULL || (pass == 0) != (v->serverAdr != 0)) continue;
				if (y - 13 > vis.bottom || y + 5 < vis.top) { y += 16; continue; }
				RGBForeColor(&kInk);
				MoveTo((short) (r.left + 30), y); DrawTrunc(v->name, 220);
				s[0] = '\0';
				if (v->serverAdr) {									/* net.node:socket, and the server's NBP name */
					CCatNum(s, (long) (v->serverAdr >> 16)); CCat(s, "."); CCatNum(s, (long) ((v->serverAdr >> 8) & 0xFF));
					CCat(s, ":"); CCatNum(s, (long) (v->serverAdr & 0xFF));
					for (j = 0; j < NC_EntityCount(); j++) {
						const NCEntity *e = NC_Entity(j);
						if (e && e->net == (v->serverAdr >> 16) && e->node == ((v->serverAdr >> 8) & 0xFF) && HasText(e->type, "AFP")) {
							CCat(s, "  "); CCat(s, e->object); break;
						}
					}
				} else CCat(s, "this Mac");
				RGBForeColor(&kInkSoft);
				MoveTo((short) (r.left + 260), y); DrawTrunc(s, 155);
				if (v->serverAdr && v->totalK >= 2096000L) {			/* AFP 2.x hands on at most 2 GB: true size unknown */
					RGBForeColor(&kInk);
					MoveTo((short) (r.left + 420), y); DrawC("> 2 GB");
					RGBForeColor(&kInkSoft);
					MoveTo((short) (r.left + 500), y); DrawC("not reported (AFP 2.x caps sizes at 2 GB)");
					y += 16;
					continue;
				}
				s[0] = '\0'; CatSize(s, v->totalK);
				RGBForeColor(&kInk);
				MoveTo((short) (r.left + 420), y); DrawC(s);
				used = (short) (v->totalK > 0 ? (v->totalK - v->freeK) * 100 / v->totalK : 0);
				SetRect(&bar, (short) (r.left + 500), (short) (y - 8), (short) (r.left + 600), (short) (y - 1));
				RGBForeColor(&kBarTrack); PaintRect(&bar);
				bar.right = (short) (bar.left + used);
				RGBForeColor(v->locked ? &kLocked : used > 90 ? &kRttSlow : &kBarFill); PaintRect(&bar);
				s[0] = '\0'; CCatNum(s, used); CCat(s, " %   "); CatSize(s, v->freeK); CCat(s, " free");
				RGBForeColor(&kInkSoft);
				MoveTo((short) (r.left + 608), y); DrawTrunc(s, (short) (r.right - r.left - 616));
				y += 16;
			}
	}
	if (sel >= 0) DrawBox(&vis);
	RGBForeColor(&kBlackC);
	SetContentHeight((short) (y - top + 8));
}
