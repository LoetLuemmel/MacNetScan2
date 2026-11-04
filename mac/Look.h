/* Look.h - MacNetScan 2's colours, layout constants and drawing helpers, shared by CMain.cp and CViews.cp (each
   gets its own static copy; a helper one file does not use costs nothing but a warning). Needs netcore.h. */

#pragma once

#define kChicago		0
#define kGeneva			3
#define kMonaco			4
#define kWinWidth		720
#define kWinHeight		460
#define kStripHeight	30
#define kStatusHeight	24
#define kReportMax		32000L
#define kListWidth		510				/* the IP view: table 0..510, detail panel 510..720	*/
#define kHeaderHeight	22
#define kRowHeight		18
#define kColLed			8				/* table columns (x)								*/
#define kColAddr		24
#define kColName		112
#define kColRtt			238
#define kColSvc			292				/* one LED per service, kSvcPitch apart			*/
#define kSvcPitch		20

	// Colours: System 7 as it looked in 1995 - a platinum tool bar of bevelled buttons (white light from the top
	// left, a grey shadow bottom right, a black outline), black icons and text, white work areas, grey rules, the
	// default highlight colour for selections and a little colour where it carries meaning (LEDs, RTT, meters).
	// Every colour is a step of the 8-bit screen's 6x6x6 cube ($00 $33 $66 $99 $CC $FF) or of the CLUT's grey ramp
	// ($11 $22 $44 $55 $77 $88 $AA $BB $DD $EE): QuickDraw would otherwise round it to the nearest entry.
static const RGBColor kStrip     = { 0xDDDD, 0xDDDD, 0xDDDD };	/* platinum: tool bar, headers, status bar	*/
static const RGBColor kStripLine = { 0x0000, 0x0000, 0x0000 };
static const RGBColor kStripText = { 0x0000, 0x0000, 0x0000 };
static const RGBColor kBevelHi   = { 0xFFFF, 0xFFFF, 0xFFFF };
static const RGBColor kBevelLo   = { 0x8888, 0x8888, 0x8888 };
static const RGBColor kBtnDown   = { 0xBBBB, 0xBBBB, 0xBBBB };
static const RGBColor kDimIcon   = { 0x8888, 0x8888, 0x8888 };
static const RGBColor kGo        = { 0x0000, 0x9999, 0x3333 };
static const RGBColor kHalt      = { 0xCCCC, 0x0000, 0x0000 };
static const RGBColor kAccent    = { 0x0000, 0x0000, 0x0000 };	/* info boxes and the Map's selection ring	*/
static const RGBColor kViewBg    = { 0xFFFF, 0xFFFF, 0xFFFF };
static const RGBColor kRowAlt    = { 0xFFFF, 0xFFFF, 0xFFFF };	/* no zebra stripes in 1995					*/
static const RGBColor kInk       = { 0x0000, 0x0000, 0x0000 };
static const RGBColor kInkSoft   = { 0x5555, 0x5555, 0x5555 };
static const RGBColor kStatusBg  = { 0xDDDD, 0xDDDD, 0xDDDD };
static const RGBColor kStatusLn  = { 0x8888, 0x8888, 0x8888 };
static const RGBColor kBarTrack  = { 0xEEEE, 0xEEEE, 0xEEEE };
static const RGBColor kBarFill   = { 0x4444, 0x4444, 0x4444 };	/* the Finder's copy bar					*/
static const RGBColor kLedAct    = { 0xFFFF, 0xFFFF, 0x0000 };	/* ACT: shrill yellow when something answers,	*/
static const RGBColor kLedActOff = { 0x9999, 0x9999, 0x0000 };	/* dark yellow (olive) at rest				*/
static const RGBColor kAlive     = { 0x0000, 0xCCCC, 0x3333 };
static const RGBColor kSelRow    = { 0xCCCC, 0xCCCC, 0xFFFF };	/* System 7's default highlight colour		*/
static const RGBColor kHeaderBg  = { 0xDDDD, 0xDDDD, 0xDDDD };
static const RGBColor kDetailBg  = { 0xFFFF, 0xFFFF, 0xFFFF };
static const RGBColor kRttGood   = { 0x0000, 0x9999, 0x3333 };
static const RGBColor kRttFair   = { 0xCCCC, 0x9999, 0x0000 };
static const RGBColor kRttSlow   = { 0xCCCC, 0x3333, 0x0000 };
static const RGBColor kGrid      = { 0x8888, 0x8888, 0x8888 };	/* Excel's dotted cell lines				*/
static const RGBColor kWhiteC    = { 0xFFFF, 0xFFFF, 0xFFFF };
static const RGBColor kBlackC    = { 0x0000, 0x0000, 0x0000 };

static const char *kViewName[kViewCount] = { "IP Network", "AppleTalk", "Listen", "Tools", "Map", "Frames" };

	// The services: a short column title and an LED colour per known port.
typedef struct { unsigned short port; const char *shortName; RGBColor colour; } SvcLook;

static const SvcLook kSvcLook[] = {
	{ 9000, "AB",  { 0xCCCC, 0x9999, 0x3333 } },	/* AppleBridge			*/
	{   80, "WEB", { 0x3333, 0x9999, 0x6666 } },
	{  443, "TLS", { 0x3333, 0x9999, 0x9999 } },
	{  445, "SMB", { 0x3333, 0x6666, 0x9999 } },
	{  139, "NB",  { 0x6666, 0x9999, 0xCCCC } },	/* NetBIOS				*/
	{  548, "AFP", { 0x9999, 0x3333, 0x6666 } },	/* AppleShare			*/
	{   22, "SSH", { 0x6666, 0x6666, 0x9999 } },
	{  631, "IPP", { 0xCCCC, 0x6666, 0x3333 } },	/* printers				*/
	{   21, "FTP", { 0x9999, 0x9999, 0x3333 } },
	{   23, "TEL", { 0xCCCC, 0x3333, 0x3333 } }		/* Telnet				*/
};
#define kSvcLookCount	((short) (sizeof(kSvcLook) / sizeof(kSvcLook[0])))
static const RGBColor kSvcOther = { 0x9999, 0x9999, 0x9999 };

static void SvcFor(short portIndex, const char **shortName, const RGBColor **colour)
{
	unsigned short port = NC_Port(portIndex);
	short i;
	for (i = 0; i < kSvcLookCount; i++)
		if (kSvcLook[i].port == port) { *shortName = kSvcLook[i].shortName; *colour = &kSvcLook[i].colour; return; }
	*shortName = "?";
	*colour = &kSvcOther;
}

static const NCHost *HostByIP(unsigned long ip)
{
	short i, n = NC_HostCount();
	for (i = 0; i < n; i++) if (NC_Host(i)->ip == ip) return NC_Host(i);
	return NULL;
}

	// View > Demo Mode, for screenshots that go public: every text drawn through DrawC, WidthC and DrawTrunc passes
	// DemoText (CViews.cp) - names become made-up ones, MAC addresses and IPv6 interface IDs invented but stable.
	// gDemo lives in CViews.cp. DemoAdd registers a name the engine does not list itself (this Mac's zone).
extern Boolean gDemo;
enum { kDemoHost = 0, kDemoZone, kDemoVol };
void DemoText(const char *in, char *out, short max);
void DemoAdd(const char *real, short kind);

/* ------------------------------------------------------------------ text helpers */

static short CLen(const char *c)
{
	short n = 0;
	while (c[n] != '\0') n++;
	return n;
}

static void CCat(char *dst, const char *src)
{
	short n = CLen(dst), i = 0;
	while (src[i] != '\0') dst[n++] = src[i++];
	dst[n] = '\0';
}

static void CCatNum(char *dst, long v)
{
	char t[12];
	short i = 0, n = CLen(dst);
	if (v < 0) { dst[n++] = '-'; v = -v; }
	do { t[i++] = (char) ('0' + v % 10); v /= 10; } while (v != 0);
	while (i > 0) dst[n++] = t[--i];
	dst[n] = '\0';
}

static void CToPStr(const char *c, Str255 p)
{
	short n = 0;
	while (c[n] != '\0' && n < 255) { p[n + 1] = (unsigned char) c[n]; n++; }
	p[0] = (unsigned char) n;
}

static void DrawC(const char *c)
{
	Str255 p;
	char t[256];
	if (gDemo) { DemoText(c, t, sizeof(t)); c = t; }
	CToPStr(c, p);
	DrawString(p);
}

static short WidthC(const char *c)
{
	Str255 p;
	char t[256];
	if (gDemo) { DemoText(c, t, sizeof(t)); c = t; }
	CToPStr(c, p);
	return StringWidth(p);
}

	// A round LED, drawn flat like a 1995 control: a black rim, the colour when lit, white when dark.
static void DrawLed(Rect *r, const RGBColor *c, Boolean lit)
{
	Rect in = *r;
	InsetRect(&in, 1, 1);
	RGBForeColor(lit ? c : &kWhiteC);
	PaintOval(&in);
	RGBForeColor(lit ? &kBlackC : &kBevelLo);
	FrameOval(r);
	RGBForeColor(&kBlackC);
}

	// Excel's grid: dotted grey lines between rows and cells, switched by the tool bar's grid button (and View >
	// Grid Lines). gShowGrid lives in CMain.cp. A 50% pattern in patOr: the dots in grey, the gaps left as they are.
extern Boolean gShowGrid;

static void DotLine(short x0, short y0, short x1, short y1)
{
	Pattern dots;
	short i;
	for (i = 0; i < 8; i++) dots.pat[i] = (unsigned char) ((i & 1) ? 0x55 : 0xAA);
	RGBForeColor(&kGrid);
	PenPat(&dots);
	PenMode(patOr);
	MoveTo(x0, y0);
	LineTo(x1, y1);
	PenNormal();
	RGBForeColor(&kBlackC);
}

	// One table row's grid: a dotted line along its bottom and one at each column edge (left + xs[i] - 4).
static void GridRow(const Rect *row, short left, const short *xs, short n)
{
	short i;
	if (!gShowGrid) return;
	DotLine(row->left, (short) (row->bottom - 1), (short) (row->right - 1), (short) (row->bottom - 1));
	for (i = 0; i < n; i++)
		DotLine((short) (left + xs[i] - 4), row->top, (short) (left + xs[i] - 4), (short) (row->bottom - 1));
}

	// A bevelled button face (Excel's tool bar): a black outline with its corner pixels in the background colour,
	// white light top left and a grey shadow bottom right when up; pressed, the shadow moves top left.
static void DrawBevel(const Rect *r, Boolean down, const RGBColor *bg)
{
	Rect in = *r;
	short l = r->left, t = r->top, rt = (short) (r->right - 1), b = (short) (r->bottom - 1);

	InsetRect(&in, 1, 1);
	RGBForeColor(down ? &kBtnDown : &kStrip);
	PaintRect(&in);
	RGBForeColor(&kBlackC);
	FrameRect(r);
	RGBForeColor(bg);
	MoveTo(l, t); LineTo(l, t);
	MoveTo(rt, t); LineTo(rt, t);
	MoveTo(l, b); LineTo(l, b);
	MoveTo(rt, b); LineTo(rt, b);
	if (down) {
		RGBForeColor(&kBevelLo);
		MoveTo((short) (l + 1), (short) (b - 1)); LineTo((short) (l + 1), (short) (t + 1)); LineTo((short) (rt - 1), (short) (t + 1));
	} else {
		RGBForeColor(&kBevelHi);
		MoveTo((short) (l + 1), (short) (b - 2)); LineTo((short) (l + 1), (short) (t + 1)); LineTo((short) (rt - 2), (short) (t + 1));
		RGBForeColor(&kBevelLo);
		MoveTo((short) (l + 1), (short) (b - 1)); LineTo((short) (rt - 1), (short) (b - 1)); LineTo((short) (rt - 1), (short) (t + 1));
	}
	RGBForeColor(&kBlackC);
}

	// A sunken well (the status bar's fields): grey shadow top left, white light bottom right.
static void DrawWell(const Rect *r)
{
	RGBForeColor(&kBevelLo);
	MoveTo(r->left, (short) (r->bottom - 1)); LineTo(r->left, r->top); LineTo((short) (r->right - 1), r->top);
	RGBForeColor(&kBevelHi);
	MoveTo((short) (r->left + 1), (short) (r->bottom - 1)); LineTo((short) (r->right - 1), (short) (r->bottom - 1));
	LineTo((short) (r->right - 1), (short) (r->top + 1));
	RGBForeColor(&kBlackC);
}

	// The round trip as a signal-strength meter: four rising bars, more and greener the faster.
static void DrawRtt(short x, short y, long us)
{
	Rect b;
	short i, lit;
	const RGBColor *c;
	if (us < 0) lit = 0;
	else if (us < 2000L) lit = 4;
	else if (us < 20000L) lit = 3;
	else if (us < 150000L) lit = 2;
	else lit = 1;
	c = lit >= 3 ? &kRttGood : lit == 2 ? &kRttFair : &kRttSlow;
	for (i = 0; i < 4; i++) {
		SetRect(&b, (short) (x + i * 5), (short) (y - 3 - i * 2), (short) (x + i * 5 + 4), y);
		RGBForeColor(i < lit ? c : &kBarTrack);
		PaintRect(&b);
	}
}

static void DrawTrunc(const char *c, short maxWidth)			/* DrawString, cut to fit with an ellipsis */
{
	Str255 p;
	char t[256];
	if (gDemo) { DemoText(c, t, sizeof(t)); c = t; }			/* the made-up text is what gets cut */
	CToPStr(c, p);
	if (StringWidth(p) > maxWidth) {
		while (p[0] > 0 && StringWidth(p) + CharWidth((char) 0xC9) > maxWidth) p[0]--;
		p[++p[0]] = (unsigned char) 0xC9;
	}
	DrawString(p);
}

static short CountBits(unsigned long m)
{
	short n = 0;
	while (m != 0) { n += (short) (m & 1); m >>= 1; }
	return n;
}

