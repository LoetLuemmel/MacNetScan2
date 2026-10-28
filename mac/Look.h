/* Look.h - MacNetScan 2's colours, layout constants and drawing helpers, shared by CMain.cp and CViews.cp (each
   gets its own static copy; a helper one file does not use costs nothing but a warning). Needs netcore.h. */

#pragma once

#define kChicago		0
#define kGeneva			3
#define kMonaco			4
#define kWinWidth		720
#define kWinHeight		460
#define kStripHeight	48
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

	// Colours: a dark instrument strip over a light work area.
static const RGBColor kStrip     = { 0x2600, 0x2B00, 0x3400 };
static const RGBColor kStripLine = { 0x4A00, 0x5200, 0x6000 };
static const RGBColor kStripText = { 0xD000, 0xD600, 0xE000 };
static const RGBColor kBtnDown   = { 0x1600, 0x1A00, 0x2000 };
static const RGBColor kDimIcon   = { 0x5800, 0x5E00, 0x6800 };
static const RGBColor kGo        = { 0x2000, 0xD000, 0x5000 };
static const RGBColor kHalt      = { 0xF000, 0x3800, 0x3000 };
static const RGBColor kIconLight = { 0xC800, 0xD000, 0xDC00 };
static const RGBColor kAccent    = { 0x1E00, 0x7800, 0xE800 };
static const RGBColor kTabOff    = { 0x3400, 0x3A00, 0x4600 };
static const RGBColor kViewBg    = { 0xF600, 0xF700, 0xF900 };
static const RGBColor kRowAlt    = { 0xEA00, 0xEE00, 0xF400 };
static const RGBColor kInk       = { 0x1C00, 0x2000, 0x2800 };
static const RGBColor kInkSoft   = { 0x6000, 0x6600, 0x7000 };
static const RGBColor kStatusBg  = { 0xE200, 0xE400, 0xE800 };
static const RGBColor kStatusLn  = { 0xB000, 0xB400, 0xBC00 };
static const RGBColor kBarTrack  = { 0xC400, 0xC800, 0xD000 };
static const RGBColor kBarFill   = { 0x1E00, 0x9000, 0xF000 };
static const RGBColor kLedAct    = { 0xFFFF, 0xB000, 0x2000 };
static const RGBColor kAlive     = { 0x2000, 0xD000, 0x5000 };
static const RGBColor kSelRow    = { 0xC800, 0xDC00, 0xFFFF };
static const RGBColor kHeaderBg  = { 0xE600, 0xE900, 0xEE00 };
static const RGBColor kDetailBg  = { 0xEC00, 0xEE00, 0xF200 };
static const RGBColor kRttGood   = { 0x2000, 0xC000, 0x5000 };
static const RGBColor kRttFair   = { 0xE000, 0xC000, 0x1000 };
static const RGBColor kRttSlow   = { 0xF000, 0x6000, 0x2000 };
static const RGBColor kWhiteC    = { 0xFFFF, 0xFFFF, 0xFFFF };
static const RGBColor kBlackC    = { 0x0000, 0x0000, 0x0000 };

static const char *kViewName[kViewCount] = { "IP Network", "AppleTalk", "Listen", "Tools", "Map", "Frames" };

	// The services: a short column title and an LED colour per known port.
typedef struct { unsigned short port; const char *shortName; RGBColor colour; } SvcLook;

static const SvcLook kSvcLook[] = {
	{ 9000, "AB",  { 0xFFFF, 0xB000, 0x2000 } },	/* AppleBridge			*/
	{   80, "WEB", { 0x2000, 0xD000, 0x5000 } },
	{  443, "TLS", { 0x2000, 0xB000, 0x9000 } },
	{  445, "SMB", { 0x3000, 0x8000, 0xFFFF } },
	{  139, "NB",  { 0x6000, 0x9800, 0xFFFF } },	/* NetBIOS				*/
	{  548, "AFP", { 0xB000, 0x5000, 0xF000 } },	/* AppleShare			*/
	{   22, "SSH", { 0x2000, 0xC800, 0xD800 } },
	{  631, "IPP", { 0xFFFF, 0x8000, 0x1000 } },	/* printers				*/
	{   21, "FTP", { 0xE800, 0xD000, 0x1000 } },
	{   23, "TEL", { 0xF000, 0x3800, 0x3000 } }		/* Telnet				*/
};
#define kSvcLookCount	((short) (sizeof(kSvcLook) / sizeof(kSvcLook[0])))
static const RGBColor kSvcOther = { 0xA000, 0xA000, 0xA800 };

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
	CToPStr(c, p);
	DrawString(p);
}

static short WidthC(const char *c)
{
	Str255 p;
	CToPStr(c, p);
	return StringWidth(p);
}

	// A round LED: dark rim, the colour when lit (a quarter of it when dark), a glint.
static void DrawLed(Rect *r, const RGBColor *c, Boolean lit)
{
	RGBColor dim, glint;
	Rect in = *r, g;

	RGBForeColor(&kBlackC);
	PaintOval(r);
	InsetRect(&in, 1, 1);
	if (lit) RGBForeColor(c);
	else {
		dim.red = (unsigned short) (0x3400 + c->red / 10);	/* dark: grey with a hint of the colour */
		dim.green = (unsigned short) (0x3600 + c->green / 10);
		dim.blue = (unsigned short) (0x3C00 + c->blue / 10);
		RGBForeColor(&dim);
	}
	PaintOval(&in);
	g.left = (short) (in.left + (in.right - in.left) / 5);
	g.top = (short) (in.top + (in.bottom - in.top) / 6);
	g.right = (short) (g.left + (in.right - in.left) * 2 / 5);
	g.bottom = (short) (g.top + (in.bottom - in.top) / 3);
	if (lit) { glint.red = 0xFFFF; glint.green = 0xFFFF; glint.blue = 0xFFFF; }
	else { glint.red = (unsigned short) (dim.red + 0x0C00); glint.green = (unsigned short) (dim.green + 0x0C00);
		   glint.blue = (unsigned short) (dim.blue + 0x0C00); }
	RGBForeColor(&glint);
	PaintOval(&g);
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

