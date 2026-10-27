/* OTProbe - MacNetScan 2 test bench for netcore (phase 1). Phase 0 (phase0_main.c) proved that Open Transport links
   and runs under Symantec C++ 7; this drives the engine the way the TCL app will: a WaitNextEvent loop that calls the
   Idle functions. It sweeps the own /24, then looks up NBP entities, then TCP-pings 192.168.3.101:548, and shows the
   results live. A click stops and quits. netcore.c and otstubs.c are included, so the project needs no further files.
   Project: MacTraps, CPlusLib, OpenTransport.o, OpenTransportApp.o, OpenTptInet.o, OpenTptATalk.o; Far CODE. */

#define OTSTUBS_NO_ANSI
#include "netcore.c"
/* otstubs.c comes with netcore.c */

static WindowPtr gWin;

static void ShowLine(short y, const char *c)
{
	Str255 p;
	short n = 0;
	while (c[n] && n < 255) { p[n + 1] = (unsigned char) c[n]; n++; }
	p[0] = (unsigned char) n;
	MoveTo(8, y);
	DrawString(p);
}

static void Num(char *s, long n)
{
	char t[12];
	short i = 0, j = 0;
	while (*s) s++;
	if (n < 0) { *s++ = '-'; n = -n; }
	do { t[i++] = (char) ('0' + n % 10); n /= 10; } while (n);
	while (i) s[j++] = t[--i];
	s[j] = 0;
}

static void Draw(short stage)
{
	static const char *kPhase[] = { "idle", "probing", "naming", "done" };
	char s[200], ip[20];
	long done, total;
	short i, p, y, n;
	Rect r;

	SetPort(gWin);
	r = gWin->portRect;
	EraseRect(&r);
	TextFont(4); TextSize(9);
	NC_SweepProgress(&done, &total);
	s[0] = 0; StrCat(s, "sweep "); StrCat(s, kPhase[NC_SweepPhase()]); StrCat(s, "  ");
	Num(s, done); StrCat(s, "/"); Num(s, total); StrCat(s, "  hosts "); Num(s, NC_HostCount());
	StrCat(s, "  answers "); Num(s, NC_ActivityCount());
	ShowLine(14, s);
	y = 30;
	n = NC_HostCount();
	for (i = 0; i < n && y < 230; i++, y += 11) {
		const NCHost *h = NC_Host(i);
		NC_IPToStr(h->ip, ip);
		s[0] = 0; StrCat(s, ip); StrCat(s, "  ");
		{ char rt[12]; NC_RttToStr(h->rttUs, rt); StrCat(s, rt); StrCat(s, h->rttUs >= 0 ? "ms  " : "  "); }
		StrCat(s, h->name[0] ? h->name : "..."); StrCat(s, "  ");
		for (p = 0; p < NC_PortCount(); p++)
			if (h->openMask & (1UL << p)) { char pl[12]; NC_PortLabel(p, pl); StrCat(s, pl); StrCat(s, " "); }
		ShowLine(y, s);
	}
	if (stage >= 1) {
		short d, t;
		NC_NbpProgress(&d, &t);
		s[0] = 0; StrCat(s, "NBP zones "); Num(s, d); StrCat(s, "/"); Num(s, t); StrCat(s, "  entities "); Num(s, NC_EntityCount());
		ShowLine(244, s);
		for (i = 0; i < NC_EntityCount() && i < 3; i++) {
			const NCEntity *e = NC_Entity(i);
			s[0] = 0; StrCat(s, "  "); StrCat(s, e->object); StrCat(s, ":"); StrCat(s, e->type); StrCat(s, "@"); StrCat(s, e->zone);
			StrCat(s, "  "); StrCat(s, e->address);
			ShowLine((short) (256 + 11 * i), s);
		}
	}
	if (stage >= 2) {
		s[0] = 0; StrCat(s, "ping 192.168.3.101:548 ");
		for (i = 0; i < NC_ToolLineCount(); i++) {
			const NCToolLine *l = NC_ToolLine(i);
			if (l->alive) { char rt[12]; NC_RttToStr(l->rttUs, rt); StrCat(s, rt); StrCat(s, "ms "); } else StrCat(s, "- ");
		}
		if (NC_ToolIdle() == NC_TOOL_DONE) StrCat(s, " done - click to quit");
		ShowLine(300, s);
	}
}

void main(void)
{
	Rect r;
	EventRecord ev;
	long lastDraw = 0, lastChange = -1;
	short stage = 0;

	InitGraf((Ptr) &qd.thePort);
	InitFonts(); InitWindows(); InitMenus(); FlushEvents(everyEvent, 0); TEInit(); InitDialogs(0L); InitCursor();
	SetRect(&r, 40, 50, 600, 370);
	gWin = NewWindow(NULL, &r, "\pOTProbe - netcore", true, documentProc, (WindowPtr) -1L, false, 0);
	if (NC_Init() != noErr) {
		SetPort(gWin); ShowLine(14, "Open Transport failed - click to quit");
		while (!Button()) ;
		return;
	}
	NC_SweepStart();
	for (;;) {
		/* the update event must be answered with BeginUpdate/EndUpdate: left alone it is posted again on every call, so
		   WaitNextEvent returns at once, never sleeps, and the AppleBridge daemon gets no time at all (measured here) */
		if (WaitNextEvent(everyEvent, &ev, stage == 2 ? 6 : 1, NULL)) {
			if (ev.what == mouseDown) break;
			if (ev.what == updateEvt) {
				BeginUpdate((WindowPtr) ev.message);
				Draw(stage);
				EndUpdate((WindowPtr) ev.message);
				lastDraw = TickCount();
			}
		}
		if (stage == 0) {
			if (NC_SweepIdle() == NC_SWEEP_DONE) { stage = 1; NC_NbpStart(); }
		} else if (stage == 1) {
			if (!NC_NbpIdle()) { stage = 2; NC_PingStart("192.168.3.101", 548, 3); }
		} else
			NC_ToolIdle();
		if (TickCount() - lastDraw > 10 && (TickCount() - lastDraw > 30 || NC_ChangeCount() != lastChange)) {
			Draw(stage); lastDraw = TickCount(); lastChange = NC_ChangeCount();
		}
	}
	NC_SweepStop();
	NC_Shutdown();
}
