/* OTProbe - phase 0 of MacNetScan 2: does Open Transport link and run under Symantec C++ 7 (THINK Project Manager)?
   Initialises OT, shows the own IP address, TCP-pings 192.168.3.101:548 (AFP on the netatalk server) with
   ipscan.c's TcpPing, opens and closes an NBP mapper (AppleTalk library). A click quits.
   Project: MacTraps + OpenTransport.o, OpenTransportApp.o, OpenTptInet.o, OpenTptATalk.o through the .o Converter.
   The four ASLM stubs follow Apple DTS's "OT + Symantec C++ Q&A" (Quinn, 1996): Symantec's linker wants routines that
   only uncalled code in the OT libraries refers to. */

#include "OTCompat.h"
#include <OpenTransport.h>
#include <OpenTptInternet.h>
#include <OpenTptAppleTalk.h>

void SetSelfAsClient(void)  { DebugStr("\pSetSelfAsClient -- This is not good."); }
void LoadClass(void)        { DebugStr("\pLoadClass -- This is not good."); }
void SetCurrentClient(void) { DebugStr("\pSetCurrentClient -- This is not good."); }
void UnloadClass(void)      { DebugStr("\pUnloadClass -- This is not good."); }
/* The same reason holds for the rest: MPW's linker drops library modules no client code reaches, Symantec's keeps
   them, so their references must resolve. The AppleBridge daemon links these very OT libraries under MPW without ASLM,
   C++ runtime or errno and runs - nothing an OT client calls reaches them. */
void __SLM11ExtblDispatch(void)       { DebugStr("\p__SLM11ExtblDispatch -- This is not good."); }
void __SLM11VTableDispatch(void)      { DebugStr("\p__SLM11VTableDispatch -- This is not good."); }
void __SLM11DestructorDispatch(void)  { DebugStr("\p__SLM11DestructorDispatch -- This is not good."); }
void __SLM11ConstructorDispatch(void) { DebugStr("\p__SLM11ConstructorDispatch -- This is not good."); }
int errno;
/* CPlusLib (operator delete for the OT library) registers static destructors with atexit, which ANSI would bring;
   this probe has none to run. The TCL project links ANSI++ instead. */
int atexit(void (*f)(void)) { return f ? 0 : 0; }

static WindowPtr gWin;
static short gLine;
static volatile OTEventCode gPingEv;

static void Say(const char *c)
{
	Str255 p;
	short n = 0;
	while (c[n] && n < 255) { p[n + 1] = (unsigned char) c[n]; n++; }
	p[0] = (unsigned char) n;
	SetPort(gWin);
	MoveTo(12, (short) (20 + 16 * gLine++));
	DrawString(p);
}

static void Num(char *s, long n)
{
	char t[12];
	short i = 0, j = 0;
	if (n < 0) { s[j++] = '-'; n = -n; }
	do { t[i++] = (char) ('0' + n % 10); n /= 10; } while (n);
	while (i) s[j++] = t[--i];
	s[j] = 0;
}

static void Cat(char *d, const char *s) { while (*d) d++; while ((*d++ = *s++) != 0) ; }

static void IPStr(InetHost ip, char *s)
{
	char n[12];
	s[0] = 0;
	Num(n, (ip >> 24) & 255); Cat(s, n); Cat(s, ".");
	Num(n, (ip >> 16) & 255); Cat(s, n); Cat(s, ".");
	Num(n, (ip >> 8) & 255);  Cat(s, n); Cat(s, ".");
	Num(n, ip & 255);         Cat(s, n);
}

static pascal void PingNotifier(void *ctx, OTEventCode code, OTResult r, void *ck)
{
	if (ctx || r || ck) {}
	if (code == T_CONNECT || code == T_DISCONNECT) gPingEv = code;
}

static long TcpPing(InetHost ip, UInt16 port, long timeoutTicks)
{
	EndpointRef ep; OSStatus err;
	InetAddress addr, local; TCall call; TBind bindReq; long start, rtt = -1;
	ep = OTOpenEndpoint(OTCreateConfiguration(kTCPName), 0, NULL, &err);
	if (err != noErr || ep == NULL) return -1;
	OTMemzero(&local, sizeof(local)); OTInitInetAddress(&local, 0, kOTAnyInetAddress);
	bindReq.addr.buf = (UInt8 *) &local; bindReq.addr.len = sizeof(local); bindReq.qlen = 0;
	if (OTBind(ep, &bindReq, NULL) != noErr) { OTCloseProvider(ep); return -1; }
	gPingEv = 0;
	if (OTInstallNotifier(ep, PingNotifier, NULL) != noErr) { OTCloseProvider(ep); return -1; }
	OTSetAsynchronous(ep);
	OTMemzero(&addr, sizeof(addr)); OTInitInetAddress(&addr, port, ip);
	OTMemzero(&call, sizeof(call)); call.addr.buf = (UInt8 *) &addr; call.addr.len = sizeof(addr);
	start = TickCount();
	err = OTConnect(ep, &call, NULL);
	if (err != noErr && err != kOTNoDataErr) { OTRemoveNotifier(ep); OTCloseProvider(ep); return -1; }
	for (;;) {
		if (gPingEv == T_CONNECT)    { rtt = TickCount() - start; OTSndDisconnect(ep, NULL); break; }
		if (gPingEv == T_DISCONNECT) { rtt = TickCount() - start; OTRcvDisconnect(ep, NULL); break; }
		if (TickCount() - start > timeoutTicks) { OTSndDisconnect(ep, NULL); break; }
		SystemTask();
	}
	OTRemoveNotifier(ep); OTCloseProvider(ep);
	return rtt;
}

void main(void)
{
	Rect r;
	char s[80], n[16];
	InetInterfaceInfo info;
	MapperRef mapper;
	OSStatus err;
	long rtt;
	EventRecord ev;

	InitGraf((Ptr) &qd.thePort);
	InitFonts(); InitWindows(); InitMenus(); FlushEvents(everyEvent, 0); TEInit(); InitDialogs(0L); InitCursor();
	SetRect(&r, 60, 60, 460, 200);
	gWin = NewWindow(NULL, &r, "\pOTProbe", true, documentProc, (WindowPtr) -1L, false, 0);
	TextFont(4); TextSize(9);

	err = InitOpenTransport();
	s[0] = 0; Cat(s, "InitOpenTransport: "); Num(n, err); Cat(s, n); Say(s);
	if (err == noErr) {
		if (OTInetGetInterfaceInfo(&info, kDefaultInetInterface) == noErr) {
			s[0] = 0; Cat(s, "own address: "); IPStr(info.fAddress, n); Cat(s, n); Say(s);
		} else Say("own address: OTInetGetInterfaceInfo failed");
		rtt = TcpPing((192UL << 24) | (168UL << 16) | (3UL << 8) | 101UL, 548, 180);
		s[0] = 0; Cat(s, "TCP 192.168.3.101:548 -> ");
		if (rtt < 0) Cat(s, "no answer"); else { Num(n, rtt); Cat(s, n); Cat(s, " ticks"); Cat(s, gPingEv == T_CONNECT ? " (open)" : " (refused)"); }
		Say(s);
		mapper = OTOpenMapper(OTCreateConfiguration(kNBPName), 0, &err);
		s[0] = 0; Cat(s, "NBP mapper: "); Num(n, err); Cat(s, n); Say(s);
		if (err == noErr && mapper) OTCloseProvider(mapper);
		CloseOpenTransport();
	}
	Say("OTProbe done - click to quit.");
	for (;;) {
		if (WaitNextEvent(everyEvent, &ev, 30, NULL) && ev.what == mouseDown) break;
	}
}
