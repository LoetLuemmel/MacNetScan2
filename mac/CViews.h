/******************************************************************************
 CViews.h

	MacNetScan 2's AppleTalk, Listen and Tools views (phase 4) - their own
	file and segment, so CMain.cp stays under the 32 KB of a 68K segment.
	Pit Förster with Claude Code via AppleBridge, 2026-10-27.

 ******************************************************************************/

#pragma once

#include "CPane.h"
#include "CEditText.h"
#include <QDOffscreen.h>

	// AppleTalk: this Mac's node, then every NBP entity with a type LED.
class CATPane : public CPane
{
public:
	CATPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight, short aHEncl, short aVEncl);

	virtual	void	Draw(Rect *area);

protected:
	char			info[96];				// "Node 65280.117 ..." - read once, NC_ATInfo opens AppleTalk
	unsigned long	infoTick;
};

	// Listen: protocol meters, the stations seen, the event log.
class CListenPane : public CPane
{
public:
	CListenPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight, short aHEncl, short aVEncl);

	virtual	void	Draw(Rect *area);
	void			Pulse(void);			// the chore: flash the meter LEDs that counted

protected:
	void			DrawMeters(Boolean all);

	long			last[9];				// the counters at the last pulse
	unsigned long	litUntil[9];
	Boolean			lit[9];
};

	// Map: who sends to whom, drawn from what Listen hears - the busiest stations on an outer ring, the groups they
	// send to (broadcast, mDNS, IPv6, LLDP, AppleTalk) on an inner one, unicast as chords between stations.
	// A click on a node selects it: its edges stand out and a box tells what is known about it.
#define kMapNodes	26
class CMapPane : public CPane
{
public:
	CMapPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight, short aHEncl, short aVEncl);
	virtual			~CMapPane();

	virtual	void	Draw(Rect *area);
	virtual	void	DoClick(Point hitPt, short modifierKeys, long when);
	void			Update(void);			// the 2 s redraw: straight to the screen, no update event

protected:
	void			DrawMap(Rect *r);
	void			DrawInfo(Rect *r, const Point *node);	// in the corner across from the node

	GWorldPtr		offscreen;				// drawn there, then copied: no flicker on a redraw
	short			nodes;					// the outer ring as last drawn, for the click
	Point			nodePt[kMapNodes];
	short			nodeSt[kMapNodes];		// station index, -1: an address only
	unsigned long	nodeIP[kMapNodes];
	Boolean			selected;
	short			selSt;					// the selected station, or -1 with
	unsigned long	selIP;					// the selected address only ever seen as a destination
};

	// Tools: what ping, DNS or traceroute found, below the host field and its buttons.
class CToolsPane : public CPane
{
public:
	CToolsPane(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight, short aHEncl, short aVEncl);

	virtual	void	Draw(Rect *area);
	void			SetMode(short aMode) { mode = aMode; }

protected:
	short			mode;					// 0 nothing yet, 1 ping, 2 DNS, 3 traceroute
};

	// A light push button for the work area (CToolButton is the dark strip's). While its
	// tool runs it stays down - accent blue - so the view shows what is going on.
class CLightButton : public CPane
{
public:
	CLightButton(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHEncl, short aVEncl,
				 const char *aLabel, long aCommand);

	virtual	void	Draw(Rect *area);
	virtual	void	DoClick(Point hitPt, short modifierKeys, long when);
	void			SetRunning(Boolean aRunning);

protected:
	void			DrawButton(Boolean pressed);

	Str31			label;
	long			command;
	Boolean			running;
};

	// The host field: Return pings.
class CHostField : public CEditText
{
public:
	CHostField(CView *anEnclosure, CBureaucrat *aSupervisor, short aWidth, short aHeight, short aHEncl, short aVEncl);

	virtual	void	DoKeyDown(char theChar, Byte keyCode, EventRecord *macEvent);
	void			GetHost(char *out, short max);	// the field as a C string, blanks trimmed
};

	// The About box (DLOG 300, logo PICT 300 with MacNetScan 1's radar sweep) and the Scan Options
	// dialog (DLOG 301); the options live in "MacNetScan Prefs" in the Preferences folder.
void	ShowAbout(void);
Boolean	RunOptions(void);			// TRUE if OK changed the settings (saved at once)
void	LoadPrefs(void);			// after NC_Init
