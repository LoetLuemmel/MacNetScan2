/******************************************************************************
 CViews.h

	MacNetScan 2's AppleTalk, Listen and Tools views (phase 4) - their own
	file and segment, so CMain.cp stays under the 32 KB of a 68K segment.
	Pit Förster with Claude Code via AppleBridge, 2026-10-27.

 ******************************************************************************/

#pragma once

#include "CPane.h"
#include "CEditText.h"

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
