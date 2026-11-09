/******************************************************************************
 CHelp.cp - View > MacNetScan Help: TEXT 400 (mac/Help.txt, Rez'd by Help.r) in a movable modal window with a
 scroll bar and a Done button. Plain Toolbox, no TCL class: one function, its own segment (the Application segment
 holds 32.2 K of 32 K). The text wraps at the window's width; arrows, Page Up/Down, Home and End scroll; Return,
 Enter, Escape and Cmd-. close.

	Copyright © 2026 Pit Förster - MIT License (with Claude Code).
 ******************************************************************************/

#include <Windows.h>
#include <Controls.h>
#include <TextEdit.h>
#include <Resources.h>
#include <Events.h>
#include <Memory.h>
#include <ToolUtils.h>
#define kHelpFont	3							/* Geneva (Look.h needs the TCL headers) */

void ShowHelp(void);

#define kHelpTEXT	400
#define kHelpW		540
#define kHelpH		420

static TEHandle			gHelpTE;
static ControlHandle	gHelpBar;

static short HelpVisible(void)								/* whole lines in the text's view */
{
	return (short) (((*gHelpTE)->viewRect.bottom - (*gHelpTE)->viewRect.top) / (*gHelpTE)->lineHeight);
}

static void HelpScrollTo(short line)							/* the top line, kept in range */
{
	short old = GetControlValue(gHelpBar), max = GetControlMaximum(gHelpBar);
	if (line < 0) line = 0;
	if (line > max) line = max;
	if (line == old) return;
	SetControlValue(gHelpBar, line);
	TEScroll(0, (short) ((old - line) * (*gHelpTE)->lineHeight), gHelpTE);
}

static pascal void HelpAction(ControlHandle c, short part)	/* arrows and the gray area, while held */
{
	short page = (short) (HelpVisible() - 1);
	if (page < 1) page = 1;
	switch (part) {
		case inUpButton:		HelpScrollTo((short) (GetControlValue(c) - 1)); break;
		case inDownButton:	HelpScrollTo((short) (GetControlValue(c) + 1)); break;
		case inPageUp:		HelpScrollTo((short) (GetControlValue(c) - page)); break;
		case inPageDown:		HelpScrollTo((short) (GetControlValue(c) + page)); break;
	}
}

static void HelpDraw(WindowPtr w, ControlHandle done)
{
	Rect r;
	EraseRect(&w->portRect);
	TEUpdate(&w->portRect, gHelpTE);
	DrawControls(w);
	r = (*done)->contrlRect;									/* the default button's ring */
	InsetRect(&r, -4, -4);
	PenSize(3, 3);
	FrameRoundRect(&r, 16, 16);
	PenNormal();
}

void ShowHelp(void)
{
	static ControlActionUPP action = NULL;
	GrafPtr savePort;
	WindowPtr w;
	ControlHandle done;
	Rect bounds, view, r;
	Handle text;
	EventRecord e;
	short max, finished = 0;

	if (action == NULL) action = NewControlActionProc(HelpAction);
	GetPort(&savePort);
	bounds = qd.screenBits.bounds;								/* centred, below the menu bar */
	SetRect(&r, 0, 0, kHelpW, kHelpH);
	OffsetRect(&r, (short) ((bounds.right - bounds.left - kHelpW) / 2),
			   (short) (40 + (bounds.bottom - bounds.top - 40 - kHelpH) / 3));
	w = NewCWindow(NULL, &r, "\pMacNetScan Help", TRUE, movableDBoxProc, (WindowPtr) -1L, FALSE, 0);
	if (w == NULL) { SysBeep(1); return; }
	SetPort(w);
	TextFont(kHelpFont); TextSize(10);
	SetRect(&view, 12, 10, kHelpW - 30, kHelpH - 46);
	gHelpTE = TENew(&view, &view);
	text = GetResource('TEXT', kHelpTEXT);
	if (gHelpTE == NULL || text == NULL) { if (gHelpTE) TEDispose(gHelpTE); DisposeWindow(w); SetPort(savePort); SysBeep(1); return; }
	HLock(text);
	TESetText(*text, GetHandleSize(text), gHelpTE);
	HUnlock(text);
	ReleaseResource(text);
	max = (short) ((*gHelpTE)->nLines - HelpVisible());
	if (max < 0) max = 0;
	SetRect(&r, kHelpW - 22, 6, kHelpW - 6, kHelpH - 42);
	gHelpBar = NewControl(w, &r, "\p", TRUE, 0, 0, max, scrollBarProc, 0);
	SetRect(&r, kHelpW - 92, kHelpH - 32, kHelpW - 22, kHelpH - 12);
	done = NewControl(w, &r, "\pDone", TRUE, 0, 0, 1, pushButProc, 0);

	while (!finished) {
		if (!WaitNextEvent(everyEvent, &e, 30, NULL)) continue;
		switch (e.what) {
		case mouseDown: {
			WindowPtr hit;
			short part = FindWindow(e.where, &hit);
			if (hit != w) { SysBeep(1); break; }				/* modal: only this window */
			if (part == inDrag) { Rect lim = (**GetGrayRgn()).rgnBBox; DragWindow(w, e.where, &lim); }
			else if (part == inContent) {
				ControlHandle c;
				Point p = e.where;
				short cp;
				GlobalToLocal(&p);
				cp = FindControl(p, w, &c);
				if (c == done) { if (TrackControl(c, p, NULL)) finished = 1; }
				else if (c == gHelpBar && cp == inThumb) {
					short old = GetControlValue(c), now;
					TrackControl(c, p, NULL);
					now = GetControlValue(c);
					SetControlValue(c, old);
					HelpScrollTo(now);
				} else if (c == gHelpBar) TrackControl(c, p, action);
			}
			break;
		}
		case keyDown:
		case autoKey: {
			char ch = (char) (e.message & charCodeMask);
			short page = (short) (HelpVisible() - 1), top = GetControlValue(gHelpBar);
			if (ch == 0x0D || ch == 0x03 || ch == 0x1B || ((e.modifiers & cmdKey) && ch == '.')) finished = 1;
			else if (ch == 0x1E) HelpScrollTo((short) (top - 1));			/* up arrow */
			else if (ch == 0x1F) HelpScrollTo((short) (top + 1));			/* down arrow */
			else if (ch == 0x0B) HelpScrollTo((short) (top - page));		/* page up */
			else if (ch == 0x0C || ch == ' ') HelpScrollTo((short) (top + page));	/* page down */
			else if (ch == 0x01) HelpScrollTo(0);							/* home */
			else if (ch == 0x04) HelpScrollTo(GetControlMaximum(gHelpBar));	/* end */
			break;
		}
		case updateEvt: {
			WindowPtr u = (WindowPtr) e.message;
			BeginUpdate(u);
			if (u == w) HelpDraw(w, done);						/* the others wait: they are redrawn below */
			EndUpdate(u);
			break;
		}
		}
	}
	TEDispose(gHelpTE);
	gHelpTE = NULL;
	DisposeWindow(w);											/* its controls go with it */
	if (FrontWindow() != NULL) {								/* updates skipped above: draw it all again */
		SetPort(FrontWindow());
		InvalRect(&FrontWindow()->portRect);
	}
	SetPort(savePort);
}
