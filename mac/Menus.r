/* Menus.r - MacNetScan 2's own menus beside Visual Architect's Apple, File and Edit: Scan (600-603) and View
   (610-618, CMain.h). TCL takes the command number from "#n" in the item text; CApp::SetUpMenus adds both to the bar.
     Rez Menus.r -a -o "Project Resources.rsrc"   (THINK merges it into MacNetScan.\0xB9.rsrc and the app) */

#include "Types.r"

resource 'MENU' (128, "Scan") {
	128,
	textMenuProc,
	allEnabled,
	enabled,
	"Scan",
	{
		"Start Scan#600", noIcon, "R", noMark, plain,
		"Stop#601", noIcon, ".", noMark, plain,
		"-", noIcon, noKey, noMark, plain,
		"Export Report\0xC9#602", noIcon, "E", noMark, plain,
		"Copy Report#603", noIcon, noKey, noMark, plain,
		"-", noIcon, noKey, noMark, plain,
		"Options\0xC9#604", noIcon, ";", noMark, plain
	}
};

resource 'MENU' (129, "View") {
	129,
	textMenuProc,
	allEnabled,
	enabled,
	"View",
	{
		"IP Network#610", noIcon, "1", noMark, plain,
		"AppleTalk#611", noIcon, "2", noMark, plain,
		"Listen#612", noIcon, "3", noMark, plain,
		"Tools#613", noIcon, "4", noMark, plain,
		"Map#614", noIcon, "5", noMark, plain,
		"Frames#615", noIcon, "6", noMark, plain,
		"-", noIcon, noKey, noMark, plain,
		"Grid Lines#616", noIcon, "G", noMark, plain,
		"Demo Mode#617", noIcon, "D", noMark, plain,
		"-", noIcon, noKey, noMark, plain,
		"MacNetScan Help\0xC9#618", noIcon, "?", noMark, plain
	}
};

/* no MBAR: Visual Architect's MBAR 1 stays; CApp::SetUpMenus adds 128 and 129 (a second MBAR 1 is a duplicate
   resource at link time). */
