/* Help.r - the text of View > MacNetScan Help (CHelp.cp): mac/Help.txt as TEXT 400. Help.txt is kept in git as
   UTF-8; tools/publish_projekte.py --sync writes it to the build guest in MacRoman with CR line ends. In MPW, from the
   project folder:   Rez Help.r -a -o "Project Resources.rsrc"   - only there: THINK links MacNetScan.π.rsrc too, and a
   TEXT 400 in both is a "duplicate resource". tools/publish_projekte.py --sync does it. */

read 'TEXT' (400, "Help", purgeable) "Help.txt";
