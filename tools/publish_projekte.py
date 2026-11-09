#!/usr/bin/env python3
"""publish_projekte.py - one MacNetScan for every guest: git -> the build guest -> the AppleShare volume "Projekte".

Git stays the source (history, review, host tests). The Macs take the project from the shelf
"Projekte:MacNetScan ƒ" on ApfelNetz (the XU4's netatalk) and copy it to their own disk to build or run it there:
building ON the share is slow (AFP, about 700 KB/s) and two Macs on one .π overwrite each other.

  --sync     the COMMITTED sources (git HEAD, not the working tree) into the build guest's own project folder,
             UTF-8 -> MacRoman, LF -> CR, type TEXT/KAHL (resources TEXT/MPS). Then build there (THINK: Cmd-K the
             changed files, Project > Build Application, SetFile -a B).
  --publish  the build guest's project folder -> the shelf, over AFP from the guest itself, so forks, types and
             netatalk's AppleDouble/CNID bookkeeping stay right; writing the share from Linux would bypass them.
             Leaves out what only that guest needs (XSYMs, pcaps, logs, backups) and writes a STAND file:
             the git commit, when the app was built, by which guest.

Paths and the guest are the constants below; the guest needs "Projekte" mounted.
Run: uv run tools/publish_projekte.py --sync | --publish | --sync --publish
"""

import argparse
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APPLEBRIDGE_HOST = Path.home() / "Documents/Dev/AppleBridge_Working/host"
sys.path.insert(0, str(APPLEBRIDGE_HOST))
from send_command import send_command          # noqa: E402
from encoding_convert import utf8_to_macroman   # noqa: E402

GUEST = "odroid-c2"
CTRL_PORT = 9031                                # its AppleBridge control port (host/guests.conf)
SSH = "pit@192.168.3.4"
DROP = "basilisk/data/build/mns_publish"        # on the C2; the guest sees it as Unix:data:build:mns_publish:
DROP_MAC = "Unix:data:build:mns_publish:"
LOCAL = "MeinMac:Development:Symantec C++ for Macintosh:MacNetScan ƒ"
SHELF = "Projekte:MacNetScan ƒ"

# git path -> (folder in the project, type, creator)
SOURCES = {f"mac/{n}": ("Source", "TEXT", "KAHL") for n in
           ("CApp.cp", "CApp.h", "CATView.cp", "CMain.cp", "CMain.h", "CViews.cp", "CViews.h", "Look.h")}
SOURCES.update({f"netcore/{n}": ("Engine", "TEXT", "KAHL") for n in
                ("frames.c", "netcore.c", "netcore.h", "OTCompat.h", "OTNames.h", "otstubs.c")})
SOURCES.update({f"mac/{n}": ("", "TEXT", "MPS ") for n in ("Extras.r", "Icons.r", "Menus.r")})

# what the shelf holds: enough to build (project, resources, sources, the OT SDK in Engine) and the app itself
SHELF_ITEMS = ["MacNetScan", "MacNetScan.π", "MacNetScan.π.rsrc", "Project Resources.rsrc", "Visual Architect.rsrc",
               "Source", "Engine", "Extras.r", "Icons.r", "Menus.r", "PLACEHOLDER.cpp", "READ ME.cp"]
SHELF_DROP = ["Engine:dump.txt"]                # a local leftover inside a folder that is copied whole


def mpw(cmd, ok_empty=True):
    """one MPW command on the build guest -> its stdout; exits on a failure"""
    r = send_command(cmd, port=CTRL_PORT)
    m = re.search(r"STATUS:(-?\d+)\r?STDOUT:(\d+)\r?", r)
    if not m:
        sys.exit(f"{GUEST}: unexpected reply to {cmd!r}: {r[:200]}")
    status, n = int(m.group(1)), int(m.group(2))
    out = r[m.end():m.end() + n]
    if status != 0:
        sys.exit(f"{GUEST}: {cmd!r} failed ({status}): {r[m.end():][:300]}")
    return out


def exists(path):
    """MPW's Exists prints the path when it is there and nothing (a -1701 status on some daemons) when it is not"""
    r = send_command(f'Exists "{path}"', port=CTRL_PORT)
    m = re.search(r"STATUS:(-?\d+)\r?STDOUT:(\d+)\r?", r)
    return bool(m and int(m.group(2)) > 0 and r[m.end():m.end() + int(m.group(2))].strip())


def head():
    rev = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%h %cs %s"],
                         capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", "mac", "netcore"],
                           capture_output=True, text=True).stdout.strip()
    return rev, dirty


def upload(files):
    """{name: bytes} -> the drop folder on the C2 (the guest's Unix: volume)"""
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in files.items():
            (Path(tmp) / name).write_bytes(data)
        subprocess.run(["ssh", SSH, f"rm -rf ~/{DROP} && mkdir -p ~/{DROP}"], check=True)
        subprocess.run(["scp", "-q"] + [str(Path(tmp) / n) for n in files] + [f"{SSH}:{DROP}/"], check=True)


def sync():
    rev, dirty = head()
    if dirty:
        print(f"note: uncommitted changes in mac/ or netcore/ are NOT synced (git HEAD is):\n{dirty}")
    files = {}
    for path in SOURCES:
        text = subprocess.run(["git", "-C", str(REPO), "show", f"HEAD:{path}"],
                              capture_output=True, text=True, check=True).stdout
        files[Path(path).name] = utf8_to_macroman(text.replace("\r\n", "\n")).replace(b"\n", b"\r")
    upload(files)
    for path, (folder, ftype, creator) in SOURCES.items():
        name = Path(path).name
        dest = f"{LOCAL}:{folder + ':' if folder else ''}{name}"
        mpw(f'Duplicate -y "{DROP_MAC}{name}" "{dest}"')
        mpw(f'SetFile -t {ftype} -c "{creator}" "{dest}"')
    print(f"synced {len(SOURCES)} sources of {rev} into {GUEST}:{LOCAL}")
    print("next: build there (THINK: Cmd-K each changed file, Project > Build Application, SetFile -a B), "
          "then --publish")


def publish():
    if not exists("Projekte:"):
        sys.exit(f'{GUEST} has no "Projekte" mounted (Chooser > AppleShare > ApfelNetz > Projekte)')
    if not exists(SHELF):
        mpw(f'NewFolder "{SHELF}"')
    for item in SHELF_ITEMS:
        if exists(f"{LOCAL}:{item}"):
            mpw(f'Duplicate -y "{LOCAL}:{item}" "{SHELF}:"')
        else:
            print(f"note: {LOCAL}:{item} is missing - not on the shelf")
    for item in SHELF_DROP:
        if exists(f"{SHELF}:{item}"):
            mpw(f'Delete -y "{SHELF}:{item}"')
    listing = mpw(f'Files -x m "{LOCAL}:MacNetScan"')
    stamp = re.search(r"\d+/\d+/\d+\s+\d+:\d+\s*[AP]M", listing)
    built = stamp.group(0) if stamp else "?"
    rev, dirty = head()
    stand = (f"MacNetScan 2 - Stand\n\n"
             f"git:        {rev}{'  (plus uncommitted changes on the host)' if dirty else ''}\n"
             f"App gebaut: {built}  auf {GUEST}\n"
             f"Abgelegt:   {datetime.now():%Y-%m-%d %H:%M}\n\n"
             f"Zum Bauen den ganzen Ordner auf die eigene Platte kopieren (nicht auf dem Server bauen).\n"
             f"Quelle der Wahrheit ist git: github.com/LoetLuemmel/MacNetScan2\n")
    upload({"STAND": utf8_to_macroman(stand).replace(b"\n", b"\r")})
    mpw(f'Duplicate -y "{DROP_MAC}STAND" "{SHELF}:STAND"')
    mpw(f'SetFile -t TEXT -c ttxt "{SHELF}:STAND"')
    print(mpw(f'Files -x tcrb "{SHELF}:"').replace("\r", "\n"))
    print(f"published to {SHELF} ({rev})")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sync", action="store_true", help="git HEAD sources -> the build guest's project")
    ap.add_argument("--publish", action="store_true", help="the build guest's project and app -> Projekte")
    a = ap.parse_args()
    if not (a.sync or a.publish):
        ap.error("--sync and/or --publish")
    if a.sync:
        sync()
    if a.publish:
        publish()


if __name__ == "__main__":
    main()
