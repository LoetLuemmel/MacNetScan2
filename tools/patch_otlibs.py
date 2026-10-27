#!/usr/bin/env python3
"""patch_otlibs.py IN_DIR OUT_DIR - makes Open Transport 1.1's 68K libraries link beside the THINK Class Library.

OpenTransport.o, OpenTransportApp.o and OpenTptATalk.o define the ASLM helpers `Fail` and `FlushCache`, which TCL (and
its Bedrock exception library) define as well: Symantec's linker stops with "multiply defined". MPW's linker never sees
the clash because it drops modules nothing reaches. The fix renames the two names inside the MPW object files, keeping
their length (`Fail` -> `Fai_`, `FlushCache` -> `FlushCach_`): an object file stores a name once, in a dictionary
record, and refers to it by number, so the definition and every call are renamed together - in all four files, since
OpenTptATalk.o calls the `Fail` of OpenTransportApp.o.

The libraries are Apple's (OT SDK: "Open Tpt Client Developer:68K Libraries:") and are not in this repository. Copy them
from the guest with mac_get_file (MacBinary) or as plain data forks into IN_DIR; OUT_DIR gets the patched files in the
same form, ready for mac_put_file into the project's Engine folder. Measured 2026-10-27 with MacNetScan 2. stdlib only."""
import os, struct, sys

NAMES = [(b"\x04Fail", b"\x04Fai_"), (b"\x0aFlushCache", b"\x0aFlushCach_")]
LIBS = ["OpenTransport.o", "OpenTransportApp.o", "OpenTptInet.o", "OpenTptATalk.o"]


def data_fork(b):
    """(start, length) of the data fork: MacBinary if the header says so, else the whole file"""
    if len(b) > 128 and b[0] == 0 and 1 <= b[1] <= 63 and b[74] == 0:
        n = struct.unpack(">I", b[83:87])[0]
        if 128 + n <= len(b):
            return 128, n
    return 0, len(b)


def main(src, dst):
    os.makedirs(dst, exist_ok=True)
    for f in sorted(os.listdir(src)):
        if not any(f.startswith(lib) for lib in LIBS):
            continue
        b = bytearray(open(os.path.join(src, f), "rb").read())
        start, n = data_fork(b)
        d = bytes(b[start:start + n])
        counts = []
        for old, new in NAMES:
            counts.append(d.count(old))
            d = d.replace(old, new)
        b[start:start + n] = d
        open(os.path.join(dst, f), "wb").write(bytes(b))
        print(f"{f}: Fail x{counts[0]}, FlushCache x{counts[1]} renamed")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
