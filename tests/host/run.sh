#!/bin/sh
# Builds the host test of netcore/frames.c and runs it on a pcap: run.sh capture.pcap [-v] [-a]
set -e
here=$(cd "$(dirname "$0")" && pwd)
out="${TMPDIR:-/tmp}/macnetscan_frames_test"
cc -std=c99 -DNC_HOST_TEST -Wall -Wno-pointer-sign -Wno-unused-function -I"$here/shim" -o "$out" "$here/frames_test.c" "$here/../../netcore/frames.c"
"$out" "$@"
