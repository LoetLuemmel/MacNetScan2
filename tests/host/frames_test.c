/* frames_test.c - runs MacNetScan's dissector, pcap reader and filter (netcore/frames.c) on the host.
   Each record goes through NC_PcapToFrame, as File > Open pcap reads it in the guest: Ethernet (802.3/SNAP,
   802.1Q) or Linux cooked (113, MacNetScan's own export), the EtherType and the bytes from layer 3 on, padding
   included. Prints the Frames list, -v each protocol tree too.
   Build and run: tests/host/run.sh capture.pcap [-v] [-a] [-r MAC] [-f "filter words"]
     -a  AppleTalk and AARP only    -r MAC  leave out what that Mac sent, as its own Listen sees it
     -f  the Frames view's filter: all words must appear (any case), "!word" must not */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../netcore/OTCompat.h"
#include "../../netcore/netcore.h"

static NCFrame *gF;
static long gN, gCap;
static unsigned long gEpoch;

long NC_FrameTotal(void) { return gN; }
const NCFrame *NC_Frame(long i) { return (i >= 0 && i < gN && i >= gN - NC_MAXFRAMES) ? &gF[i] : NULL; }
unsigned long NC_FrameEpoch(void) { return gEpoch; }
void NC_FramesReset(unsigned long epoch) { gN = 0; gEpoch = epoch; }
NCFrame *NC_FrameSlot(void)						/* the host keeps every frame; NC_Frame still shows the last 400 */
{
	if (gN >= gCap) { gCap = gCap ? gCap * 2 : 256; gF = realloc(gF, (size_t) gCap * sizeof(NCFrame)); }
	return &gF[gN];
}
void NC_FrameCommit(void) { gN++; }
void NC_IPToStr(NCAddr ip, char *out) { sprintf(out, "%lu.%lu.%lu.%lu", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255); }
void NC_MACToStr(const unsigned char *m, char *out) { sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); }

static unsigned long rd32(const unsigned char *b, int sw) { return sw ? (unsigned long) b[0] | b[1] << 8 | b[2] << 16 | (unsigned long) b[3] << 24 : (unsigned long) b[3] | b[2] << 8 | b[1] << 16 | (unsigned long) b[0] << 24; }

static void Print(long i, int verbose)
{
	char s[48], d[48], pr[16], in[96], lines[40][NC_DETAILLEN];
	short nl, k;
	NC_FrameSummary(&gF[i], s, d, pr, in);
	printf("%4ld %8.3f  %-16s %-16s %-5s %s\n", i + 1, gF[i].us / 1e6, s, d, pr, in);
	if (verbose) {
		nl = NC_FrameDetail(&gF[i], lines, 40);
		for (k = 0; k < nl; k++) printf("        %s\n", lines[k][0] == 1 ? lines[k] + 1 : lines[k]);
	}
}

int main(int argc, char **argv)
{
	unsigned char gh[24], rh[16], *buf;
	int sw, verbose = 0, atonly = 0, rx = 0, i;
	unsigned char self[6];
	const char *path = NULL, *filter = NULL;
	unsigned long link;
	long total, n;
	FILE *fp;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v")) verbose = 1;
		else if (!strcmp(argv[i], "-a")) atonly = 1;
		else if (!strcmp(argv[i], "-f") && i + 1 < argc) filter = argv[++i];
		else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
			unsigned m[6]; int k;
			sscanf(argv[++i], "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
			for (k = 0; k < 6; k++) self[k] = (unsigned char) m[k];
			rx = 1;
		} else path = argv[i];
	}
	if (!path || !(fp = fopen(path, "rb")) || fread(gh, 1, 24, fp) != 24) { fprintf(stderr, "usage: frames_test file.pcap [-v] [-a] [-r MAC] [-f words]\n"); return 2; }
	sw = gh[0] == 0xd4 || gh[0] == 0x4d;
	link = rd32(gh + 20, sw);
	buf = malloc(262144);
	while (fread(rh, 1, 16, fp) == 16) {
		unsigned long incl = rd32(rh + 8, sw);
		NCFrame *f;
		if (incl > 262144 || fread(buf, 1, incl, fp) != incl) break;
		if (gN == 0 && gEpoch == 0) gEpoch = rd32(rh, sw);
		f = NC_FrameSlot();
		if (!NC_PcapToFrame(rh, buf, (long) incl, link, (short) sw, gEpoch, f)) continue;
		if (atonly && f->type != 0x809B && f->type != 0x80F3) continue;
		if (rx && !memcmp(f->src, self, 6)) continue;
		NC_FrameCommit();
	}
	total = gN;
	if (filter) {											/* as the view: the last 400, then the matches */
		NC_FilterSet(filter);
		n = NC_FilterUpdate();
		for (i = 0; i < n; i++) Print(NC_FilterFrame(i), verbose);
		fprintf(stderr, "%ld of the last %ld frames match \"%s\"\n", n, total < NC_MAXFRAMES ? total : (long) NC_MAXFRAMES, filter);
		return 0;
	}
	for (i = 0; i < total; i++) { gN = i + 1; Print(i, verbose); }	/* the ring as it stood when frame i arrived */
	return 0;
}
