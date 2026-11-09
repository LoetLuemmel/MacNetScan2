/* frames_test.c - runs MacNetScan's dissector (netcore/frames.c) on the host against a pcap file.
   Reads Ethernet (link type 1, 802.3/SNAP and 802.1Q too) or Linux cooked (113, MacNetScan's own export) and
   hands each frame on as Open Transport would: the EtherType (the SNAP protocol for AppleTalk and AARP) and the
   bytes from the layer-3 header on. Prints the list line of every frame, -v also its protocol tree.
   Build and run: tests/host/run.sh capture.pcap [-v] [-a] [-r MAC] (-a: AppleTalk and AARP only; -r: leave out what
   that MAC sent, as the guest's own Listen sees it) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../netcore/OTCompat.h"
#include "../../netcore/netcore.h"

static NCFrame *gF;
static long gN;

long NC_FrameTotal(void) { return gN; }
const NCFrame *NC_Frame(long i) { return (i >= 0 && i < gN && i >= gN - NC_MAXFRAMES) ? &gF[i] : NULL; }
unsigned long NC_FrameEpoch(void) { return 0; }
void NC_IPToStr(NCAddr ip, char *out) { sprintf(out, "%lu.%lu.%lu.%lu", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255); }
void NC_MACToStr(const unsigned char *m, char *out) { sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]); }

static unsigned rd32(const unsigned char *b, int sw) { return sw ? (unsigned) b[0] | b[1] << 8 | b[2] << 16 | (unsigned) b[3] << 24 : (unsigned) b[3] | b[2] << 8 | b[1] << 16 | (unsigned) b[0] << 24; }
static unsigned g16(const unsigned char *b) { return (unsigned) (b[0] << 8 | b[1]); }

int main(int argc, char **argv)
{
	unsigned char gh[24], rh[16], *buf;
	int sw, verbose = 0, atonly = 0, i, rx = 0;
	unsigned char self[6];
	unsigned link, t0 = 0, cap = 0;
	FILE *fp;
	const char *path = NULL;
	for (i = 1; i < argc; i++) { if (!strcmp(argv[i], "-v")) verbose = 1; else if (!strcmp(argv[i], "-a")) atonly = 1;
		else if (!strcmp(argv[i], "-r") && i + 1 < argc) { unsigned m[6]; int k; sscanf(argv[++i], "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]); for (k = 0; k < 6; k++) self[k] = (unsigned char) m[k]; rx = 1; }
		else path = argv[i]; }
	if (!path || !(fp = fopen(path, "rb")) || fread(gh, 1, 24, fp) != 24) { fprintf(stderr, "usage: frames_test file.pcap [-v] [-a]\n"); return 2; }
	sw = gh[0] == 0xd4;
	link = rd32(gh + 20, sw);
	buf = malloc(262144);
	while (fread(rh, 1, 16, fp) == 16) {
		unsigned ts = rd32(rh, sw), us = rd32(rh + 4, sw), incl = rd32(rh + 8, sw), orig = rd32(rh + 12, sw);
		const unsigned char *src, *l3;
		unsigned type, off, l3len;
		NCFrame *f;
		if (incl > 262144 || fread(buf, 1, incl, fp) != incl) break;
		if (gN == 0) t0 = ts;
		if (link == 1) {
			if (incl < 14) continue;
			src = buf + 6; off = 12;
			type = g16(buf + off);
			if (type == 0x8100) { off += 4; type = g16(buf + off); }
			off += 2;
			l3len = orig - off;
			if (type <= 1500) {								/* 802.3: the length, then LLC/SNAP */
				if (incl < off + 8 || buf[off] != 0xaa || buf[off + 1] != 0xaa) continue;
				l3len = type - 8; type = g16(buf + off + 6); off += 8;
			}
		} else if (link == 113) {
			if (incl < 16) continue;
			src = buf + 6; type = g16(buf + 14); off = 16; l3len = orig - 16;
		} else { fprintf(stderr, "link type %u not handled\n", link); return 2; }
		if (atonly && type != 0x809B && type != 0x80F3) continue;
		if (rx && !memcmp(src, self, 6)) continue;			/* -r MAC: drop what that Mac sent, as Open Transport does */
		if (cap <= (unsigned) gN) { cap = cap ? cap * 2 : 256; gF = realloc(gF, cap * sizeof(NCFrame)); }
		f = &gF[gN];
		memset(f, 0, sizeof(*f));
		f->us = (unsigned long) (ts - t0) * 1000000UL + us;
		memcpy(f->src, src, 6);
		f->type = (unsigned short) type;
		f->len = (short) l3len;
		f->caplen = (short) (incl - off < NC_SNAPLEN ? incl - off : NC_SNAPLEN);
		if (f->caplen > f->len) f->caplen = f->len;
		l3 = buf + off;
		memcpy(f->data, l3, (size_t) f->caplen);
		gN++;
	}
	for (i = 0; i < gN; i++) {
		char s[48], d[48], pr[16], in[96], lines[40][NC_DETAILLEN];
		short nl, k;
		NC_FrameSummary(&gF[i], s, d, pr, in);
		printf("%4d %8.3f  %-16s %-16s %-5s %s\n", i + 1, gF[i].us / 1e6, s, d, pr, in);
		if (verbose) {
			nl = NC_FrameDetail(&gF[i], lines, 40);
			for (k = 0; k < nl; k++) printf("        %s\n", lines[k][0] == 1 ? lines[k] + 1 : lines[k]);
		}
	}
	return 0;
}
