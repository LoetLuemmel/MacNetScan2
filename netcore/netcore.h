/* netcore.h - MacNetScan 2's network engine: everything that talks to Open Transport, no window code.
   Taken from MacNetScan 1's ipscan.c (2026, MIT), restructured so that nothing blocks: every activity is a
   Start / Idle / result triple and the application calls the Idle functions from its event loop (a TCL CChore), so
   the Mac keeps yielding while a /24 is swept - MacNetScan 1 looped on SystemTask and froze every other process.

   NC_Init opens Open Transport, NC_Shutdown closes it. The header needs no Open Transport header: the TCL application
   (C++) includes only this, and the OT headers stay inside netcore.c. Plain C (THINK C / Symantec C++ 7, 68K, far code). */

#ifndef __NETCORE__
#define __NETCORE__

#ifdef __cplusplus
extern "C" {
#endif

#define NC_MAXPORTS		16
#define NC_MAXHOSTS		254
#define NC_MAXSLOTS		24
#define NC_NAMELEN		64

typedef unsigned long	NCAddr;					/* an IPv4 address, = Open Transport's NCAddr */

/* ---- setup ---- */
long    	NC_Init(void);							/* opens Open Transport, reads the own address */
void		NC_Shutdown(void);						/* closes whatever is still open, then Open Transport */
NCAddr	NC_LocalIP(void);
NCAddr	NC_Netmask(void);
NCAddr	NC_Base(void);							/* the /24 being swept: local address & 0xFFFFFF00 */
void		NC_IPToStr(NCAddr ip, char *out);		/* "192.168.3.1" */
void		NC_RttToStr(long us, char *out);		/* "0.8", "12", "340" (milliseconds), "-" if none */

/* ---- sweep parameters (defaults: .1 - .254, 600 ms, 24 at once, the ten well-known ports) ---- */
void		NC_SetRange(short first, short last);
void		NC_GetRange(short *first, short *last);
void		NC_SetTimeoutMs(long ms);
long		NC_TimeoutMs(void);
void		NC_SetConcurrency(short n);
short		NC_Concurrency(void);
void		NC_SetDefaultPorts(void);
short		NC_ParsePorts(const char *list);		/* "80,443,548" -> count taken; 0 keeps the old list */
void		NC_PortsToStr(char *out);				/* the current list as "80,443,..." */
short		NC_PortCount(void);
unsigned short		NC_Port(short i);
void		NC_PortLabel(short i, char *out);		/* "HTTP", "AFP", or the number */

/* ---- the sweep ---- */
enum { NC_SWEEP_IDLE = 0, NC_SWEEP_PROBING, NC_SWEEP_NAMING, NC_SWEEP_DONE };

typedef struct {
	NCAddr	ip;
	long		rttUs;						/* first answer in microseconds, -1 if none measured */
	unsigned long		openMask;					/* bit i = port NC_Port(i) answered with a connection */
	char		name[NC_NAMELEN];			/* "" until resolved, "?" if nothing answered */
	char		nameSource;					/* 'N' NetBIOS, 'M' multicast DNS, 'D' DNS, 0 none */
} NCHost;

void		NC_SweepStart(void);
void		NC_SweepStop(void);						/* finishes the probes in flight, skips the rest */
short		NC_SweepIdle(void);						/* does a bounded slice of work, returns the phase */
short		NC_SweepPhase(void);
void		NC_SweepProgress(long *done, long *total);	/* probes, then hosts named */
short		NC_HostCount(void);
const NCHost *NC_Host(short i);					/* ordered by address */
long		NC_ChangeCount(void);					/* grows whenever results change: redraw when it moved */
long		NC_ActivityCount(void);					/* grows with every answer: the ACT LED */
long		NC_BuildReport(char *buf, long max);	/* tab-delimited, CR line ends */

/* ---- AppleTalk ---- */
typedef struct {
	char		address[24];				/* "65280.117:4" */
	char		router[24];					/* "" if none */
	char		zone[34];
	short		cableLow, cableHigh;
	Boolean		isExtended;					/* "extended" is SANE's floating type in C++ */
} NCATInfo;

typedef struct {
	char		object[34];
	char		type[34];
	char		zone[34];
	char		address[24];
} NCEntity;

Boolean		NC_ATAvailable(void);
long    	NC_ATInfo(NCATInfo *info);
short		NC_ZoneCount(void);						/* fetches the zone list on first use */
const char *NC_Zone(short i);
void		NC_NbpStart(void);						/* all zones ("*" on a flat network) */
Boolean		NC_NbpIdle(void);						/* one zone per call; false when finished */
void		NC_NbpProgress(short *done, short *total);
short		NC_EntityCount(void);
const NCEntity *NC_Entity(short i);

/* ---- tools: ping (TCP), DNS, traceroute (ICMP) ---- */
enum { NC_TOOL_IDLE = 0, NC_TOOL_RESOLVING, NC_TOOL_RUNNING, NC_TOOL_DONE, NC_TOOL_FAILED };

typedef struct {
	short		seq;						/* ping sequence or traceroute hop */
	NCAddr	ip;							/* answering host (0 = none) */
	long		rttUs;						/* microseconds, -1 = timeout */
	char		name[NC_NAMELEN];			/* traceroute: reverse name of the hop */
	Boolean		alive;						/* ping: host answered (open or refused) */
} NCToolLine;

void		NC_PingStart(const char *host, unsigned short port, short count);
void		NC_DnsStart(const char *host);
void		NC_TraceStart(const char *host);
short		NC_ToolIdle(void);						/* returns the tool state */
short		NC_ToolState(void);						/* the same, without doing any work */
const char *NC_ToolHost(void);						/* what was asked for, as typed */
void		NC_ToolStop(void);
short		NC_ToolLineCount(void);
const NCToolLine *NC_ToolLine(short i);
NCAddr	NC_ToolTarget(void);
const char *NC_ToolMessage(void);					/* DNS answer, error text */

/* ---- listen: what reaches this Mac anyway (passive, sends nothing) ---- */
typedef struct {
	unsigned char	mac[6];
	NCAddr			ip;							/* 0 if none seen; only addresses of the own /24 */
	unsigned short	atNet;						/* AppleTalk network and node, 0 if none seen */
	unsigned char	atNode;
	char			seen;						/* NC_SEEN_ bits */
	long			packets;
	unsigned long	firstTick, lastTick;
	char			name[24];					/* LLDP system name, "" if none */
} NCStation;
enum { NC_SEEN_ARP = 1, NC_SEEN_IP = 2, NC_SEEN_AT = 4, NC_SEEN_SELF = 8, NC_SEEN_IP6 = 16, NC_SEEN_LLDP = 32 };

typedef struct {
	long		total, arp, ipBroadcast, ipMulticast, ipUnicast, dhcp, netbios, ddp, aarp, conflicts;
	long		ipv6, lldp;
	short		joined;							/* multicast groups joined (mDNS, LLDP, IPv6) */
} NCListenStats;

	/* the map: who sends to whom, from the frames Listen hears. A unicast edge ends at an IPv4 address (a station
	   that claims it, or one never heard sending); every other edge ends at a group. */
enum { NC_TO_UNICAST = 0, NC_TO_BCAST, NC_TO_MDNS, NC_TO_IP6MC, NC_TO_LLDP, NC_TO_MCAST, NC_TO_ATALK, NC_TO_COUNT };
typedef struct {
	short			from;						/* station index, see NC_Station */
	char			to;							/* NC_TO_ */
	NCAddr			dst;						/* NC_TO_UNICAST: the destination; 0 otherwise */
	long			packets;
	unsigned long	lastTick;
} NCEdge;

long		NC_ListenStart(void);					/* opens the endpoints; 0 or an Open Transport error */
void		NC_ListenStop(void);
Boolean		NC_Listening(void);
void		NC_ListenIdle(void);					/* reads what has arrived, a bounded number of frames */
void		NC_ListenGetStats(NCListenStats *s);
short		NC_StationCount(void);
const NCStation *NC_Station(short i);
long		NC_EventTotal(void);					/* events so far; the last NC_MAXEVENTS are kept */
const char *NC_EventLine(long i);					/* i < NC_EventTotal(), "" once dropped */
short		NC_EdgeCount(void);
const NCEdge *NC_Edge(short i);
void		NC_MACToStr(const unsigned char *mac, char *out);	/* "00:0c:6c:0b:0e:ad" */
#define NC_MAXEVENTS	64

#ifdef __cplusplus
}
#endif

#endif
