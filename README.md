# MacNetScan 2

A network scanner for System 7 on the classic 68K Macintosh, rebuilt from [MacNetScan 1](original/) with Symantec's
**Visual Architect** and the **THINK Class Library 2.0** (Symantec C++ 7). Written, compiled, linked and tested on a
System 7.6.1 guest in Basilisk II through [AppleBridge](https://github.com/LoetLuemmel/AppleBridge).

![IP Network view](docs/macnetscan2-ip-network.png)

## Views

| View | What it does |
|---|---|
| **IP Network** | Asynchronous TCP-connect sweep of the own /24 against ten well-known ports (AppleBridge, HTTP, HTTPS, SMB, NetBIOS, AFP, SSH, IPP, FTP, Telnet). Names from NetBIOS, multicast DNS or reverse DNS. Round-trip times stamped in the Open Transport notifier, to 0.1 ms. One LED per service, a detail panel per host. |
| **AppleTalk** | This Mac's node and zone; every NBP entity in every zone with a type LED. |
| **Listen** | Passive - sends nothing. ARP, IP broadcasts/multicasts, DHCP, NetBIOS, AppleTalk and AARP that reach this Mac: protocol meters, a station table (MAC, IP, AppleTalk address), an event log (new stations, gratuitous ARP, DHCP, IP conflicts). |
| **Tools** | Ping (TCP connect), DNS lookup (both directions), traceroute (ICMP). |

Plus: Export / Copy of a tab-delimited report, **Scan › Options** (range, timeout, probes at once, ports; kept in
`MacNetScan Prefs`), an About box with MacNetScan 1's radar sweep, a Finder icon.

| Listen | AppleTalk | Tools |
|---|---|---|
| ![](docs/macnetscan2-listen.png) | ![](docs/macnetscan2-appletalk.png) | ![](docs/macnetscan2-tools.png) |

## Layout

```
netcore/     the engine, plain C, all Open Transport (Start / Idle / result, nothing blocks)
mac/         the TCL application: CMain (window, tool strip, IP view), CViews (AppleTalk, Listen, Tools,
             About, Options), CApp; Look.h shared colours and helpers; Menus.r, Extras.r, Icons.r
mac/generated/  what Visual Architect generated, for reference
mac/rsrc/    Visual Architect.rsrc and Project Resources.rsrc as MacBinary
tools/       mkicons.py (Finder icons from a PNG), patch_otlibs.py (see below), mkotnames.py (OTNames.h)
probe/       the spikes: OTProbe (engine test bench) and SniffProbe (raw Ethernet, five runs)
original/    MacNetScan 1 (MPW, one C file)
```

## Building

1. A Visual Architect project in Symantec C++ 7 (project model "Visual Architect Project"), Generate once.
   Replace `Source:CMain.*`, `CApp.*` with the files in `mac/`, add `CViews.cp`, `Look.h`; Rez `Menus.r Extras.r
   Icons.r` into `Project Resources.rsrc` (or use the copy in `mac/rsrc/`).
2. Add `netcore/netcore.c` (it includes `otstubs.c`) and the four Open Transport 68K libraries through the
   ".o Converter": `OpenTransport.o`, `OpenTransportApp.o`, `OpenTptInet.o`, `OpenTptATalk.o` - **patched** with
   `tools/patch_otlibs.py` first (the SDK's `Fail` and `FlushCache` collide with TCL's). The OT SDK headers go next
   to `netcore.c`; `OTCompat.h` and `OTNames.h` (MPW's upper-case pascal names) are here.
3. Project type: **Far CODE**, partition 1500 K, creator `IPSc`. Segments: the OT libraries in one, `netcore.c` +
   `CViews.cp` in another (28.6 K of 32 K).
4. Build Application, then `SetFile -a B MacNetScan`.

Why each step is there: the comments in `netcore/netcore.c`, `tools/patch_otlibs.py` and `probe/sniff_main.c`.

## Under Basilisk II

The Listen view only binds and receives. Asking the emulated Ethernet driver for raw mode (`I_OTSetRawMode`) or
promiscuous mode (`OPT_SETPROMISCUOUS` at `LNK_TPI`) never returns and freezes the guest - measured with a flushed
per-call trail in `probe/sniff_main.c`.

## Authorized use only

MacNetScan actively probes hosts. Use it only on networks you own or are explicitly allowed to scan.

## License

MIT - Copyright (c) 2026 Pit Förster. See [License.txt](License.txt).
