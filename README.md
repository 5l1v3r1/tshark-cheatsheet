# Hunting Real Fish with tshark

## Install/Configure tshark

### Make Sure Utilities are on $PATH

Setting up your environment should be done once and done well. 
There are a couple Additional work is usually necessary to make sure all utilities are on the path.

```bash
utils=(androiddump capinfos captype ciscodump dftest dumpcap editcap idl2wrs
  mergecap mmdbresolve randpkt randpktdump reordercap sshdump text2pcap tshark
  udpdump wireshark pcap-filter wireshark-filter)

for util in ${utils[*]}; do
  if [[ -z $(which $util) ]]; then
    echo $util
  fi
done
```

### Custom Aliases
```
alias tshark-any-any="tshark -i any"
alias tshark-usb="tshark -i usb0"
alias tshark-bluemoon='tshark -C BlueConfig -o BlueKey:BlueVal'
echo "alias tshark='tshark --color'" >> ~/.profile
```

## Flags

```bash
tshark -q -F 1> /dev/null
    pcap - Wireshark/tcpdump/... - pcap
    pcapng - Wireshark/... - pcapng
    5views - InfoVista 5View capture
    btsnoop - Symbian OS btsnoop
    commview-ncf - TamoSoft CommView NCF
    commview-ncfx - TamoSoft CommView NCFX
    dct2000 - Catapult DCT2000 trace (.out format)
    erf - Endace ERF capture
    eyesdn - EyeSDN USB S0/E1 ISDN trace format
    k12text - K12 text file
    lanalyzer - Novell LANalyzer
    logcat - Android Logcat Binary format
    logcat-brief - Android Logcat Brief text format
    logcat-long - Android Logcat Long text format
    logcat-process - Android Logcat Process text format
    logcat-tag - Android Logcat Tag text format
    logcat-thread - Android Logcat Thread text format
    logcat-threadtime - Android Logcat Threadtime text format
    logcat-time - Android Logcat Time text format
    modpcap - Modified tcpdump - pcap
    netmon1 - Microsoft NetMon 1.x
    netmon2 - Microsoft NetMon 2.x
    nettl - HP-UX nettl trace
    ngsniffer - Sniffer (DOS)
    ngwsniffer_1_1 - NetXray, Sniffer (Windows) 1.1
    ngwsniffer_2_0 - Sniffer (Windows) 2.00x
    nokiapcap - Nokia tcpdump - pcap
    nsecpcap - Wireshark/tcpdump/... - nanosecond pcap
    nstrace10 - NetScaler Trace (Version 1.0)
    nstrace20 - NetScaler Trace (Version 2.0)
    nstrace30 - NetScaler Trace (Version 3.0)
    nstrace35 - NetScaler Trace (Version 3.5)
    observer - Viavi Observer
    rf5 - Tektronix K12xx 32-bit .rf5 format
    rh6_1pcap - RedHat 6.1 tcpdump - pcap
    snoop - Sun snoop
    suse6_3pcap - SuSE 6.3 tcpdump - pcap
    visual - Visual Networks traffic capture
```    

### Print frame.number

``` bash
tshark -i any -V -T fields -e frame.number
1
2
3
4
5
6
7
8
9
10
11
```

### Set the format of the output when viewing decoded packet data

* tshark -V is just an example how to use it

|Command | Description |
|--------|-------------|
|`tshark -T fields -V`     | The values of fields specified with the -e option, in a form specified by the -E option.
|`tshark -T pdml -e -V`    | Packet Details Markup Language, an XML-based format for the details of a decoded packet.
|`tshark -T ps  -e -V`     | PostScript for a human-readable one-line summary of each of the packets
|`tshark -T psml -e -V`    | Packet Summary Markup Languag
|`tshark -T json -e  -V`   | Packet Summary, an JSON-based format
|`tshark -T jsonraw -V`    | Packet Details, a JSON-based format for machine parsing
|`tshark -T text  -V`      | Text of a human-readable one-line summary (default)
|`tshark -T tabs  -V`      | Similar to the text report except that each column of the human-readable one-line summary

jsonraw JSON file format including only raw hex-encoded packet data.  It can be used
with -j including or -J the JSON filter flag.  Example of usage:

```bash
tshark -T jsonraw -r fish_hunting.pcap
tshark -T jsonraw -j "http tcp ip" -x -r fish_hunting
```
### Well-Known mac addresses

<details>
  <summary>expand me for details</summary>

```
# Well-known addresses.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald [AT] wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The data below has been assembled from the following sources:
#
# Michael Patton's "Ethernet Codes Master Page" available from:
# <http://www.cavebear.com/CaveBear/Ethernet/>
# <ftp://ftp.cavebear.com/pub/Ethernet.txt>
#
# Microsoft Windows 2000 Server
# Operating System
# Network Load Balancing Technical Overview
# White Paper
#
00-00-00-00-FE-21       Checkpoint-Uninitialized-Cluster-Member
00-00-0C-07-AC/40       All-HSRP-routers
00-00-5E-00-01/40       IETF-VRRP-VRID
00-0C-0C-0C-0C-0C       Cisco-ACI-Gleaning-Leaf
00-0D-0D-0D-0D-0D       Cisco-ACI-Gleaning-Spine
00-BF-00-00-00-00/16    MS-NLB-VirtServer
00-E0-2B-00-00-00       Extreme-EDP
# Extreme Encapsulation Protocol (basically EDP renamed)
00-E0-2B-00-00-01       Extreme-EEP
00-E0-2B-00-00-02       Extreme-ESRP-Client
00-E0-2B-00-00-04       Extreme-EAPS
00-E0-2B-00-00-06       Extreme-EAPS-SL
00-E0-2B-00-00-08       Extreme-ESRP-Master
01-00-0C-00-00/40       ISL-Frame
01-00-0C-CC-CC-CC       CDP/VTP/DTP/PAgP/UDLD
01-00-0C-CC-CC-CD       PVST+
01-00-0C-CD-CD-CD       STP-UplinkFast
01-00-0C-CD-CD-CE       VLAN-bridge
01-00-0C-CD-CD-D0       GBPT
01-00-0C-DD-DD-DD       CGMP
01-00-10-00-00-20       Hughes-Lantshark  -z smb,srt -V -T text-Systems-Terminal-Server-S/W-download
01-00-10-FF-FF-20       Hughes-Lan-Systems-Terminal-Server-S/W-request
01-00-1D-00-00-00       Cabletron-PC-OV-PC-discover-(on-demand)
01-00-1D-00-00-05       Cabletron-PVST-BPDU
01-00-1D-00-00-06       Cabletron-QCSTP-BPDU
01-00-1D-42-00-00       Cabletron-PC-OV-Bridge-discover-(on-demand)
01-00-1D-52-00-00       Cabletron-PC-OV-MMAC-discover-(on-demand)
01-00-3C                Auspex-Systems-(Serverguard)
01-00-5E/25             IPv4mcast
01-00-81-00-00-00       Nortel-Network-Management
01-00-81-00-00-02       Nortel-Network-Management
01-00-81-00-01-00       Nortel-autodiscovery
01-00-81-00-01-01       Nortel-autodiscovery
# Cisco Fabric Path
01-0F-FF-C1-01-C0       FP-Flood-to-all-VLANs
01-0F-FF-C1-02-C0       FP-Flood-to-all-Fabrics
#
# As per
#
#       http://www.t11.org/ftp/t11/pub/fc/bb-5/08-334v0.pdf
#
# Broadcom "donated" one of their OUIs, 00-10-18, for use for
# Fibre Channel over Ethernet, so we add entries for the
# addresses in that document and a group of addresses for all
# otherwise unlisted 01-10-18-XX-XX-XX addresses.
#
01-10-18-01-00-00       All-FCoE-MACs
01-10-18-01-00-01       All-ENode-MACs
01-10-18-01-00-02       All-FCF-MACs
01-10-18-00-00-00/24    FCoE-group
01-11-1E-00-00-01       EPLv2_SoC
01-11-1E-00-00-02       EPLv2_PRes
01-11-1E-00-00-03       EPLv2_SoA
01-11-1E-00-00-04       EPLv2_ASnd
01-11-1E-00-00-05       EPLv2_AMNI
01-20-25/25             Control-Technology-Inc's-Industrial-Ctrl-Proto.
01-80-24-00-00-00       Kalpana-Ettshark  -z smb,srt -V -T textherswitch-every-60-seconds
# IEEE 802.1Q-2018 Table 8-1, C-VLAN and MAC Bridge component Reserved addresses
01-80-C2-00-00-00/44    Spanning-tree-(for-bridges)
# 01-80-C2-00-00-00     also: Nearest customer bridge
01-80-C2-00-00-01       MAC-specific-ctrl-proto-01
01-80-C2-00-00-02       Slow-Protocols
01-80-C2-00-00-03       Nearest-non-TPMR-bridge
01-80-C2-00-00-04       MAC-specific-ctrl-proto-04
01-80-C2-00-00-05       Reserved-future-std-05
01-80-C2-00-00-06       Reserved-future-std-06
01-80-C2-00-00-07       MEF-Forum-ELMI-proto
01-80-C2-00-00-08       Provider-Bridge
01-80-C2-00-00-09       Reserved-future-std-09
01-80-C2-00-00-0A       Reserved-future-std-0a
01-80-C2-00-00-0B       EDE-SS-PEP
01-80-C2-00-00-0C       Reserved-future-std-0c
01-80-C2-00-00-0D       Provider-Bridge-MVRP
01-80-C2-00-00-0E       LLDP_Multicast
01-80-C2-00-00-0F       Reserved-future-std-0f
01-80-C2-00-00-10       Bridge-Management
01-80-C2-00-00-11       Load-Server
01-80-C2-00-00-12       Loadable-Device
01-80-C2-00-00-13       IEEE-1905.1-Control
01-80-C2-00-00-14       ISIS-all-level-1-IS's
01-80-C2-00-00-15       ISIS-all-level-2-IS's
01-80-C2-00-00-18       IEEE-802.1B-All-Manager-Stations
01-80-C2-00-00-19       IEEE-802.11aa-groupcast-with-retries
01-80-C2-00-00-1A       IEEE-802.1B-All-Agent-Stations
01-80-C2-00-00-1B       ESIS-all-multicast-capable-ES's
01-80-C2-00-00-1C       ESIS-all-multicast-announcements
01-80-C2-00-00-1D       ESIS-all-multicast-capable-IS's
01-80-C2-00-00-1E       Token-Ring-all-DTR-Concentrators
01-80-C2-00-00-30/45    OAM-Multicast-DA-Class-1
01-80-C2-00-00-38/45    OAM-Multicast-DA-Class-2
01-80-C2-00-00-40       All-RBridges
01-80-C2-00-00-41       All-IS-IS-RBridges
01-80-C2-00-00-42       All-Egress-RBridges
01-80-C2-00-00-45       TRILL-End-Stations
01-80-C2-00-00-46       All-Edge-RBridges
01-80-C2-00-01-00       FDDI-RMT-Directed-Beacon
01-80-C2-00-01-10       FDDI-status-report-frame
01-DD-00-FF-FF-FF       Ungermann-Bass-boot-me-requests
01-DD-01-00-00-00       Ungermann-Bass-Spanning-Tree
01-E0-52-CC-CC-CC       Foundry-DP
# DOCSIS, defined in ANSI SCTE 22-1 2012
01-E0-2F-00-00-01       DOCSIS-CM
01-E0-2F-00-00-02       DOCSIS-CMTS
01-E0-2F-00-00-03       DOCSIS-STP

# Extremenetworks in their infinite wisdom seems to use 02-04-94 (Vendor MAC XOR 02-00-00)
# for their base mac address, thus colliding with MS-NLB 02-04/16 which Microsoft in their
# infinite wisdom decided to use for MS-NLB.
02-04-96-00-00-00/24    ExtremeNetworks

# Microsoft Network Load Balancing (NLB)
# Actually, 02-01-virtualip to 02-20-virtualip will be used from server to rest-of-world
# 02-bf-virtualip will be used from rest-of-world to server
02-BF-00-00-00-00/16    MS-NLB-VirtServer
02-01-00-00-00-00/16    MS-NLB-PhysServer-01
02-02-00-00-00-00/16    MS-NLB-PhysServer-02
02-03-00-00-00-00/16    MS-NLB-PhysServer-03
02-04-00-00-00-00/16    MS-NLB-PhysServer-04
02-05-00-00-00-00/16    MS-NLB-PhysServer-05
02-06-00-00-00-00/16    MS-NLB-PhysServer-06
02-07-00-00-00-00/16    MS-NLB-PhysServer-07
02-08-00-00-00-00/16    MS-NLB-PhysServer-08
02-09-00-00-00-00/16    MS-NLB-PhysServer-09
02-0a-00-00-00-00/16    MS-NLB-PhysServer-10
02-0b-00-00-00-00/16    MS-NLB-PhysServer-11
02-0c-00-00-00-00/16    MS-NLB-PhysServer-12
02-0d-00-00-00-00/16    MS-NLB-PhysServer-13
02-0e-00-00-00-00/16    MS-NLB-PhysServer-14
02-0f-00-00-00-00/16    MS-NLB-PhysServer-15
02-10-00-00-00-00/16    MS-NLB-PhysServer-16
02-11-00-00-00-00/16    MS-NLB-PhysServer-17
02-12-00-00-00-00/16    MS-NLB-PhysServer-18
02-13-00-00-00-00/16    MS-NLB-PhysServer-19
02-14-00-00-00-00/16    MS-NLB-PhysServer-20
02-15-00-00-00-00/16    MS-NLB-PhysServer-21
02-16-00-00-00-00/16    MS-NLB-PhysServer-22
02-17-00-00-00-00/16    MS-NLB-PhysServer-23
02-18-00-00-00-00/16    MS-NLB-PhysServer-24
02-19-00-00-00-00/16    MS-NLB-PhysServer-25
02-1a-00-00-00-00/16    MS-NLB-PhysServer-26
02-1b-00-00-00-00/16    MS-NLB-PhysServer-27
02-1c-00-00-00-00/16    MS-NLB-PhysServer-28
02-1d-00-00-00-00/16    MS-NLB-PhysServer-29
02-1e-00-00-00-00/16    MS-NLB-PhysServer-30
02-1f-00-00-00-00/16    MS-NLB-PhysServer-31
02-20-00-00-00-00/16    MS-NLB-PhysServer-32

#       [ The following block of addresses (03-...) are used by various ]
#       [ standards.  Some (marked [TR?]) are suspected of only being   ]
#       [ used on Token Ring for group addresses of Token Ring specific ]
#       [ functions, reference ISO 8802-5:1995 aka. IEEE 802.5:1995 for ]
#       [ some info.  These in the Ethernet order for this list.  On    ]
#       [ Token Ring they appear reversed.  They should never appear on ]
#       [ Ethernet.  Others, not so marked, are normal reports (may be  ]
#       [ seen on either).
03-00-00-00-00-01       NETBIOS-# [TR?]
03-00-00-00-00-02       Locate-Directory-Server # [TR?]
03-00-00-00-00-04       Synchronous-Bandwidth-Manager-# [TR?]
03-00-00-00-00-08       Configuration-Report-Server-# [TR?]
03-00-00-00-00-10       Ring-Error-Monitor-# [TR?]
03-00-00-00-00-10       (OS/2-1.3-EE+Communications-Manager)
03-00-00-00-00-20       Network-Server-Heartbeat-# [TR?]
03-00-00-00-00-40       (OS/2-1.3-EE+Communications-Manager)
03-00-00-00-00-80       Active-Monitor # [TR?]
03-00-00-00-01-00       OSI-All-IS-Token-Ring-Multicast
03-00-00-00-02-00       OSI-All-ES-Token-Ring-Multicast
03-00-00-00-04-00       LAN-Manager # [TR?]
03-00-00-00-08-00       Ring-Wiring-Concentrator # [TR?]
03-00-00-00-10-00       LAN-Gateway # [TR?]
03-00-00-00-20-00       Ring-Authorization-Server # [TR?]
03-00-00-00-40-00       IMPL-Server # [TR?]
03-00-00-00-80-00       Bridge # [TR?]
03-00-00-20-00-00       IP-Token-Ring-Multicast (RFC1469)
03-00-00-80-00-00       Discovery-Client
03-00-0C-00-00/40       ISL-Frame [TR?]
03-00-C7-00-00-EE       HP (Compaq) ProLiant NIC teaming
03-00-FF-FF-FF-FF       All-Stations-Address
03-BF-00-00-00-00/16    MS-NLB-VirtServer-Multicast
09-00-07-00-00-00/40    AppleTalk-Zone-multicast-addresses
                        # only goes through 09-00-07-00-00-FC?
09-00-07-FF-FF-FF       AppleTalk-broadcast-address
09-00-09-00-00-01       HP-Probe
09-00-09-00-00-04       HP-DTC
09-00-0D-00-00-00/24    ICL-Oslan-Multicast
09-00-0D-02-00-00       ICL-Oslan-Service-discover-only-on-boot
09-00-0D-02-0A-38       ICL-Oslan-Service-discover-only-on-boot
09-00-0D-02-0A-39       ICL-Oslan-Service-discover-only-on-boot
09-00-0D-02-0A-3C       ICL-Oslan-Service-discover-only-on-boot
09-00-0D-02-FF-FF       ICL-Oslan-Service-discover-only-on-boot
09-00-0D-09-00-00       ICL-Oslan-Service-discover-as-required
09-00-1E-00-00-00       Apollo-DOMAIN
09-00-2B-00-00-00       DEC-MUMPS?
09-00-2B-00-00-01       DEC-DSM/DDP
09-00-2B-00-00-02       DEC-VAXELN?
09-00-2B-00-00-03       DEC-Lanbridge-Traffic-Monitor-(LTM)
09-00-2B-00-00-04       DEC-MAP-(or-OSI?)-End-System-Hello?
09-00-2B-00-00-05       DEC-MAP-(or-OSI?)-Intermediate-System-Hello?
09-00-2B-00-00-06       DEC-CSMA/CD-Encryption?
09-00-2B-00-00-07       DEC-NetBios-Emulator?
09-00-2B-00-00-0F       DEC-Local-Area-Transport-(LAT)
09-00-2B-00-00-10/44    DEC-Experitshark  -z smb,srt -V -T textmental
09-00-2B-01-00-00       DEC-LanBridge-Copy-packets-(All-bridges)
09-00-2B-01-00-01       DEC-LanBridge-Hello-packets-(All-local-bridges)
09-00-2B-02-00-00       DEC-DNA-Level-2-Routing-Layer-routers?
09-00-2B-02-01-00       DEC-DNA-Naming-Service-Advertisement?
09-00-2B-02-01-01       DEC-DNA-Naming-Service-Solicitation?
09-00-2B-02-01-09       DEC-Availability-Manager-for-Distributed-Systems-DECamds
09-00-2B-02-01-02       DEC-Distributed-Time-Service
09-00-2B-03-00-00/32    DEC-default-filtering-by-bridges?
09-00-2B-04-00-00       DEC-Local-Area-System-Transport-(LAST)?
09-00-2B-23-00-00       DEC-Argonaut-Console?
09-00-4C-00-00-00       BICC-802.1-management
09-00-4C-00-00-02       BICC-802.1-management
09-00-4C-00-00-06       BICC-Local-bridge-STA-802.1(D)-Rev6
09-00-4C-00-00-0C       BICC-Remote-bridge-STA-802.1(D)-Rev8
09-00-4C-00-00-0F       BICC-Remote-bridge-ADAPTIVE-ROUTING
09-00-56-FF-00-00/32    Stanford-V-Kernel,-version-6.0
09-00-6A-00-01-00       TOP-NetBIOS.
09-00-77-00-00-00       Retix-Bridge-Local-Management-System
09-00-77-00-00-01       Retix-spanning-tree-bridges
09-00-77-00-00-02       Retix-Bridge-Adaptive-routing
09-00-7C-01-00-01       Vitalink-DLS-Multicast
09-00-7C-01-00-03       Vitalink-DLS-Inlink
09-00-7C-01-00-04       Vitalink-DLS-and-non-DLS-Multicast
09-00-7C-02-00-05       Vitalink-diagnostics
09-00-7C-05-00-01       Vitalink-gateway?
09-00-7C-05-00-02       Vitalink-Network-Validation-Message
09-00-87-80-FF-FF       Xyplex-Terminal-Servers
09-00-87-90-FF-FF       Xyplex-Terminal-Servers
0C-00-0C-00-00/40       ISL-Frame
0D-1E-15-BA-DD-06       HP
20-52-45-43-56-00/40    Receive
20-53-45-4E-44-00/40    Send
33-33-00-00-00-00       IPv6-Neighbor-Discovery
33-33-00-00-00-00/16    IPv6mcast
AA-00-03-00-00-00/32    DEC-UNA
AA-00-03-01-00-00/32    DEC-PROM-AA
AA-00-03-03-00-00/32    DEC-NI20
AB-00-00-01-00-00       DEC-MOP-Dump/Load-Assistance
AB-00-00-02-00-00       DEC-MOP-Remote-Console
AB-00-00-03-00-00       DECNET-Phase-IV-end-node-Hello-packets
AB-00-00-04-00-00       DECNET-Phase-IV-Router-Hello-packets
AB-00-03-00-00-00       DEC-Local-Area-Transport-(LAT)-old
AB-00-04-01-00-00/32    DEC-Local-Area-VAX-Cluster-groups-SCA
CF-00-00-00-00-00       Ethernet-Configuration-Test-protocol-(Loopback)
FF-FF-00-60-00-04       Lantastic
FF-FF-00-40-00-01       Lantastic
FF-FF-01-E0-00-04       Lantastic

FF-FF-FF-FF-FF-FF       Broadcast
```
</details>

 
### Sample pcaps is available from below url:

* Source: wireshark's wiki
 
https://wiki.wireshark.org/SampleCaptures

### Print tshark version

```bash
(02:39:29)-[wuseman@w] ~ $ tshark -v
TShark (Wireshark) 4.0.1 (Git commit e9f3970b1527).

Copyright 1998-2022 Gerald Comb <gerald@wireshark.org> and contributors.
Licensed under the terms of the GNU General Public License (version 2 or later).
This is free software; see the file named COPYING in the distribution. There is
NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) using `GCC 11.3.0`, with `GLib 2.74.1`, with PCRE2, with zlib
`1.2.13`, with libpcap, with `POSIX` capabilities (`Linux`), with `libnl 3`, without
`Lua`, with `GnuTLS 3.7.8`, with `Gcrypt 1.10.1-unknown`, without `Kerberos`, without
`MaxMind`, without `nghttp2`, without `brotli`, without `LZ`4, with `Zstandard`, without
`Snappy`, without `libxml2`, without `libsmi`, with binary plugins.

Running on `Linux 5.10.144-gentoo-x86_64`, with `Intel(R) Core(TM) i5-9500T CPU @
2.20GHz` (with `SSE4.2`), with `31316MB` of physical memory, with `GLib 2.74.1`, with
`PCRE2 10.40 2022-04-14`, with `zlib 1.2.13`, with `libpcap 1.10.1` (with `TPACKET_V3`),
with `c-ares 1.18.1`, with `GnuTLS 3.7.8`, with `Gcrypt 1.10.1-unknown`, with
`Zstandard 1.5.2`, with `LC_TYPE=en_US.utf8`, binary plugins supported.
```

### Shorter example for version

```bash
tshark --version|head -n1
TShark (Wireshark) 4.0.1 (Git commit e9f3970b1527).
```

### My personal install

![tshark](https://user-images.githubusercontent.com/26827453/201454078-e5c19d46-325b-4854-8f33-32c436720d7b.png)

### Gentoo Useflags(Description) 

|section/package[useflag] | useFlag Desription | 
|--------------------------|--------------| 
|app-emulation/crossover-bin[pcap] |  Support packet capture software (e.g. wireshark) |
|app-emulation/libvirt[wireshark-plugins] |  Build the net-analyzer/wireshark plugin for the Libvirt RPC protocol |
|app-emulation/wine-staging[pcap] |  Support packet capture software (e.g. wireshark) |
|app-emulation/wine-vanilla[pcap]|  Support packet capture software (e.g. wireshark) |
|net-analyzer/wireshark[androiddump] |  Install androiddump, an extcap interface to capture from Android devices |
|net-analyzer/wireshark[bcg729| ] Use media-libs/bcg729 for G.729 codec support in RTP Player |
|net-analyzer/wireshark[brotli] |  Use app-arch/brotli for compression/decompression |
|net-analyzer/wireshark[capinfos] |  Install capinfos, to print information about capture files |
|net-analyzer/wireshark[captype] |  Install captype, to print the file types of capture files |
|net-analyzer/wireshark[ciscodump] |  Install ciscodump, extcap interface to capture from a remote Cisco router |
|net-analyzer/wireshark[dftest] |  Install dftest, to display filter byte-code, for debugging dfilter routines |
|net-analyzer/wireshark[dpauxmon] |  Install dpauxmon, an external capture interface (extcap) that captures DisplayPort AUX channel data |
|net-analyzer/wireshark[dumpcap] |  Install dumpcap, to dump network traffic from inside wireshark |
|net-analyzer/wireshark[editcap] |  Install editcap, to edit and/or translate the format of capture files |
|net-analyzer/wireshark[http2] |  Use net-libs/nghttp2 for HTTP/2 support |
|net-analyzer/wireshark[ilbc] |  Build with iLBC support in RTP Player using media-libs/libilbc |
|net-analyzer/wireshark[libxml2] |  Use dev-libs/libxml2 for handling XML configuration in dissectors |
|net-analyzer/wireshark[lto] |  Enable link time optimization |
|net-analyzer/wireshark[maxminddb] |  Use dev-libs/libmaxminddb for IP address geolocation |
|net-analyzer/wireshark[mergecap] |  Install mergecap, to merge two or more capture files into one |
|net-analyzer/wireshark[minizip] |  Build with zip file compression support |
|net-analyzer/wireshark[netlink] |  Use dev-libs/libnl |
|net-analyzer/wireshark[pcap] |  Use net-libs/libpcap for network packet capturing (build dumpcap, rawshark) |
|net-analyzer/wireshark[plugin-ifdemo] |  Install plugin interface demo |
|net-analyzer/wireshark[plugins] |  Install plugins |
|net-analyzer/wireshark[qt6] |  Build with Qt6 support instead of the default Qt5 for GUI support |
|net-analyzer/wireshark[randpkt] |  Install randpkt, a utility for creating pcap trace files full of random packets |
|net-analyzer/wireshark[randpktdump] |  Install randpktdump, an extcap interface to provide access to the random packet generator (randpkt) |
|net-analyzer/wireshark[reordercap] |  Install reordercap, to reorder input file by timestamp into output file |
|net-analyzer/wireshark[sbc] | Use media-libs/sbc for playing back SBC encoded packets |
|net-analyzer/wireshark[sdjournal] |  Install sdjournal, an extcap that captures systemd journal entries |
|net-analyzer/wireshark[sharkd] |  Install sharkd, the daemon variant of wireshark |
|net-analyzer/wireshark[spandsp] | Use media-libs/spandsp for for G.722 and G.726 codec support in the RTP Player |
|net-analyzer/wireshark[smi] | Use net-libs/libsmi to resolve numeric OIDs into human readable format |
|net-analyzer/wireshark[spandsp] | Use media-libs/spandsp for for G.722 and G.726 codec support in the RTP Player |
|net-analyzer/wireshark[sshdump] | Install sshdump, an extcap interface to capture from a remote host through SSH |
|net-analyzer/wireshark[text2pcap] | Install text2pcap, to generate a capture file from an ASCII hexdump of packets |
|net-analyzer/wireshark[tfshark] | Install tfshark, a terminal-based version of the FileShark capability |
|net-analyzer/wireshark[tshark] | Install tshark, to dump and analyzer network traffic from the command line |
|net-analyzer/wireshark[udpdump] | Install udpdump, to get packets exported from a source (like a network device or a GSMTAP producer) that are dumped to a pcap file |
|net-analyzer/wireshark[wifi]  | Install wifidump, to dump and analyse 802.11 traffic |


 
### Display the contents of the second TCP stream (the first is stream 0) in "hex" format.
  
```bash
tshark -i any  -z "follow,tcp,hex,1"
```

### Capture in X seconds

```bash
tshark -i enp0s3 -a duration:120 -w /tmp/test_capture.pcap
```
  
### Capture in X minutes

```bash
tshark -i enp0s3 -a duration:120 -w /tmp/test_capture.pcap
```
  
* Similarly, if you don’t need your files to be extra-large, 
  filesize is a perfect flag to stop the process after some KB’s limits.

```bash
tshark -i enp0s3 -a filesize:50 -w /tmp/test_capture.pcap
```
  
### I have split my terminal into two screens to actively monitor the creation of three .pcap files.
  
```bash
tshark -i enp0s3 -f "port 53 or port 21" -b filesize:15 -a files:2 -w /tmp/test_capture.pcap
```
  
### Selecting Fields to Output:

```bash
tshark -r /tmp/test_capture.pcap -T fields -e frame.number -e ip.src -e ip.dst
```

###  Print all available fields

```bash
tshark -G|head -n 10|paste
P       Short Frame     _ws.short
P       Malformed Packet        _ws.malformed
P       Unreassembled Fragmented Packet _ws.unreassembled
F       Dissector bug   _ws.malformed.dissector_bug     FT_NONE _ws.malformed           0x0
F       Reassembly error        _ws.malformed.reassembly        FT_NONE _ws.malformed           0x0
F       Malformed Packet (Exception occurred)   _ws.malformed.expert    FT_NONE _ws.malformed           0x0
```

###  Find all subfields of a protocol

```bash
tshark -G | grep -E "http\.response\."
F       Response line   http.response.line      FT_STRING       http            0x0
F       Response Version        http.response.version   FT_STRING       http            0x0     HTTP Response HTTP-Version
F       Status Code     http.response.code      FT_UINT16       http    BASE_DEC        0x0     HTTP Response Status Code
F       Status Code Description http.response.code.desc FT_STRING       http            0x0     HTTP Response Status Code Description
F       Response Phrase http.response.phrase    FT_STRING       http            0x0     HTTP Response Reason Phrase
```
### If you’re looking for any frames that match an OUI `00:91:e1`, there are a couple ways of doing this.

* [Source - Packet hunting](https://tshark.dev/analyze/packet_hunting/packet_hunting/)

```bash
tshark -r $file -Y "eth.addr contains 00:91:e1"
tshark -r $file -Y "eth.addr[0:3] == 00:91:e1"
tshark -r $file -Y "eth.addr matches \"^[^\x01-\xff]\x16\xe3
```

### Search for a URL with regex

```bash
tshark -r hunting_fish.pcap -Y "frame matches \"https?.*?\.ru.*?worm\""
```

### The following tshark command captures 500 network packets and then stop
```bash
tshark -i any -c 500
```
  
### Exporting Data
  
Imagine you want to extract the frame number, the relative time of the frame,
he source IP address, the destination IP address, the protocol of the packet 
and the length of the network packet from previously captured network traffic. 

The `-E header=y` option tells tshark first to print a header line. The `-E quote=n` dictates that 
tshark not include the data in quotes, and the `-E occurrence=f` tells tshark to use only the 
first occurrence for fields that have multiple occurrences.


```bash
tshark -r hunting_newbies.tcpdump -T fields -e frame.number -e 
    frame.time_relative -e ip.src -e ip.dst -e 
    rame.protocols -e frame.len -E header=y -E 
    quote=n -E occurrence=f
```

Having plain text as output means that you easily can process it the `UNIX`way.
The following command shows the ten most popular IPs using input from the `ip.src field`:

```bash
 tshark -r ~/netData.pcap -T fields -e ip.src | sort 
    |sed '/^\s*$/d' | uniq -c | sort -rn
    |awk {'print $2 " " $1'} | head
```

### Find icmp package sent from our server

* Try

```bash
nmap -sP 192.168.0.0/24
```

* Then find total number of ICMP packets sent can be found with the help of the following command:

```bash
tshark -r nmap.pcap -R "icmp" | grep "2.x" | wc -l
```
### Extract referer
```bash
tshark -r fishing_for_threats.pcap \
    -T fields -e http.file_data http.response_number eq 1 and tcp.stream eq 4
```
  
### Extract data from mulitple interfaces
  
```bash 
tshark -i enp0s3 -i usbmon1 -i lo
```

### Saving Captured Traffic to a File:

```
tshark -i any -w /tmp/some_capture.pcap
```

### Automatically reset internal session when reached to specified number of packets, this example  will reset session every 100000 packets.

```
tshark -M 100000
```

### Find referers for a prefered domain

```bash
tshark -r fishing_for_threats.pcap 'http.referer == "http://www.facebook.com/"'
```
  
```bash
tshark -z <any_option_below>
     afp,srt
     ancp,tree
     ansi_a,bsmap
     ansi_a,dtap
     ansi_map
     asap,stat
     bacapp_instanceid,tree
     bacapp_ip,tree
     bacapp_objectid,tree
     bacapp_service,tree
     calcappprotocol,stat
     camel,counter
     camel,srt
     collectd,tree
     componentstatusprotocol,stat
     conv,bluetooth
     conv,dccp
     conv,eth
     conv,fc
     conv,fddi
     conv,ip
     conv,ipv6
     conv,ipx
     conv,jxta
     conv,mptcp
     conv,ncp
     conv,opensafety
     conv,rsvp
     conv,sctp
     conv,sll
     conv,tcp
     conv,tr
     conv,udp
     conv,usb
     conv,wlan
     conv,wpan
     conv,zbee_nwk
     credentials
     dcerpc,srt
     dests,tree
     dhcp,stat
     diameter,avp
     diameter,srt
     dns,tree
     endpoints,bluetooth
     endpoints,dccp
     endpoints,eth
     endpoints,fc
     endpoints,fddi
     endpoints,ip
     endpoints,ipv6
     endpoints,ipx
     endpoints,jxta
     endpoints,mptcp
     endpoints,ncp
     endpoints,opensafety
     endpoints,rsvp
     endpoints,sctp
     endpoints,sll
     endpoints,tcp
     endpoints,tr
     endpoints,udp
     endpoints,usb
     endpoints,wlan
     endpoints,wpan
     endpoints,zbee_nwk
     enrp,stat
     expert
     f1ap,tree
     f5_tmm_dist,tree
     f5_virt_dist,tree
     fc,srt
     flow,any
     flow,icmp
     flow,icmpv6
     flow,lbm_uim
     flow,tcp
     follow,dccp
     follow,http
     follow,http2
     follow,quic
     follow,sip
     follow,tcp
     follow,tls
     follow,udp
     fractalgeneratorprotocol,stat
     gsm_a
     gsm_a,bssmap
     gsm_a,dtap_cc
     gsm_a,dtap_gmm
     gsm_a,dtap_mm
     gsm_a,dtap_rr
     gsm_a,dtap_sacch
     gsm_a,dtap_sm
     gsm_a,dtap_sms
     gsm_a,dtap_ss
     gsm_a,dtap_tp
     gsm_map,operation
     gtp,srt
     h225,counter
     h225_ras,rtd
     hart_ip,tree
     hosts
     hpfeeds,tree
     http,stat
     http,tree
     http2,tree
     http_req,tree
     http_seq,tree
     http_srv,tree
     icmp,srt
     icmpv6,srt
     io,phs
     io,stat
     ip_hosts,tree
     ip_srcdst,tree
     ipv6_dests,tree
     ipv6_hosts,tree
     ipv6_ptype,tree
     ipv6_srcdst,tree
     isup_msg,tree
     lbmr_queue_ads_queue,tree
     lbmr_queue_ads_source,tree
     lbmr_queue_queries_queue,tree
     lbmr_queue_queries_receiver,tree
     lbmr_topic_ads_source,tree
     lbmr_topic_ads_topic,tree
     lbmr_topic_ads_transport,tree
     lbmr_topic_queries_pattern,tree
     lbmr_topic_queries_pattern_receiver,tree
     lbmr_topic_queries_receiver,tree
     lbmr_topic_queries_topic,tree
     ldap,srt
     mac-lte,stat
     megaco,rtd
     mgcp,rtd
     mtp3,msus
     ncp,srt
     ngap,tree
     npm,stat
     osmux,tree
     pingpongprotocol,stat
     plen,tree
     proto,colinfo
     ptype,tree
     radius,rtd
     rlc-lte,stat
     rpc,programs
     rpc,srt
     rtp,streams
     rtsp,stat
     rtsp,tree
     sametime,tree
     scsi,srt
     sctp,stat
     sip,stat
     smb,sids
     smb,srt
     smb2,srt
     smpp_commands,tree
     snmp,srt
     someip_messages,tree
     someipsd_entries,tree
     ssprotocol,stat
     sv
     ucp_messages,tree
     wsp,stat
```
  
### Show DHCP (BOOTP) statistics

```bash
tshark -z -z bootp,stat[,filter]
```

### Extract most important fields from diameter CC messages:

```bash
tshark -r fish_hunting.pcap -q \
  -z diameter,avp,272,CC-Request-Type,CC-Request-Number,Session-Id,Subscription-Id-Data,Rating-Group,Result-Code
```

### Print packet details 
  
```bash
  (03:09:25)-[wuseman@w] ~ $ tshark -i any -V
Capturing on 'any'
 ** (tshark:14467) 03:09:28.468543 [Main MESSAGE] -- Capture started.
 ** (tshark:14467) 03:09:28.468606 [Main MESSAGE] -- File: "/tmp/wireshark_anyDLD8U1.pcapng"
Frame 1: 672 bytes on wire (5376 bits), 672 bytes captured (5376 bits) on interface any, id 0
    Section number: 1
    Interface id: 0 (any)
        Interface name: any
    Encapsulation type: Linux cooked-mode capture v1 (25)
    Arrival Time: Nov 12, 2022 03:09:28.468475995 CET
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1668218968.468475995 seconds
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 672 bytes (5376 bits)
    Capture Length: 672 bytes (5376 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: sll:ethertype:ip:tcp:tls]
Linux cooked capture v1
    Packet type: Sent by us (4)
    Link-layer address type: zero header length (65534)
    Link-layer address length: 0
    Unused: 0000000000000000
    Protocol: IPv4 (0x0800)
Internet Protocol Version 4, Src: 10.66.211.zz, Dst: 23.195.249.zx
```

### Print pcap in IO/PHS

```
tshark -q -i any -qz "io,phs"
969 packets captured

===================================================================
Protocol Hierarchy Statistics
Filter: 

sll                                      frames:969 bytes:441356
  ip                                     frames:969 bytes:441356
    udp                                  frames:651 bytes:382155
      wg                                 frames:488 bytes:237104
      dns                                frames:46 bytes:5359
      data                               frames:117 bytes:139692
    tcp                                  frames:318 bytes:59201
      tls                                frames:92 bytes:45413
        tcp.segments                     frames:6 bytes:2159
===================================================================
```
### Print http data in a tree

```bash
tshark  -q -i any -Y http -z http,tree
```

```
=======================================================================================================================================
HTTP/Packet Counter:
Topic / Item            Count         Average       Min Val       Max Val       Rate (ms)     Percent       Burst Rate    Burst Start  
---------------------------------------------------------------------------------------------------------------------------------------
Total HTTP Packets      1                                                                     100%          0.0100        2.255        
 HTTP Request Packets   1                                                                     100.00%       0.0100        2.255        
  GET                   1                                                                     100.00%       0.0100        2.255        
 Other HTTP Packets     0                                                                     0.00%         -             -            
 HTTP Response Packets  0                                                                     0.00%         -             -            
  ???: broken           0                                                                                   -             -            
  5xx: Server Error     0                                                                                   -             -            
  4xx: Client Error     0                                                                                   -             -            
  3xx: Redirection      0                                                                                   -             -            
  2xx: Success          0                                                                                   -             -            
  1xx: Informational    0                                                                                   -             -            

---------------------------------------------------------------------------------------------------------------------------------------
```

* Example view (use -q for disable capture message)

https://user-images.githubusercontent.com/26827453/201450379-8d5361d5-9da0-4046-91c6-9fd30893091f.mp4

### Extraet user agents matching ....

```bash
tshark http.user_agent matches "^.{1,9}$"                 
```
###  Extract HTTP Requests
```
tshark tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' \
    -R 'http.request.method == "GET" || http.request.method == "HEAD"
```

### Log HTTP Request / Receive Headers
```bash
tshark tcp port 80 or tcp port 443 -V -R "http.request || http.response"
```


### Filter to identify all pages containing a certain string as any in below optins
```
tshark -i any -Y 'data-text-lines contains "javascript"'
```

```bash
tshark -i any -Y 'http.content_type == 'application/octet-stream"'
```

### Using packet filters

```bash
tshark -r network.pcap "http.request.method == POST" and "http.file_data contains password"
tshark -nr sagemcom_update.pcapng "http.request.method == POST" and "http.file_data contains guest"
```

### Extract all GET and POST requests

```bash
http.request.method == GET or http.request.method == POST        
```

### Extract GET or POST

 ```bash
 tshark -r foo.pcapng "http.request.method == GET or http.request.method == POST"
 1420 32.944563596 192.168.1.161 → 192.168.1.1  HTTP 681 GET /index.en-us.ui HTTP/1.1 
 1426 33.828088953 192.168.1.161 → 192.168.1.1  HTTP 709 GET /advanced/service_separation/index.en-us.ui HTTP/1.1 
 1524 39.845660076 192.168.1.161 → 192.168.1.1  HTTP 969 POST /advanced/service_separation/index.en-us.ui HTTP/1.1  (application/x-www-form-urlencoded)
 1528 40.102820143 192.168.1.161 → 192.168.1.1  HTTP 754 GET /advanced/service_separation/index.en-us.ui HTTP/1.1 
 1551 40.492695824 192.168.1.161 → 192.168.1.1  HTTP 675 GET /led_red.gif HTTP/1.1 
 1559 45.286211462 192.168.1.161 → 192.168.1.1  HTTP 709 GET /wireless/index.en-us.ui HTTP/1.1 
 1583 49.734826033 192.168.1.161 → 192.168.1.1  HTTP 689 GET /account/index.en-us.ui HTTP/1.1 
 1603 52.004119781 192.168.1.161 → 192.168.1.1  HTTP 689 GET /advanced/index.en-us.ui HTTP/1.1 
```


### Print available interfaces

```bash
tshark -D
1. eno1
2. cz5-wireguard
3. any
4. lo (Loopback)
5. bluetooth0
6. bluetooth-monitor
7. usbmon2
8. usbmon1
9. usbmon0
10. nflog
11. nfqueue
12. dbus-system
13. dbus-session
14. randpkt (Random packet generator)
15. udpdump (UDP Listener remote capture)
```

## Active Hunting 

### Threat Hunting with Live Network Traffic

```bash
tshark -i any 
```

### This command uses the traditional "pcap" filter to select what to capture from your interface.

```bash
tshark -f "host 192.168.1.12 and (dst port 80 or 443)"

```
### This command will help you to capture DNS traffic fo specific domain. (Here we have selected wuseman.se)

```bash
tshark -Y 'dns.qry.name=="wuseman.se"'
```
### This command will help you to capture all SSH traffic, except "192.168.1.2" IP-Address.

```bash
tshark -i eth0 -f "tcp port 22 and not src host 192.168.1.12"
```

### This command will extract only http request data from eth0 interface.
```bash
tshark -i eth0 -Y http.request -T fields -e http.host -e http.user_agent
```
### This command will extract source address, destination address, DNS request, DNS response from eth0 interface.
```bash
tshark -i eth0 \
    -f "src port 53" \
    -n \
    -T fields \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e dns.qry.name \
    -e dns.resp.addr


```
### This command will help you to extract only DHCP packets.
```bash
tshark -w dhcp_attack_hunt.pcap -f "port 67 or port 68" -i eth0 -P
```
### This command will help you to display UDP traffic of non-standard port with rage of 1045 – 10000.
```bash
tshark -i eth0 -Y "(tcp.dstport >= 1024 and tcp.dstport < 10000) or udp"
```
### This command will help you to hunt for client’s direct web access packets for local network.
```bash
tshark -i eth0 -Y "http.request.uri contains string(ip.dst)"
```
### This command will help you to capture TCP traffic for FIN flag.
```bash
tshark -i eth0 -Y "tcp.flags.fin==1"
```

### This command will help you to hunt the current mysql query statement in real time. (-R: Filter out mysql query statements)
```bash
tshark -s 512- i eth0 -n -f’tcp dst port 3306′ -R’mysql.query’ -T fields -e mysql.query
```
### This command will help you to hunt smpp protocol header and value
```bash
tshark \
    -r test.cap \
    -R'(smpp.command_id==0x80000004) and (smpp.command_status==0x0)’ \
    -e smpp.message_id -e frame.time -T fields -E header=y >test.txt
```
### This command will extract 200 packet and print out the visited URL
```bash
tshark -s 0 -i eth1 -n -f’tcp dst port 80′ -R’http.host and http.request.uri’ \
-T fields -e http.host -e http.request.uri -l -c 200
```
### This command will extract 200 packet and print out the visited SLL URL.
```bash
tshark -n -ta Fields -e ssl -T -R & lt "ip.src" -e "ssl.app_data" -e http.request.uri -l -c 200
```
### This command will help you to sniff HTTP
```bash
tshark ‘tcp port 80 and (((ip[2:2] – ((ip[0]&0xf)<<2)) – ((tcp[12]&0xf0)>>2)) != 0)’  \
-R ‘http.request.method == "GET" || http.request.method == "HEAD" || http.request.method == "POST"‘ 
```

### captures all port 110 traffic and filters out the ‘user’ command and saves it to a PCAP file
```bash
tshark -i 2 -f ‘port 110’ -R ‘pop.request.parameter contains ‘user" > /tmp/pop_hunting.pcap
```
### This command will display all packets coming from 192.168.4.51 except to 192.168.1.144 and have length less than 1800 bytes.

```bash
tshark -Y "ip.addr != 192.168.1.144 && ip.len < 1800" \ -Y "ip.src == 192.168.4.51"
```

## Passive Hunting 

##### Command to read PCAP file
```bash
tshark -r dns_port.pcap
```
### This command will help you to get details on protocol hierarchy statistics.
```bash
tshark -nr Network-Hunting.pcap -qz "io,phs"
```
### This command will help you hunt for statistics for a Specific Protocol. (Here we have selected HTTP protocol)
```bash
tshark -q -r Network-Hunting.pcap -Y http -z http,tree
```
### This command will help you to analyze the address and length of each of those IP packets as they occur on the network to which the computer running this command is
```bash
tshark -T fields -e frame.number -e ip.addr -e ip.len -r RDS.pcap
```
### Command will help you to hunt only TCP communications
```bash
tshark -r arp-storm.pcap -z conv,tcp
```
### This command will help you to hunt for all IP conversation.
```bash
tshark -r find_hackers06.pcap -z conv,ip
```
### List of packets with a specific source IP address from DNS captured PCAP.
```bash
tshark -r dns_port.pcap ip.host=="192.168.1.4″
```
### List of packets with a specific destination IP address from DNS captured PCAP.
```bash
tshark -r dns_port.pcap ip.dst=="192.168.1.4″
```
### This command will help you to extract fields source address and destination address.
```bash
tshark -r Malware-Traffic-hunting-1.pcap/malware-hunting.pcap -T fields -e ip.src -e ip.dst
```
### This command will help you to hunt for python user agent.
```bash
tshark -r Network-Hunting.pcap -T fields -e http.user_agent | grep python
```
### This command will give you the unique user-agent used for communications.
```bash
tshark -r Network-Hunting.pcap -T fields -e http.user_agent | sort | uniq
```
### Get packet details in tree format.
```bash
tshark -nr Network-Hunting.pcap -V
```
### This command will help you to hunt for source, destination and port details.
```bash
tshark -r hunting_fish.pcap -2 \
    -R "tcp.port==80″ \
    -E header=y \
    -E separator=/t \
    -e eth.src \
    -e ip.src \
    -e ip.dst \
    -T fields \
    -e tcp.port \
    -E aggregator="/s"
```
### This command will help you to get frame by frame details which contain PHP.
```bash
tshark -r 4-SL.pcap -2 -R "frame contains \"php\"" -V | more
```
### This command will help you to hunt for http portal based traffic. 
```bash
tshark -r find_hackers01.pcap -Y "http" | grep -i portal | more
```
### This command will help you to analyze referrer based traffic of Nr1.com domain.
```bash
tshark -r 10- find_hackers01.pcap  \
    -Y "http.referer == \"https:\/\nr1.nu\/p\/ find_hackers01\/\"" \
    -T fields -e "http.referer"
```

### Use -T fields & -e to identify which specific fields to print.
```bash
tshark -r Network-Hunting.pcap -T fields -e ip.src -e ip.dst ip.dst==192.168.1.10 | head
```

### This command will help you passively hunt to collect all source and destination
```bash
tshark -r /tmp/hacking_threat.pcap -T fields -e ip.src -e ip.dst \
    |awk -F " " ‘{print $1″\n"$2″\n"}’ | sort | uniq | grep -v "^$" > /tmp/passive_hunting.txt
```
### This command will help you to hunt for important fileds from PCAP
```bash
tshark \
    -r dns_port.pcap \±
    -T fields \
    -e frame.number \
    -e frame.encap_type \
    -e frame.protocols \
    -e frame.len \
    -e ip.addr \
    -E separator=, \
    -E quote=d > threats.csv
```
### This command will help you to analyze the request
```bash
tshark -2 -r proof_for_hackers.pcap \
    -R "http.request.line || http.file_data || http.response.line"  \
    -T fields -e http.request.line- e http.file_data -e http.response.line -E header=y
```

### This command will help you to hunt and extract most valuable field from network traffic captured PCAP file.
```bash
tshark -r find_hackers06.pcap \
    -T fields \
    -E header=y \
    -E separator=, \
    -E quote=d \
    -E occurrence=f \
    -e ip.src \
    -e ip.dst \
    -e ip.len \
    -e ip.flags.df \
    -e ip.flags.mf \
    -e ip.fragment \
    -e ip.fragment.count \
    -e ip.fragments \
    -e ip.ttl \
    -e ip.proto -e
```

## Resources

* [edit-cap manual](https://manpages.ubuntu.com/manpages/bionic/man1/editcap.1.html)
* [pcap-filter manual](https://manpages.ubuntu.com/manpages/bionic/man7/pcap-filter.7.html)
* [wireshark manual](https://manpages.ubuntu.com/manpages/bionic/man1/wireshark.1.html)
* [wireshark filter](https://manpages.ubuntu.com/manpages/bionic/man4/wireshark-filter.4.html)
* [tshark manual](https://manpages.ubuntu.com/manpages/bionic/man1/tshark.1.html)
* [threat hunting with tshark](https://hackforlab.com/threat-hunting-with-tshark/)
* [tshark examples](https://www.activecountermeasures.com/tshark-examples-theory-implementation/)
* [threat hunting](https://www.activecountermeasures.com/wp-content/uploads/2021/08/Network-Threat-Hunting-202108.pdf)
* [netowrk forensics](https://www.enisa.europa.eu/topics/training-and-exercises/trainings-for-cybersecurity-specialists/online-training-material/documents/network-forensics-toolset)
* [trickbot pcap.analysis](https://sanog.org/resources/sanog36/SANOG36-Tutorial_ThreatHunting_Hassan.pdf)
* [regular expressions in the "matches" operator are provided by GRegex in GLib](http://developer.gnome.org/glib/2.32/glib-regex-syntax.html/)
## Cheatsheet <small>author</small>

* wuseman [wuseman@nr1.nu](mailto:wuseman@nr1.nu)

## Wiki <small>License</small>

tshark nu wiki is licensed under the GNU General Public License v3.0 - See the [LICENSE.md](LICENSE.md) file for details

