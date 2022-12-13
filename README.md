<p align="center">
  <h1 align="center"># Hunting Fish with tshark</h1>
  <img src="https://user-images.githubusercontent.com/26827453/201454751-c8ccad1a-882f-4f73-b731-b9549892fd4b.png" />
</p>

* [Sample Captures](https://wiki.wireshark.org/SampleCaptures)
* [Packet Captures](https://packetlife.net/captures/)
* [Wireshark Bug Database ](https://bugs.wireshark.org/bugzilla/)
* [PCAP Table](https://tshark.dev/search/pcaptable/)


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
```

```bash
tshark -T jsonraw -j "http tcp ip" -x -r fish_hunting
```

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

![Screenshot_20221213_010934](https://user-images.githubusercontent.com/26827453/207190308-a0eaacd4-6ec6-4ace-869b-342665a0308a.png)

### Gentoo Useflags(Description) 

|section/package[useflag] | useFlag Desription | 
|--------------------------|--------------| 
|net-analyzer/wireshark[`androiddump`] |  Install androiddump, an extcap interface to capture from Android devices |
|net-analyzer/wireshark[`bcg729`| ] Use media-libs/bcg729 for G.729 codec support in RTP Player |
|net-analyzer/wireshark[`brotli`] |  Use app-arch/brotli for compression/decompression |
|net-analyzer/wireshark[`capinfos`] |  Install capinfos, to print information about capture files |
|net-analyzer/wireshark[`captype`] |  Install captype, to print the file types of capture files |
|net-analyzer/wireshark[`ciscodump`] |  Install ciscodump, extcap interface to capture from a remote Cisco router |
|net-analyzer/wireshark[`dftest`] |  Install dftest, to display filter byte-code, for debugging dfilter routines |
|net-analyzer/wireshark[`dpauxmon`] |  Install dpauxmon, an external capture interface (extcap) that captures DisplayPort AUX channel data |
|net-analyzer/wireshark[`dumpcap`] |  Install dumpcap, to dump network traffic from inside wireshark |
|net-analyzer/wireshark[`editcap`] |  Install editcap, to edit and/or translate the format of capture files |
|net-analyzer/wireshark[`http2`] |  Use net-libs/nghttp2 for HTTP/2 support |
|net-analyzer/wireshark[`ilbc`] |  Build with iLBC support in RTP Player using media-libs/libilbc |
|net-analyzer/wireshark[`libxml2`] |  Use dev-libs/libxml2 for handling XML configuration in dissectors |
|net-analyzer/wireshark[`lto]` |  Enable link time optimization |
|net-analyzer/wireshark[`maxminddb`] |  Use dev-libs/libmaxminddb for IP address geolocation |
|net-analyzer/wireshark[`mergecap`] |  Install mergecap, to merge two or more capture files into one |
|net-analyzer/wireshark[`minizip`] |  Build with zip file compression support |
|net-analyzer/wireshark[`netlink`] |  Use dev-libs/libnl |
|net-analyzer/wireshark[`pcap`] |  Use net-libs/libpcap for network packet capturing (build dumpcap, rawshark) |
|net-analyzer/wireshark[`plugin-ifdemo`] |  Install plugin interface demo |
|net-analyzer/wireshark[`plugins`] |  Install plugins |
|net-analyzer/wireshark[`qt6`] |  Build with Qt6 support instead of the default Qt5 for GUI support |
|net-analyzer/wireshark[`randpkt`] |  Install randpkt, a utility for creating pcap trace files full of random packets |
|net-analyzer/wireshark[`randpktdump`] |  Install randpktdump, an extcap interface to provide access to the random packet generator (randpkt) |
|net-analyzer/wireshark[`reordercap`] |  Install reordercap, to reorder input file by timestamp into output file |
|net-analyzer/wireshark[`sbc`] | Use media-libs/sbc for playing back SBC encoded packets |
|net-analyzer/wireshark[`sdjournal`] |  Install sdjournal, an extcap that captures systemd journal entries |
|net-analyzer/wireshark[`sharkd`] |  Install sharkd, the daemon variant of wireshark |
|net-analyzer/wireshark[`spandsp`]| Use media-libs/spandsp for for G.722 and G.726 codec support in the RTP Player |
|net-analyzer/wireshark[`smi`] | Use net-libs/libsmi to resolve numeric OIDs into human readable format |
|net-analyzer/wireshark[`spandsp`] | Use media-libs/spandsp for for G.722 and G.726 codec support in the RTP Player |
|net-analyzer/wireshark[`sshdump`] | Install sshdump, an extcap interface to capture from a remote host through SSH |
|net-analyzer/wireshark[`text2pcap`] | Install text2pcap, to generate a capture file from an ASCII hexdump of packets |
|net-analyzer/wireshark[`tfshark`] | Install tfshark, a terminal-based version of the FileShark capability |
|net-analyzer/wireshark[`tshark]` | Install tshark, to dump and analyzer network traffic from the command line |
|net-analyzer/wireshark[`udpdump`] | Install udpdump, to get packets exported from a source (like a network device or a GSMTAP producer) that are dumped to a pcap file |
|net-analyzer/wireshark[`wifi`]  | Install wifidump, to dump and analyse 802.11 traffic |



## Color output 

Color output text similarly to the Wireshark GUI, requires a terminal with 24-bit color support                          
Also supplies color attributes to pdml and psml formats (Note that attributes are nonstandard)

	tshark -i wlp2s0 --color

## Diagnostic output

### Sets the active log level ("critical", "warning", etc.)

	tshark --log-level <level>      

### Sets level to abort the program ("critical" or "warning")

	tshark --log-fatal <level>     

### Comma separated list of the active log domains 

	tshark --log-domains <[!]list> 

### Comma separated list of domains with "debug" level

	tshark --log-debug <[!]list>    

### comma separated list of domains with "noisy" level

	tshark --log-noisy <[!]list>    

### file to output messages to (in addition to stderr)

	tshark --log-file <path>        

### Ooutput format of seconds (def: s: seconds)

	tshark -u s|hms                 


## Display Filter Logical Operations


| English | C-like | Description    | Example                                                                  |
|---------|--------|----------------|--------------------------------------------------------------------------|
| and     | &&     | Logical AND    | ip.src==10.0.0.5 and tcp.flags.fin                                       |
| or      | ||     | Logical OR     | ip.src==10.0.0.5 or ip.src==192.1.1.1                                    |
| xor     | ^^     | Logical XOR    | tr.dst[0:3] == 0.6.29 xor tr.src[0:3] == 0.6.29                          |
| not     | !      | Logical NOT    | not llc                                                                  |
| […]     |        | Subsequence    | See “Slice Operator” below.                                              |
| in      |        | Set Membership | http.request.method in {"HEAD", "GET"}. See “Membership Operator” below. |

## Display Filter comparison operators


| English  | Alais  | C-like | Description                               | Example                                  |
|----------|--------|--------|-------------------------------------------|------------------------------------------|
| eq       | any_eq | ==     | Equal (any if more than one)              | ip.src == 10.0.0.5                       |
| ne       | all_ne | !=     | Not equal (all if more than one)          | ip.src != 10.0.0.5                       |
|          | all_eq | ===    | Equal (all if more than one)              | ip.src === 10.0.0.5                      |
|          | any_ne | !==    | Not equal (any if more than one)          | ip.src !== 10.0.0.5                      |
| gt       |        | >      | Greater than                              | frame.len > 10                           |
| lt       |        | <      | Less than                                 | frame.len < 128                          |
| ge       |        | >=     | Greater than or equal to                  | frame.len ge 0x100                       |
| le       |        | <=     | Less than or equal to                     | frame.len <= 0x20                        |
| contains |        |        | Protocol, field or slice contains a value | sip.To contains "a1762"                  |
| matches  |        | ~      | Perl-compatible regular expression        | http.host matches "acme\\.(org|com|net)" |



## Arithmetic operators


| Name           | Syntax | Description                 |
|----------------|--------|-----------------------------|
| Unary minus    | -A     | Negation of A               |
| Addition       | A + B  | Add B to A                  |
| Subtraction    | A - B  | Subtract B from A           |
| Multiplication | A * B  | Multiply A times B          |
| Division       | A / B  | Divide A by B               |
| Modulo         | A % B  | Remainder of A divided by B |
| Bitwise AND    | A & B  | Bitwise AND of A and B      |

## Display Filter Functions


| Function | Description                                         |
|----------|-----------------------------------------------------|
| upper    | Converts a string field to uppercase.               |
| lower    | Converts a string field to lowercase.               |
| len      | Returns the byte length of a string or bytes field. |
| count    | Returns the number of field occurrences in a frame. |
| string   | Converts a non-string field to a string.            |
| max      | Return the maximum value for the arguments.         |
| min      | Return the minimum value for the arguments.         |
| abs      | Return the absolute value for the argument.         |


### Finding Components of Protocols

	tshark -G | grep -E "sec_websocket_version"

###  Find all subfields of a protocol

```bash
tshark -G | grep -E "http\.response\."
F       Response line   http.response.line      FT_STRING       http            0x0
F       Response Version        http.response.version   FT_STRING       http            0x0     HTTP Response HTTP-Version
F       Status Code     http.response.code      FT_UINT16       http    BASE_DEC        0x0     HTTP Response Status Code
F       Status Code Description http.response.code.desc FT_STRING       http            0x0     HTTP Response Status Code Description
F       Response Phrase http.response.phrase    FT_STRING       http            0x0     HTTP Response Reason Phrase
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

### Capture from mulitple interfaces
  
```bash 
tshark -i enp0s3 -i usbmon1 -i lo
```

### The following tshark command captures 500 network packets and then stop
```bash
tshark -i any -c 500
```
 
### I have split my terminal into two screens to actively monitor the creation of three .pcap files.
  
```bash
tshark -i enp0s3 -f "port 53 or port 21" -b filesize:15 -a files:2 -w /tmp/test_capture.pcap
```
  
### Selecting Fields to Output:

```bash
tshark -r /tmp/test_capture.pcap -T fields -e frame.number -e ip.src -e ip.dst
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


### Find referers for a prefered domain

```bash
tshark -r fishing_for_threats.pcap 'http.referer == "http://www.facebook.com/"'
```

### Automatically reset internal session when reached to specified number of packets, this example  will reset session every 100000 packets.

```
tshark -M 100000
```


## Display Filters

### Show only SMTP (port 25) and ICMP traffic:

	tcp.port eq 25 or icmp

### Show only traffic in the LAN (192.168.x.x), between workstations and servers – no Internet:

	ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16

### TCP buffer full – Source is instructing Destination to stop sending data

	tcp.window_size == 0 && tcp.flags.reset != 1

### Filter on Windows – Filter out noise, while watching Windows Client - DC exchanges

	smb || nbns || dcerpc || nbss || dns

### Sasser worm: –What sasser really did–

	ls_ads.opnum==0x09

### Match packets

Match packets containing the (arbitrary) 3-byte sequence 0x81, 0x60, 0x03 at the beginning of the UDP payload, 
skipping the 8-byte UDP header. Note that the values for the byte sequence implicitly are in hexadecimal only. 
(Useful for matching homegrown packet protocols.)

	udp[8:3]==81:60:03

### Slice Feature

The "slice" feature is also useful to filter on the vendor identifier part (OUI) of the MAC address, 
see the Ethernet page for details. Thus you may restrict the display to only packets from a specific 
device manufacturer. E.g. for DELL machines only:

	eth.addr[0:3]==00:06:5B

### Match packets that contains the 3-byte sequence 0x81, 0x60, 0x03 anywhere in the UDP header or payload:

	udp contains 81:60:03

### Match packets where SIP To-header contains the string "a1762" anywhere in the header:

	sip.To contains "a1762"

### Match HTTP requests where the last characters in the uri are the characters "gl=se":

!!! Note "Note: The $ character is a PCRE punctuation character that matches the end of a string, in this case the end of http.request.uri field."

	http.request.uri matches "gl=se$"


### Filter by a protocol ( e.g. SIP ) and filter out unwanted IPs:

### ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip

## Layer operator
```bash
tshark -i wlp2s0 -Y 'ip.src#1 == 10.1.2.3
```

* Will match the outer address

```bash
tshark -i wlp2s0 -Y 'ip.src#2 == 10.1.2.3
```

* Will match the inner address, and will match either address.

```bash
ip.src == 10.1.2.3
```

### Operators

```
eq or ==
ne or !=
gt or >
lt or <
ge or >=
le or <=
```

### Logic

```
and or && Logical AND
or or || Logical OR
xor or ^^ Logical XOR
not or ! Logical NOT
[n] […] Substring operator
```

### ARP

```
arp.dst.hw_mac 
arp.proto.size
arp.dst.proto_ipv4 
arp.proto.type
arp.hw.size 
arp.src.hw_mac
arp.hw.type 
arp.src.proto_ipv4
arp.opcode
```

### Ethernet
```
eth.addr 
eth.len 
eth.src
eth.dst 
eth.lg 
eth.trailer
eth.ig
eth.multicast 
eth.type
```
### IEEE 802.1Q
```
vlan.cfi 
vlan.id 
vlan.priority
vlan.etype 
vlan.len 
vlan.trailer
```
### IPv4
```
ip.addr 
ip.fragment.overlap.conflict
ip.checksum 
ip.fragment.toolongfragment
ip.checksum_bad 
ip.fragments
ip.checksum_good 
ip.hdr_len
ip.dsfield 
ip.host
ip.dsfield.ce 
ip.id
ip.dsfield.dscp 
ip.len
ip.dsfield.ect 
ip.proto
ip.dst 
ip.reassembled_in
ip.dst_host 
ip.src
ip.flags 
ip.src_host
ip.flags.df 
ip.tos
ip.flags.mf 
ip.tos.cost
ip.flags.rb 
ip.tos.delay
ip.frag_offset 
ip.tos.precedence
ip.fragment 
ip.tos.reliability
ip.fragment.error 
ip.tos.throughput
ip.fragment.multipletails 
ip.ttl
ip.fragment.overlap 
ip.version
```
### IPv6
```
ipv6.addr 
ipv6.hop_opt
ipv6.class 
ipv6.host
ipv6.dst 
ipv6.mipv6_home_address
ipv6.dst_host 
ipv6.mipv6_length
ipv6.dst_opt 
ipv6.mipv6_type
ipv6.flow 
ipv6.nxt
ipv6.fragment 
ipv6.opt.pad1
ipv6.fragment.error 
ipv6.opt.padn
ipv6.fragment.more 
ipv6.plen
ipv6.fragment.multipletails 
ipv6.reassembled_in
ipv6.fragment.offset 
ipv6.routing_hdr
ipv6.fragment.overlap 
ipv6.routing_hdr.addr
ipv6.fragment.overlap.conflict 
ipv6.routing_hdr.left
ipv6.fragment.toolongfragment 
ipv6.routing_hdr.type
ipv6.fragments 
ipv6.src
ipv6.fragment.id 
ipv6.src_host
ipv6.hlim 
ipv6.version
```
### UDP
```
udp.checksum 
udp.dstport 
udp.srcport
udp.checksum_bad 
udp.length
udp.checksum_good 
udp.port
```
### TCP
```
tcp.ack 
tcp.options.qs
tcp.checksum 
tcp.options.sack
tcp.checksum_bad
tcp.options.sack_le
tcp.checksum_good
tcp.options.sack_perm
tcp.continuation_to 
tcp.options.sack_re
tcp.dstport 
tcp.options.time_stamp
tcp.flags 
tcp.options.wscale
tcp.flags.ack 
tcp.options.wscale_val
tcp.flags.cwr 
tcp.pdu.last_frame
tcp.flags.ecn 
tcp.pdu.size
tcp.flags.fin 
tcp.pdu.time
tcp.flags.push 
tcp.port
tcp.flags.reset 
tcp.reassembled_in
tcp.flags.syn 
tcp.segment
tcp.flags.urg 
tcp.segment.error
tcp.hdr_len 
tcp.segment.multipletails
tcp.len 
tcp.segment.overlap
tcp.nxtseq 
tcp.segment.overlap.conflict
tcp.options 
tcp.segment.toolongfragment
tcp.options.cc 
tcp.segments
tcp.options.ccecho 
tcp.seq
tcp.options.ccnew 
tcp.srcport
tcp.options.echo 
tcp.time_delta
tcp.options.echo_reply 
tcp.time_relative
tcp.options.md5 
tcp.urgent_pointer
tcp.options.mss 
tcp.window_size
tcp.options.mss_val
```


### Frame Relay

```
tshark -i wlp2s0 -Tfields -e fr.becn 
tshark -i wlp2s0 -Tfields -e fr.de
tshark -i wlp2s0 -Tfields -e fr.chdlctype 
tshark -i wlp2s0 -Tfields -e fr.dlci
tshark -i wlp2s0 -Tfields -e fr.control 
tshark -i wlp2s0 -Tfields -e fr.dlcore_control
tshark -i wlp2s0 -Tfields -e fr.control.f 
tshark -i wlp2s0 -Tfields -e fr.ea
tshark -i wlp2s0 -Tfields -e fr.control.ftype 
tshark -i wlp2s0 -Tfields -e fr.fecn
tshark -i wlp2s0 -Tfields -e fr.control.n_r 
tshark -i wlp2s0 -Tfields -e fr.lower_dlci
tshark -i wlp2s0 -Tfields -e fr.control.n_s 
tshark -i wlp2s0 -Tfields -e fr.nlpid
tshark -i wlp2s0 -Tfields -e fr.control.p 
tshark -i wlp2s0 -Tfields -e fr.second_dlci
tshark -i wlp2s0 -Tfields -e fr.control.s_ftype 
tshark -i wlp2s0 -Tfields -e fr.snap.oui
tshark -i wlp2s0 -Tfields -e fr.control.u_modifier_cmd 
tshark -i wlp2s0 -Tfields -e fr.snap.pid
tshark -i wlp2s0 -Tfields -e fr.control.u_modifier_resp 
tshark -i wlp2s0 -Tfields -e fr.snaptype
tshark -i wlp2s0 -Tfields -e fr.cr 
tshark -i wlp2s0 -Tfields -e fr.third_dlci
tshark -i wlp2s0 -Tfields -e fr.dc 
tshark -i wlp2s0 -Tfields -e fr.upper_dlci
```

### PPP

```
tshark -i wlp2s0 -Tfields -e ppp.address 
tshark -i wlp2s0 -Tfields -e ppp.direction
tshark -i wlp2s0 -Tfields -e ppp.control 
tshark -i wlp2s0 -Tfields -e ppp.protocol
```

### MPLS

```
tshark -i wlp2s0 -Tfields -e mpls.bottom 
tshark -i wlp2s0 -Tfields -e mpls.oam.defect_location
tshark -i wlp2s0 -Tfields -e mpls.cw.control 
tshark -i wlp2s0 -Tfields -e mpls.oam.defect_type
tshark -i wlp2s0 -Tfields -e mpls.cw.res 
tshark -i wlp2s0 -Tfields -e mpls.oam.frequency
tshark -i wlp2s0 -Tfields -e mpls.exp 
tshark -i wlp2s0 -Tfields -e mpls.oam.function_type
tshark -i wlp2s0 -Tfields -e mpls.label 
tshark -i wlp2s0 -Tfields -e mpls.oam.ttsi
tshark -i wlp2s0 -Tfields -e mpls.oam.bip16 
tshark -i wlp2s0 -Tfields -e mpls.ttl
```

### DTP

```
tshark -i wlp2s0 -Tfields -e dtp.neighbor 
tshark -i wlp2s0 -Tfields -e dtp.tlv_type 
tshark -i wlp2s0 -Tfields -e vtp.neighbor
tshark -i wlp2s0 -Tfields -e dtp.tlv_len 
tshark -i wlp2s0 -Tfields -e dtp.version
```

### VTP

```
tshark -i wlp2s0 -Tfields -e vtp.code 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.802_10_index
tshark -i wlp2s0 -Tfields -e vtp.conf_rev_num 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.isl_vlan_id
tshark -i wlp2s0 -Tfields -e vtp.followers 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.len
tshark -i wlp2s0 -Tfields -e vtp.md 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.mtu_size
tshark -i wlp2s0 -Tfields -e vtp.md5_digest
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.status.vlan_susp
tshark -i wlp2s0 -Tfields -e vtp.md_len 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.tlv_len
tshark -i wlp2s0 -Tfields -e vtp.seq_num 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.tlv_type
tshark -i wlp2s0 -Tfields -e vtp.start_value 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.vlan_name
tshark -i wlp2s0 -Tfields -e vtp.upd_id 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.vlan_name_len
tshark -i wlp2s0 -Tfields -e vtp.upd_ts 
tshark -i wlp2s0 -Tfields -e vtp.vlan_info.vlan_type
tshark -i wlp2s0 -Tfields -e vtp.version
```

### ICMPv4

```
tshark -i wlp2s0 -Tfields -e icmp.checksum 
tshark -i wlp2s0 -Tfields -e icmp.ident 
tshark -i wlp2s0 -Tfields -e icmp.seq
tshark -i wlp2s0 -Tfields -e icmp.checksum_bad 
tshark -i wlp2s0 -Tfields -e icmp.mtu 
tshark -i wlp2s0 -Tfields -e icmp.type
tshark -i wlp2s0 -Tfields -e icmp.code 
tshark -i wlp2s0 -Tfields -e icmp.redir_gw
```

### ICMPv6

```
tshark -i wlp2s0 -Tfields -e icmpv6.all_comp
tshark -i wlp2s0 -Tfields -e icmpv6.checksum
tshark -i wlp2s0 -Tfields -e icmpv6.option.name_type.fqdn
tshark -i wlp2s0 -Tfields -e icmpv6.option.name_x501
tshark -i wlp2s0 -Tfields -e icmpv6.checksum_bad
tshark -i wlp2s0 -Tfields -e icmpv6.code
tshark -i wlp2s0 -Tfields -e icmpv6.option.rsa.key_hash
tshark -i wlp2s0 -Tfields -e icmpv6.option.type
tshark -i wlp2s0 -Tfields -e icmpv6.comp
tshark -i wlp2s0 -Tfields -e icmpv6.haad.ha_addrs
tshark -i wlp2s0 -Tfields -e icmpv6.ra.cur_hop_limit
tshark -i wlp2s0 -Tfields -e icmpv6.ra.reachable_time
tshark -i wlp2s0 -Tfields -e icmpv6.identifier
tshark -i wlp2s0 -Tfields -e icmpv6.option
tshark -i wlp2s0 -Tfields -e icmpv6.ra.retrans_timer
tshark -i wlp2s0 -Tfields -e icmpv6.ra.router_lifetime
tshark -i wlp2s0 -Tfields -e icmpv6.option.cga
tshark -i wlp2s0 -Tfields -e icmpv6.option.length
tshark -i wlp2s0 -Tfields -e icmpv6.recursive_dns_serv
tshark -i wlp2s0 -Tfields -e icmpv6.type
tshark -i wlp2s0 -Tfields -e icmpv6.option.name_type
```

### RIP

```
tshark -i wlp2s0 -Tfields -e rip.auth.passwd 
tshark -i wlp2s0 -Tfields -e rip.ip 
tshark -i wlp2s0 -Tfields -e rip.route_tag
tshark -i wlp2s0 -Tfields -e rip.auth.type 
tshark -i wlp2s0 -Tfields -e rip.metric 
tshark -i wlp2s0 -Tfields -e rip.routing_domain
tshark -i wlp2s0 -Tfields -e rip.command 
tshark -i wlp2s0 -Tfields -e rip.netmask 
tshark -i wlp2s0 -Tfields -e rip.version
tshark -i wlp2s0 -Tfields -e rip.family 
tshark -i wlp2s0 -Tfields -e rip.next_hop
```

### BGP
```
bgp.aggregator_as 
tshark -i wlp2s0 -Tfields -e bgp.mp_reach_nlri_ipv4_prefix
tshark -i wlp2s0 -Tfields -e bgp.aggregator_origin 
tshark -i wlp2s0 -Tfields -e bgp.mp_unreach_nlri_ipv4_prefix
tshark -i wlp2s0 -Tfields -e bgp.as_path 
tshark -i wlp2s0 -Tfields -e bgp.multi_exit_disc
tshark -i wlp2s0 -Tfields -e bgp.cluster_identifier 
tshark -i wlp2s0 -Tfields -e bgp.next_hop
tshark -i wlp2s0 -Tfields -e bgp.cluster_list 
tshark -i wlp2s0 -Tfields -e bgp.nlri_prefix
tshark -i wlp2s0 -Tfields -e bgp.community_as 
tshark -i wlp2s0 -Tfields -e bgp.origin
tshark -i wlp2s0 -Tfields -e bgp.community_value 
tshark -i wlp2s0 -Tfields -e bgp.originator_id
tshark -i wlp2s0 -Tfields -e bgp.local_pref 
tshark -i wlp2s0 -Tfields -e bgp.type
tshark -i wlp2s0 -Tfields -e bgp.mp_nlri_tnl_id 
tshark -i wlp2s0 -Tfields -e bgp.withdrawn_prefix
```
### HTTP

```
tshark -i wlp2s0 -Tfields -e http.accept 
tshark -i wlp2s0 -Tfields -e http.proxy_authorization
tshark -i wlp2s0 -Tfields -e http.accept_encoding 
tshark -i wlp2s0 -Tfields -e http.proxy_connect_host
tshark -i wlp2s0 -Tfields -e http.accept_language 
tshark -i wlp2s0 -Tfields -e http.proxy_connect_port
tshark -i wlp2s0 -Tfields -e http.authbasic 
tshark -i wlp2s0 -Tfields -e http.referer
tshark -i wlp2s0 -Tfields -e http.authorization 
tshark -i wlp2s0 -Tfields -e http.request
tshark -i wlp2s0 -Tfields -e http.cache_control 
tshark -i wlp2s0 -Tfields -e http.request.method
tshark -i wlp2s0 -Tfields -e http.connection 
tshark -i wlp2s0 -Tfields -e http.request.uri
tshark -i wlp2s0 -Tfields -e http.content_encoding 
tshark -i wlp2s0 -Tfields -e http.content_length 
tshark -i wlp2s0 -Tfields -e http.response
tshark -i wlp2s0 -Tfields -e http.content_type 
tshark -i wlp2s0 -Tfields -e http.response.code
tshark -i wlp2s0 -Tfields -e http.request.version
tshark -i wlp2s0 -Tfields -e http.cookie 
tshark -i wlp2s0 -Tfields -e http.server
tshark -i wlp2s0 -Tfields -e http.date 
tshark -i wlp2s0 -Tfields -e http.set_cookie
tshark -i wlp2s0 -Tfields -e http.host 
tshark -i wlp2s0 -Tfields -e http.transfer_encoding
tshark -i wlp2s0 -Tfields -e http.last_modified 
tshark -i wlp2s0 -Tfields -e http.user_agent
tshark -i wlp2s0 -Tfields -e http.location 
tshark -i wlp2s0 -Tfields -e http.www_authenticate
tshark -i wlp2s0 -Tfields -e http.notification 
tshark -i wlp2s0 -Tfields -e http.x_forwarded_for
tshark -i wlp2s0 -Tfields -e http.proxy_authenticate
```
### Display the contents of the second TCP stream (the first is stream 0) in "hex" format.
  
```bash
tshark -i any  -z "follow,tcp,hex,1"
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

### Capture in X seconds

```bash
tshark -i enp0s3 -a duration:120 -w /tmp/test_capture.pcap
```
  
### Capture in X minutes

```bash
tshark -i enp0s3 -a duration:120 -w /tmp/test_capture.pcap
```

### Sample Capture File Types

    tshark -F 

### Field to print if -Tfields selected (e.g. tcp.port,_ws.col.Info) this option can be repeated to print multiple field

	tshark -Ffields -e tcp.port

### Start with specified configuration profile

	tshark -C ~tshark.conf

### Read a list of entries from a hosts file, which will then be written to a capture file. (Implies -W n)

	tshark -H /etc/hosts


### Enable specific name resolution(s): "mnNtdv"

	tshark -N

### Disable all name resolutions (def: "mNd" enabled, or as set in preferences)

    tshark -n

### Packet displaY filter in Wireshark display filter syntax

    tshark --display-filter

### Write packets to a pcapng-format file named "outfile" (or '-' for stdout)

    tshark -w foo.pcap

### Set the filename to read from (or '-' for stdin)

	tshark -r foo.pcap

### Capture in monitor mode, if available

    tshark -I 

### Print list of timestamp types for iface and exit 

	tshark --list-time-stamp-types

### Print list of link-layer types of iface and exit

	tshark -L

### List available interfaces

	tshark -D

### Sniff traffic from a specifik device

	tshark -i <interface_name>
	tshark -i <interface_number>

### Sniff HTTP GET Requests

	tshark -i wlp2s0 -Y 'http.request.method == "GET"'

### Sniff HTTP POST Requests

	tshark -i wlp2s0 -Y 'http.request.method == "GET"'

### Sniff HTTP PUT Requests

	tshark -i wlp2s0 -Y 'http.request.method == "PUT"'

### Sniff HTTP GET/POST and PUT Requests

	tshark -i wlp2s0 -Y 'http.request.method == "GET" or http.request.method == "POST" or http.request.method == "GET"'

### Sniff HTTP GET/POST and PUT Requests and use Fields and Text

	tshark -i wlp2s0 -Y 'http.request.method == "GET" or http.request.method == "POST" or http.request.method == "GET"' -Tfields -e text


### Extract referer
```bash
tshark -r fishing_for_threats.pcap \
    -T fields -e http.file_data http.response_number eq 1 and tcp.stream eq 4
```

### Extract user-agents

	tshark -i wlp2s0 -Y http.request -T fields -e http.user_agent 

### Let's get passwords.... in a HTTP post

	tshark -i wlan0 -Y 'http.request.method == POST and tcp contains "password"' | grep password

### Extract Files from PCAP using Tshark

    tshark -nr test.pcap --export-objects smb,tmpfolder

### This command will do the same except from HTTP, extracting all the files seen in the pcap.

	tshark -nr test.pcap --export-objects http,tmpfolder

### Capturing Specific Packets by Filter String

	tshark -i wlp2s0 -f "tcp port 22" -c 10

### Capture and display the first 10 filtered packets (-Y) related to the xx.xx.xx.xx IP address.

	tshark -i wlp2s0 -Y 'ip.addr == xx.xx.xx.xx' -c 10

### This command will help you to capture DNS traffic fo specific domain. (Here we have selected wuseman.se)

	tshark -Y 'dns.qry.name=="wuseman.se"'

### Reading packets with a specific host IP address. 

	tshark -r foo.pcap ip.host=="192.168.1.4"

### List of packets with a specific source IP address. 

	tshark -r foo.pcap ip.src=="192.168.1.4"

### List of packets with a specific destination IP address.

	tshark -r foo.pcap ip.dst=="192.168.1.4"

### Display UDP ports from this dhcp.pcap using rawshark. 

	tshark -r dhcp.pcap -w - | rawshark -s -r - -d proto:udp -F udp.port

### tshark is more useful with less work though, even if we pass in as a stream

	cat dhcp.pcap | tshark -r -

### Filters for Web-Based Infection Traffic

	tshark -i wlp2s0 -Y 'http.request or ssl.handshake.type == 1'
	tshark -i wlp2s0 -Y '(http.request or ssl.handshake.type == 1) and !(ssdp)'

### Filters for Other Types of Infection Traffic

	tshark -i wlp2s0 -Y '(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)'

###  Filtering on SMTP traffic in Wireshark when viewing spambot traffic.

In recent years, email traffic from spambots is most likely encrypted SMTP.  
However, you might find unencrypted SMTP traffic by searching for strings in common email header lines like:

```bash
tshark -i wlp2s0 -Y 'smtp contains "From: "'
```
```bash
tshark -i wlp2s0 -Y smtp contains "Message-ID: "
```

```bash
tshark -i wlp2s0 -Y smtp contains "Subject: "
```

### Examples of these filter expressions follow:

```bash
tshark -i wlp2s0 -Y 'ip.addr eq 192.168.10.195 and ip.addr == 192.168.10.1'
```
```bash
tshark -i wlp2s0 -Y 'http.request && ip.addr == 192.168.10.195'
```
```bash
tshark -i wlp2s0 -Y 'http.request || http.response'
```
```bash
tshark -i wlp2s0 -Y 'dns.qry.name contains microsoft or dns.qry.name contains windows'
```
### 2-pass analysis with -R, -Y, and -2

```bash
tshark -r foo.pcapng -R "arp" -2 -Y "frame.number == 5"
```

### Search for a URL with regex

!!! Warning "You cannot use the null character,\x00 when using matches because Wireshark uses null-terminated C-strings. Use [^\x01-\xff] instead.

You’re looking for an HTTP GET that contains a request for a URL that starts with `http` or `https`, 
has the Russian `.ru` domain, and contains the word `worm` in the query string. Luckily, 
Wireshark gives you matches which uses PCRE regex syntax. A simple one that satisfies this is 
`https?.*?\.ru.*?worm`. If this seems like greek, you can explore it on `regex101`.

Given that this is `GET`, it’s better to just search the ‘http’ protocol: http matches `https?.*?\.ru.*?worm` 
Note that the regex is double quoted. With tshark, `-Y` "display filter" also needs to be double-quoted. 
In order to use this display filter, escape the inner quotes

	tshark -r $file -Y "frame matches \"https?.*?\.ru.*?worm\""

### Search for a byte sequence

```bash
tshark -r $file -Y "eth.addr contains 00:16:e3"
```
```bash
tshark -r $file -Y "eth.addr[0:3] == 00:16:e3"
```
```bash
tshark -r $file -Y "eth.addr matches \"^[^\x01-\xff]\x16\xe3\""
```

## Dumpcat

```bash
dumpcap \
	-a duration:100 \
    -a files:10 \
    -a filesize:10000 \
    -a packets:10000 \
    -b duration:100 \
    -b files:1000 \
    -b filesize:1024 \
    -b packets:20 \
                       -w file.pcap \
```

### Activity from malware generating FTP traffic.

In addition to FTP, malware can use other common protocols for malicious traffic. 
Spambot malware can turn an infected host into a spambot designed to send dozens 
to hundreds of email messages every minute. This is characterized by several DNS 
requests to various mail servers followed by SMTP traffic on TCP ports 25, 465, 587, 
or other TCP ports associated with email traffic.

```bash
tshark -i wlp2s0 -Y "ftp"
```

```bash
tshark -i wlp2s0 -Y '(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)'
```


## HTTP Packet Capturing to debug Apache

### wget

```bash
wget -S --spider URL 
```

### lynx

```bash
lynx -head -dump URL 
```

### curl
```bash
curl -I URL HEAD URL 
```

### GET

```bash
GET -de URL 
```

### w3m
```bash
w3m -dump_head URL siege -g URL
```

### HTTP Display Filter Options

| Display Filter | Description 
|----------------|------------------------------------|
| http.accept | String Accept
| http.accept_encoding | String Accept Encoding
| http.accept_language | String Accept-Language
| http.authbasic |  String Credentials
| http.authorization |  String Authorization
| http.cache_control | String Cache-Control
| http.connection|  String Connection
| http.content_encoding | String Content-Encoding
| http.content_length | Unsigned 32-bit integer Content-Length
| http.content_type | String Content-Type
| http.cookie | String Cookie
| http.date | String Date
| http.host | String Host
| http.last_modified | String Last-Modified
| http.location | String Location
| http.notification | Boolean Notification
| http.proxy_authenticate | String Proxy-Authenticate
| http.proxy_authorization | String Proxy-Authorization
| http.referer | String Referer
| http.request | Boolean Request
| http.request.method |  String Request Method
| http.request.uri | String Request URI
| http.request.version | String Request Version
| http.response | Boolean Response
| http.response.code | Unsigned 16-bit integer Response Code
| http.server | String Server
| http.set_cookie String | Set-Cookie
| http.transfer_encoding | String Transfer-Encoding
| http.user_agent String | User-Agent
| http.www_authenticate | String WWW-Authenticate
| http.x_forwarded_for | String X-Forwarded-For


### View All HTTP trafic

	tshark -Y 'http'

### View all flash video stuff

	tshark -Y 'http.request.uri contains "flv" or http.request.uri contains "swf" or http.content_type contains "flash" or http.content_type contains "video"'

### Show non-google cache-control

	tshark -Y '(((((http.cache_control != "private, x-gzip-ok=""") && !(http.cache_control == "no-cache, no-store, must-revalidate, max-age=0, proxy-revalidate, no-transform, private")) && !(http.cache_control == "max-age=0, no-store")) && !(http.cache_control == "private")) && !(http.cache_control == "no-cache")) && !(http.cache_control == "no-transform")'

### Show only certain responses

* #404: page not found

	tshark -Y 'http.response.code == 404'

* #200: OK

	tshark -Y 'http.response.code == 200'

### Show only certain HTTP methods

	tshark -Y 'http.request.method == "POST" || http.request.method == "PUT"'

### Show only filetypes that begin with "text"

	tshark -Y 'http.content_type[0:4] == "text"'

### Show only javascript

	tshark -Y tshark -i wlp2s0 -Y 'http.content_type contains "javascript"'

### Show all http with content-type="image/(gif|jpeg|png|etc)"

	tshark -Y 'http.content_type[0:5] == "image"'

### Show all http with content-type="image/gif"

	tshark -Y http.content_type == "image/gif"

### Do not show content http, only headers

	tshark -Y http.response !=0 || http.request.method != "TRACE"


### To match IP addresses ending in 255 in a block of subnets (172.16 to 172.31):

	tshark -Y  string(ip.dst) matches r"^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.255


### To match odd frame numbers

	tshark -Y  string(frame.number) matches "[13579]$"

### If you capture no packets and send to xxd, you can see just the file header for any capture type. 

An easy way to capture no packets is to filter by unused ipx in your capture filter. In this example, we use -F pcap for the pcap file type.

	tshark -f ipx -a duration:1 -F pcap -w - 2>/dev/null | xxd -u


### Custom Aliases
```
alias tshark-any-any="tshark -i any"
alias tshark-usb="tshark -i usb0"
alias tshark-bluemoon='tshark -C BlueConfig -o BlueKey:BlueVal'
echo "alias tshark='tshark --color'" >> ~/.profile
```

### Statistics

```
tshark -i wlp2s0 -z afp,srt
tshark -i wlp2s0 -z ancp,tree
tshark -i wlp2s0 -z ansi_a,bsmap
tshark -i wlp2s0 -z ansi_a,dtap
tshark -i wlp2s0 -z ansi_map
tshark -i wlp2s0 -z asap,stat
tshark -i wlp2s0 -z bacapp_instanceid,tree
tshark -i wlp2s0 -z bacapp_ip,tree
tshark -i wlp2s0 -z bacapp_objectid,tree
tshark -i wlp2s0 -z bacapp_service,tree
tshark -i wlp2s0 -z calcappprotocol,stat
tshark -i wlp2s0 -z camel,counter
tshark -i wlp2s0 -z camel,srt
tshark -i wlp2s0 -z collectd,tree
tshark -i wlp2s0 -z componentstatusprotocol,stat
tshark -i wlp2s0 -z conv,bluetooth
tshark -i wlp2s0 -z conv,dccp
tshark -i wlp2s0 -z conv,eth
tshark -i wlp2s0 -z conv,fc
tshark -i wlp2s0 -z conv,fddi
tshark -i wlp2s0 -z conv,ip
tshark -i wlp2s0 -z conv,ipv6
tshark -i wlp2s0 -z conv,ipx
tshark -i wlp2s0 -z conv,jxta
tshark -i wlp2s0 -z conv,mptcp
tshark -i wlp2s0 -z conv,ncp
tshark -i wlp2s0 -z conv,rsvp
tshark -i wlp2s0 -z conv,sctp
tshark -i wlp2s0 -z conv,sll
tshark -i wlp2s0 -z conv,tcp
tshark -i wlp2s0 -z conv,tr
tshark -i wlp2s0 -z conv,udp
tshark -i wlp2s0 -z conv,usb
tshark -i wlp2s0 -z conv,wlan
tshark -i wlp2s0 -z conv,wpan
tshark -i wlp2s0 -z conv,zbee_nwk
tshark -i wlp2s0 -z credentials
tshark -i wlp2s0 -z dcerpc,srt
tshark -i wlp2s0 -z dests,tree
tshark -i wlp2s0 -z dhcp,stat
tshark -i wlp2s0 -z diameter,avp
tshark -i wlp2s0 -z diameter,srt
tshark -i wlp2s0 -z dns,tree
tshark -i wlp2s0 -z endpoints,bluetooth
tshark -i wlp2s0 -z endpoints,dccp
tshark -i wlp2s0 -z endpoints,eth
tshark -i wlp2s0 -z endpoints,fc
tshark -i wlp2s0 -z endpoints,fddi
tshark -i wlp2s0 -z endpoints,ip
tshark -i wlp2s0 -z endpoints,ipv6
tshark -i wlp2s0 -z endpoints,ipx
tshark -i wlp2s0 -z endpoints,jxta
tshark -i wlp2s0 -z endpoints,mptcp
tshark -i wlp2s0 -z endpoints,ncp
tshark -i wlp2s0 -z endpoints,rsvp
tshark -i wlp2s0 -z endpoints,sctp
tshark -i wlp2s0 -z endpoints,sll
tshark -i wlp2s0 -z endpoints,tcp
tshark -i wlp2s0 -z endpoints,tr
tshark -i wlp2s0 -z endpoints,udp
tshark -i wlp2s0 -z endpoints,usb
tshark -i wlp2s0 -z endpoints,wlan
tshark -i wlp2s0 -z endpoints,wpan
tshark -i wlp2s0 -z endpoints,zbee_nwk
tshark -i wlp2s0 -z enrp,stat
tshark -i wlp2s0 -z expert
tshark -i wlp2s0 -z f1ap,tree
tshark -i wlp2s0 -z f5_tmm_dist,tree
tshark -i wlp2s0 -z f5_virt_dist,tree
tshark -i wlp2s0 -z fc,srt
tshark -i wlp2s0 -z flow,any
tshark -i wlp2s0 -z flow,icmp
tshark -i wlp2s0 -z flow,icmpv6
tshark -i wlp2s0 -z flow,lbm_uim
tshark -i wlp2s0 -z flow,tcp
tshark -i wlp2s0 -z follow,dccp
tshark -i wlp2s0 -z follow,http
tshark -i wlp2s0 -z follow,http2
tshark -i wlp2s0 -z follow,quic
tshark -i wlp2s0 -z follow,sip
tshark -i wlp2s0 -z follow,tcp
tshark -i wlp2s0 -z follow,tls
tshark -i wlp2s0 -z follow,udp
tshark -i wlp2s0 -z fractalgeneratorprotocol,stat
tshark -i wlp2s0 -z gsm_a
tshark -i wlp2s0 -z gsm_a,bssmap
tshark -i wlp2s0 -z gsm_a,dtap_cc
tshark -i wlp2s0 -z gsm_a,dtap_gmm
tshark -i wlp2s0 -z gsm_a,dtap_mm
tshark -i wlp2s0 -z gsm_a,dtap_rr
tshark -i wlp2s0 -z gsm_a,dtap_sacch
tshark -i wlp2s0 -z gsm_a,dtap_sm
tshark -i wlp2s0 -z gsm_a,dtap_sms
tshark -i wlp2s0 -z gsm_a,dtap_ss
tshark -i wlp2s0 -z gsm_a,dtap_tp
tshark -i wlp2s0 -z gsm_map,operation
tshark -i wlp2s0 -z gtp,srt
tshark -i wlp2s0 -z h225,counter
tshark -i wlp2s0 -z h225_ras,rtd
tshark -i wlp2s0 -z hart_ip,tree
tshark -i wlp2s0 -z hosts
tshark -i wlp2s0 -z hpfeeds,tree
tshark -i wlp2s0 -z http,stat
tshark -i wlp2s0 -z http,tree
tshark -i wlp2s0 -z http2,tree
tshark -i wlp2s0 -z http_req,tree
tshark -i wlp2s0 -z http_seq,tree
tshark -i wlp2s0 -z http_srv,tree
tshark -i wlp2s0 -z icmp,srt
tshark -i wlp2s0 -z icmpv6,srt
tshark -i wlp2s0 -z io,phs
tshark -i wlp2s0 -z io,stat
tshark -i wlp2s0 -z ip_hosts,tree
tshark -i wlp2s0 -z ip_srcdst,tree
tshark -i wlp2s0 -z ipv6_dests,tree
tshark -i wlp2s0 -z ipv6_hosts,tree
tshark -i wlp2s0 -z ipv6_ptype,tree
tshark -i wlp2s0 -z ipv6_srcdst,tree
tshark -i wlp2s0 -z isup_msg,tree
tshark -i wlp2s0 -z lbmr_queue_ads_queue,tree
tshark -i wlp2s0 -z lbmr_queue_ads_source,tree
tshark -i wlp2s0 -z lbmr_queue_queries_queue,tree
tshark -i wlp2s0 -z lbmr_queue_queries_receiver,tree
tshark -i wlp2s0 -z lbmr_topic_ads_source,tree
tshark -i wlp2s0 -z lbmr_topic_ads_topic,tree
tshark -i wlp2s0 -z lbmr_topic_ads_transport,tree
tshark -i wlp2s0 -z lbmr_topic_queries_pattern,tree
tshark -i wlp2s0 -z lbmr_topic_queries_pattern_receiver,tree
tshark -i wlp2s0 -z lbmr_topic_queries_receiver,tree
tshark -i wlp2s0 -z lbmr_topic_queries_topic,tree
tshark -i wlp2s0 -z ldap,srt
tshark -i wlp2s0 -z mac-lte,stat
tshark -i wlp2s0 -z megaco,rtd
tshark -i wlp2s0 -z mgcp,rtd
tshark -i wlp2s0 -z mtp3,msus
tshark -i wlp2s0 -z ncp,srt
tshark -i wlp2s0 -z ngap,tree
tshark -i wlp2s0 -z npm,stat
tshark -i wlp2s0 -z osmux,tree
tshark -i wlp2s0 -z pingpongprotocol,stat
tshark -i wlp2s0 -z plen,tree
tshark -i wlp2s0 -z proto,colinfo
tshark -i wlp2s0 -z ptype,tree
tshark -i wlp2s0 -z radius,rtd
tshark -i wlp2s0 -z rlc-lte,stat
tshark -i wlp2s0 -z rpc,programs
tshark -i wlp2s0 -z rpc,srt
tshark -i wlp2s0 -z rtp,streams
tshark -i wlp2s0 -z rtsp,stat
tshark -i wlp2s0 -z rtsp,tree
tshark -i wlp2s0 -z sametime,tree
tshark -i wlp2s0 -z scsi,srt
tshark -i wlp2s0 -z sctp,stat
tshark -i wlp2s0 -z sip,stat
tshark -i wlp2s0 -z smb,sids
tshark -i wlp2s0 -z smb,srt
tshark -i wlp2s0 -z smb2,srt
tshark -i wlp2s0 -z smpp_commands,tree
tshark -i wlp2s0 -z snmp,srt
tshark -i wlp2s0 -z ssprotocol,stat
tshark -i wlp2s0 -z sv
tshark -i wlp2s0 -z ucp_messages,tree
tshark -i wlp2s0 -z wsp,stat
```

## Active Hunting 


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

## Layouts

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

## Exporting Data
  
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

## Well Known MAC Adresses

| Mac Address      | Description |
|------------------|------------------------------------- |
|00-00-00-00-FE-21 | Checkpoint-Uninitialized-Cluster-Member |
|00-00-0C-07-AC/40 | All-HSRP-routers |
|00-00-5E-00-01/40 | IETF-VRRP-VRID |
|00-0C-0C-0C-0C-0C | Cisco-ACI-Gleaning-Leaf |
|00-0D-0D-0D-0D-0D | Cisco-ACI-Gleaning-Spine |
|00-BF-00-00-00-00/16 | MS-NLB-VirtServer |
|00-E0-2B-00-00-00 | Extreme-EDP |
|00-E0-2B-00-00-01 | Extreme-EEP |
|00-E0-2B-00-00-02 | Extreme-ESRP-Client |
|00-E0-2B-00-00-04 | Extreme-EAPS |
|00-E0-2B-00-00-06 | Extreme-EAPS-SL |
|00-E0-2B-00-00-08 | Extreme-ESRP-Master |
|01-00-0C-00-00/40 | ISL-Frame |
|01-00-0C-CC-CC-CC | CDP/VTP/DTP/PAgP/UDLD |
|01-00-0C-CC-CC-CD | PVST+ |
|01-00-0C-CD-CD-CD | STP-UplinkFast |
|01-00-0C-CD-CD-CE | VLAN-bridge |
|01-00-0C-CD-CD-D0 | GBPT |
|01-00-0C-DD-DD-DD | CGMP |
|01-00-10-00-00-20 | Hughes-Lantshark -z smb,srt -V -T text-Systems-Terminal-Server-S/W-download |
|01-00-10-FF-FF-20 | Hughes-Lan-Systems-Terminal-Server-S/W-request |
|01-00-1D-00-00-00 | Cabletron-PC-OV-PC-discover-(on-demand) |
|01-00-1D-00-00-05 | Cabletron-PVST-BPDU |
|01-00-1D-00-00-06 | Cabletron-QCSTP-BPDU |
|01-00-1D-42-00-00 | Cabletron-PC-OV-Bridge-discover-(on-demand) |
|01-00-1D-52-00-00 | Cabletron-PC-OV-MMAC-discover-(on-demand) |
|01-00-3C | Auspex-Systems-(Serverguard) |
|01-00-5E/25 | IPv4mcast |
|01-00-81-00-00-00 | Nortel-Network-Management |
|01-00-81-00-00-02 | Nortel-Network-Management |
|01-00-81-00-01-00 | Nortel-autodiscovery |
|01-00-81-00-01-01 | Nortel-autodiscovery |
|01-0F-FF-C1-01-C0 | FP-Flood-to-all-VLANs |
|01-0F-FF-C1-02-C0 | FP-Flood-to-all-Fabrics |
|01-10-18-01-00-00 | All-FCoE-MACs |
|01-10-18-01-00-01 | All-ENode-MACs |
|01-10-18-01-00-02 | All-FCF-MACs |
|01-10-18-00-00-00/24 | FCoE-group |
|01-11-1E-00-00-01 | EPLv2_SoC |
|01-11-1E-00-00-02 | EPLv2_PRes |
|01-11-1E-00-00-03 | EPLv2_SoA |
|01-11-1E-00-00-04 | EPLv2_ASnd |
|01-11-1E-00-00-05 | EPLv2_AMNI |
|01-20-25/25 | Control-Technology-Inc's-Industrial-Ctrl-Proto. |
|01-80-24-00-00-00 | Kalpana-Ettshark -z smb,srt -V -T textherswitch-every-60-seconds |
|01-80-C2-00-00-00/44 | Spanning-tree-(for-bridges) |
|01-80-C2-00-00-01 | MAC-specific-ctrl-proto-01 |
|01-80-C2-00-00-02 | Slow-Protocols |
|01-80-C2-00-00-03 | Nearest-non-TPMR-bridge |
|01-80-C2-00-00-04 | MAC-specific-ctrl-proto-04 |
|01-80-C2-00-00-05 | Reserved-future-std-05 |
|01-80-C2-00-00-06 | Reserved-future-std-06 |
|01-80-C2-00-00-07 | MEF-Forum-ELMI-proto |
|01-80-C2-00-00-08 | Provider-Bridge |
|01-80-C2-00-00-09 | Reserved-future-std-09 |
|01-80-C2-00-00-0A | Reserved-future-std-0a |
|01-80-C2-00-00-0B | EDE-SS-PEP |
|01-80-C2-00-00-0C | Reserved-future-std-0c |
|01-80-C2-00-00-0D | Provider-Bridge-MVRP |
|01-80-C2-00-00-0E | LLDP_Multicast |
|01-80-C2-00-00-0F | Reserved-future-std-0f |
|01-80-C2-00-00-10 | Bridge-Management |
|01-80-C2-00-00-11 | Load-Server |
|01-80-C2-00-00-12 | Loadable-Device |
|01-80-C2-00-00-13 | IEEE-1905.1-Control |
|01-80-C2-00-00-14 | ISIS-all-level-1-IS's |
|01-80-C2-00-00-15 | ISIS-all-level-2-IS's |
|01-80-C2-00-00-18 | IEEE-802.1B-All-Manager-Stations |
|01-80-C2-00-00-19 | IEEE-802.11aa-groupcast-with-retries |
|01-80-C2-00-00-1A | IEEE-802.1B-All-Agent-Stations |
|01-80-C2-00-00-1B | ESIS-all-multicast-capable-ES's |
|01-80-C2-00-00-1C | ESIS-all-multicast-announcements |
|01-80-C2-00-00-1D | ESIS-all-multicast-capable-IS's |
|01-80-C2-00-00-1E | Token-Ring-all-DTR-Concentrators |
|01-80-C2-00-00-30/45 | OAM-Multicast-DA-Class-1 |
|01-80-C2-00-00-38/45 | OAM-Multicast-DA-Class-2 |
|01-80-C2-00-00-40 | All-RBridges |
|01-80-C2-00-00-41 | All-IS-IS-RBridges |
|01-80-C2-00-00-42 | All-Egress-RBridges |
|01-80-C2-00-00-45 | TRILL-End-Stations |
|01-80-C2-00-00-46 | All-Edge-RBridges |
|01-80-C2-00-01-00 | FDDI-RMT-Directed-Beacon |
|01-80-C2-00-01-10 | FDDI-status-report-frame |
|01-DD-00-FF-FF-FF | Ungermann-Bass-boot-me-requests |
|01-DD-01-00-00-00 | Ungermann-Bass-Spanning-Tree |
|01-E0-52-CC-CC-CC | Foundry-DP |
|01-E0-2F-00-00-01 | DOCSIS-CM |
|01-E0-2F-00-00-02 | DOCSIS-CMTS |
|01-E0-2F-00-00-03 | DOCSIS-STP |
|02-04-96-00-00-00/24 | ExtremeNetworks |
|02-BF-00-00-00-00/16 | MS-NLB-VirtServer |
|02-01-00-00-00-00/16 | MS-NLB-PhysServer-01 |
|02-02-00-00-00-00/16 | MS-NLB-PhysServer-02 |
|02-03-00-00-00-00/16 | MS-NLB-PhysServer-03 |
|02-04-00-00-00-00/16 | MS-NLB-PhysServer-04 |
|02-05-00-00-00-00/16 | MS-NLB-PhysServer-05 |
|02-06-00-00-00-00/16 | MS-NLB-PhysServer-06 |
|02-07-00-00-00-00/16 | MS-NLB-PhysServer-07 |
|02-08-00-00-00-00/16 | MS-NLB-PhysServer-08 |
|02-09-00-00-00-00/16 | MS-NLB-PhysServer-09 |
|02-0a-00-00-00-00/16 | MS-NLB-PhysServer-10 |
|02-0b-00-00-00-00/16 | MS-NLB-PhysServer-11 |
|02-0c-00-00-00-00/16 | MS-NLB-PhysServer-12 |
|02-0d-00-00-00-00/16 | MS-NLB-PhysServer-13 |
|02-0e-00-00-00-00/16 | MS-NLB-PhysServer-14 |
|02-0f-00-00-00-00/16 | MS-NLB-PhysServer-15 |
|02-10-00-00-00-00/16 | MS-NLB-PhysServer-16 |
|02-11-00-00-00-00/16 | MS-NLB-PhysServer-17 |
|02-12-00-00-00-00/16 | MS-NLB-PhysServer-18 |
|02-13-00-00-00-00/16 | MS-NLB-PhysServer-19 |
|02-14-00-00-00-00/16 | MS-NLB-PhysServer-20 |
|02-15-00-00-00-00/16 | MS-NLB-PhysServer-21 |
|02-16-00-00-00-00/16 | MS-NLB-PhysServer-22 |
|02-17-00-00-00-00/16 | MS-NLB-PhysServer-23 |
|02-18-00-00-00-00/16 | MS-NLB-PhysServer-24 |
|02-19-00-00-00-00/16 | MS-NLB-PhysServer-25 |
|02-1a-00-00-00-00/16 | MS-NLB-PhysServer-26 |
|02-1b-00-00-00-00/16 | MS-NLB-PhysServer-27 |
|02-1c-00-00-00-00/16 | MS-NLB-PhysServer-28 |
|02-1d-00-00-00-00/16 | MS-NLB-PhysServer-29 |
|02-1e-00-00-00-00/16 | MS-NLB-PhysServer-30 |
|02-1f-00-00-00-00/16 | MS-NLB-PhysServer-31 |
|02-20-00-00-00-00/16 | MS-NLB-PhysServer-32 |
|03-00-00-00-00-01 | NETBIOS-# [TR?] |
|03-00-00-00-00-02 | Locate-Directory-Server # [TR?] |
|03-00-00-00-00-04 | Synchronous-Bandwidth-Manager-# [TR?] |
|03-00-00-00-00-08 | Configuration-Report-Server-# [TR?] |
|03-00-00-00-00-10 | Ring-Error-Monitor-# [TR?] |
|03-00-00-00-00-10 | (OS/2-1.3-EE+Communications-Manager) |
|03-00-00-00-00-20 | Network-Server-Heartbeat-# [TR?] |
|03-00-00-00-00-40 | (OS/2-1.3-EE+Communications-Manager) |
|03-00-00-00-00-80 | Active-Monitor # [TR?] |
|03-00-00-00-01-00 | OSI-All-IS-Token-Ring-Multicast |
|03-00-00-00-02-00 | OSI-All-ES-Token-Ring-Multicast |
|03-00-00-00-04-00 | LAN-Manager # [TR?] |
|03-00-00-00-08-00 | Ring-Wiring-Concentrator # [TR?] |
|03-00-00-00-10-00 | LAN-Gateway # [TR?] |
|03-00-00-00-20-00 | Ring-Authorization-Server # [TR?] |
|03-00-00-00-40-00 | IMPL-Server # [TR?] |
|03-00-00-00-80-00 | Bridge # [TR?] |
|03-00-00-20-00-00 | IP-Token-Ring-Multicast (RFC1469) |
|03-00-00-80-00-00 | Discovery-Client |
|03-00-0C-00-00/40 | ISL-Frame [TR?] |
|03-00-C7-00-00-EE | HP (Compaq) ProLiant NIC teaming |
|03-00-FF-FF-FF-FF | All-Stations-Address |
|03-BF-00-00-00-00/16 | MS-NLB-VirtServer-Multicast |
|09-00-07-00-00-00/40 | AppleTalk-Zone-multicast-addresses |
|09-00-07-FF-FF-FF | AppleTalk-broadcast-address |
|09-00-09-00-00-01 | HP-Probe |
|09-00-09-00-00-04 | HP-DTC |
|09-00-0D-00-00-00/24 | ICL-Oslan-Multicast |
|09-00-0D-02-00-00 | ICL-Oslan-Service-discover-only-on-boot |
|09-00-0D-02-0A-38 | ICL-Oslan-Service-discover-only-on-boot |
|09-00-0D-02-0A-39 | ICL-Oslan-Service-discover-only-on-boot |
|09-00-0D-02-0A-3C | ICL-Oslan-Service-discover-only-on-boot |
|09-00-0D-02-FF-FF | ICL-Oslan-Service-discover-only-on-boot |
|09-00-0D-09-00-00 | ICL-Oslan-Service-discover-as-required |
|09-00-1E-00-00-00 | Apollo-DOMAIN |
|09-00-2B-00-00-00 | DEC-MUMPS? |
|09-00-2B-00-00-01 | DEC-DSM/DDP |
|09-00-2B-00-00-02 | DEC-VAXELN? |
|09-00-2B-00-00-03 | DEC-Lanbridge-Traffic-Monitor-(LTM) |
|09-00-2B-00-00-04 | DEC-MAP-(or-OSI?)-End-System-Hello? |
|09-00-2B-00-00-05 | DEC-MAP-(or-OSI?)-Intermediate-System-Hello? |
|09-00-2B-00-00-06 | DEC-CSMA/CD-Encryption? |
|09-00-2B-00-00-07 | DEC-NetBios-Emulator? |
|09-00-2B-00-00-0F | DEC-Local-Area-Transport-(LAT) |
|09-00-2B-00-00-10/44 | DEC-Experitshark -z smb,srt -V -T textmental |
|09-00-2B-01-00-00 | DEC-LanBridge-Copy-packets-(All-bridges) |
|09-00-2B-01-00-01 | DEC-LanBridge-Hello-packets-(All-local-bridges) |
|09-00-2B-02-00-00 | DEC-DNA-Level-2-Routing-Layer-routers? |
|09-00-2B-02-01-00 | DEC-DNA-Naming-Service-Advertisement? |
|09-00-2B-02-01-01 | DEC-DNA-Naming-Service-Solicitation? |
|09-00-2B-02-01-09 | DEC-Availability-Manager-for-Distributed-Systems-DECamds |
|09-00-2B-02-01-02 | DEC-Distributed-Time-Service |
|09-00-2B-03-00-00/32 | DEC-default-filtering-by-bridges? |
|09-00-2B-04-00-00 | DEC-Local-Area-System-Transport-(LAST)? |
|09-00-2B-23-00-00 | DEC-Argonaut-Console? |
|09-00-4C-00-00-00 | BICC-802.1-management |
|09-00-4C-00-00-02 | BICC-802.1-management |
|09-00-4C-00-00-06 | BICC-Local-bridge-STA-802.1(D)-Rev6 |
|09-00-4C-00-00-0C | BICC-Remote-bridge-STA-802.1(D)-Rev8 |
|09-00-4C-00-00-0F | BICC-Remote-bridge-ADAPTIVE-ROUTING |
|09-00-56-FF-00-00/32 | Stanford-V-Kernel,-version-6.0 |
|09-00-6A-00-01-00 | TOP-NetBIOS. |
|09-00-77-00-00-00 | Retix-Bridge-Local-Management-System |
|09-00-77-00-00-01 | Retix-spanning-tree-bridges |
|09-00-77-00-00-02 | Retix-Bridge-Adaptive-routing |
|09-00-7C-01-00-01 | Vitalink-DLS-Multicast |
|09-00-7C-01-00-03 | Vitalink-DLS-Inlink |
|09-00-7C-01-00-04 | Vitalink-DLS-and-non-DLS-Multicast |
|09-00-7C-02-00-05 | Vitalink-diagnostics |
|09-00-7C-05-00-01 | Vitalink-gateway? |
|09-00-7C-05-00-02 | Vitalink-Network-Validation-Message |
|09-00-87-80-FF-FF | Xyplex-Terminal-Servers |
|09-00-87-90-FF-FF | Xyplex-Terminal-Servers |
|0C-00-0C-00-00/40 | ISL-Frame |
|0D-1E-15-BA-DD-06 | HP |
|20-52-45-43-56-00/40 | Receive |
|20-53-45-4E-44-00/40 | Send |
|33-33-00-00-00-00 | IPv6-Neighbor-Discovery |
|33-33-00-00-00-00/16 | IPv6mcast |
|AA-00-03-00-00-00/32 | DEC-UNA |
|AA-00-03-01-00-00/32 | DEC-PROM-AA |
|AA-00-03-03-00-00/32 | DEC-NI20 |
|AB-00-00-01-00-00 | DEC-MOP-Dump/Load-Assistance |
|AB-00-00-02-00-00 | DEC-MOP-Remote-Console |
|AB-00-00-03-00-00 | DECNET-Phase-IV-end-node-Hello-packets |
|AB-00-00-04-00-00 | DECNET-Phase-IV-Router-Hello-packets |
|AB-00-03-00-00-00 | DEC-Local-Area-Transport-(LAT)-old |
|AB-00-04-01-00-00/32 | DEC-Local-Area-VAX-Cluster-groups-SCA |
|CF-00-00-00-00-00 | Ethernet-Configuration-Test-protocol-(Loopback) |
|FF-FF-00-60-00-04 | Lantastic |
|FF-FF-00-40-00-01 | Lantastic |
|FF-FF-01-E0-00-04 | Lantastic |
|FF-FF-FF-FF-FF-FF | Broadcast |

### Resources

* [tshark.dev](https://tshark.dev/)
* [tshark.dev - capture](https://tshark.dev/capture/)
* [tshark.dev - ssh interface](https://tshark.dev/capture/sources/ssh_interface/)
* [tshark.dev - downloading file](https://tshark.dev/capture/sources/downloading_file/)
* [tshark.dev - tshark analysis](https://tshark.dev/analyze/packet_hunting/tshark_analysis/)
* [tshark.dev - lua scripts](https://tshark.dev/packetcraft/scripting/lua_scripts/)
* [Wireshark Display Filters](https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf)
* [Long Term Traffic Capture Wireshark](https://packetlife.net/blog/2011/mar/9/long-term-traffic-capture-wireshark/)
* [Using Wireshark Display Filter Expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [Customizing Wireshark Changing Column Display](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [List Wireshark Display Filters](https://networksecuritytools.com/list-wireshark-display-filters/)
* [Display Filters](https://wiki.wireshark.org/DisplayFilters)
* [HTTP Headers Tool](https://www.askapache.com/online-tools/http-headers-tool)
* [tcpdump.pdf](https://packetlife.net/media/library/12/tcpdump.pdf)
* [wikipedia - Byte order mark](https://en.wikipedia.org/wiki/Byte_order_mark)
* [Sniff HTTP To Debug Apache .htaccess and httpdconf](https://www.askapache.com/software/sniff-http-to-debug-apache-htaccess-and-httpdconf/)
* [wikipedia - List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
* [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)

### Wiki Author

* [<wuseman>]

