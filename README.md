# packet-mod

Generate tunnelled and tagged test traffic for network devices: packet brokers, DPI engines, firewalls, load balancers and NIC offloads.

[`packet-mod.py`](packet-mod.py) is a single script with two modes. Both modes use the same header-building code, so a VXLAN, GRE or GTP-U header has the same format whichever mode you use.

| Mode | Command | What it does | Output |
|------|---------|--------------|--------|
| **pcap mode** | `packet-mod.py <file.pcap> <protocol> [fragmented]` | Reads an existing capture and wraps **every packet** in a tunnel or tag. It can also fragment the packets. | A new `.pcap` file |
| **replay mode** | `packet-mod.py <iface> <protocol> <speed> [options]` | Builds random traffic of the chosen tunnel or tag and sends it out of a network interface at a fixed rate (for example `4G`). | Live traffic on the wire |

To replay a `.pcap` produced by pcap mode at a chosen speed, use [tcpreplay](https://tcpreplay.appneta.com/); see [Replaying pcaps at different speeds](#replaying-pcaps-at-different-speeds).

---

## Contents

- [Supported encapsulations](#supported-encapsulations)
- [Requirements](#requirements)
- [Installation](#installation)
- [Pcap mode: encapsulate a capture](#pcap-mode-encapsulate-a-capture)
- [Replaying pcaps at different speeds](#replaying-pcaps-at-different-speeds)
- [Replay mode: live traffic at a fixed rate](#replay-mode-live-traffic-at-a-fixed-rate)
- [How it works](#how-it-works)
- [Verifying the output](#verifying-the-output)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Supported encapsulations

The same protocol names work in both modes.

| Name | Standard | Resulting frame |
|------|----------|-----------------|
| `vlan` | IEEE 802.1Q | Eth / 802.1Q / payload |
| `qinq` (`dot1ad`) | IEEE 802.1ad | Eth / S-tag (0x88A8) / C-tag (0x8100) / payload. See [QinQ](#qinq). |
| `vntag` | Cisco VN-Tag (0x8926) | Eth / VN-Tag / payload |
| `fabricpath` | Cisco FabricPath (0x8903) | FabricPath outer header / original Eth frame |
| `trill` | RFC 6325 (0x22F3) | Outer Eth / TRILL / Eth + 802.1Q / payload |
| `ppp` (`pppoe`) | RFC 2516 / RFC 1661 | Eth / PPPoE session / PPP / IP |
| `gre` | RFC 2784 / RFC 2890 | Eth / IPv4 / GRE (Key + Sequence) / IP |
| `nvgre` | RFC 7637 | Eth / IPv4 / GRE (0x6558) / Eth / … |
| `vxlan` | RFC 7348 | Eth / IPv4 / UDP 4789 / VXLAN / Eth / … |
| `geneve` | RFC 8926 | Eth / IPv4 / UDP 6081 / GENEVE (one option) / Eth / … |
| `l2tp` | RFC 2661 (L2TPv2) | Eth / IPv4 / UDP 1701 / L2TP / PPP / IP |
| `lisp` | RFC 9300 | Eth / IPv4 / UDP 4341 / LISP / IP |
| `gtp` (`gtpu`) | 3GPP TS 29.281 (GTPv1-U) | Eth / IPv4 / UDP 2152 / GTP-U / IP |
| `none` | — | No extra layer. In pcap mode, combine it with `fragmented` to fragment only; in replay mode it sends plain IPv4 traffic. |

Names are case-insensitive, and `-` / `_` are ignored, so `VN-Tag`, `fabric_path` and `GTP-U` all work.

**IP tunnels** (`gre`, `nvgre`, `vxlan`, `geneve`, `l2tp`, `lisp`, `gtp`) add an outer Ethernet + IPv4 header. **L2 tags** (`vlan`, `qinq`, `vntag`, `fabricpath`, `trill`, `ppp`, `none`) do not. This difference matters for fragmentation.

---

## Requirements

- **Linux.** Replay mode uses `AF_PACKET` raw sockets and `fork`.
- **Python 3.9 or newer.**
- **[Scapy](https://scapy.net/)**, tested with 2.7.0. Both modes need it.
- **root or `CAP_NET_RAW`** for replay mode and for `tcpreplay`.
- Optional: `tcpreplay` to replay pcaps, and `tshark`, Wireshark or `tcpdump` to inspect the output.

## Installation

```bash
git clone https://github.com/noorulislam770/packet-mod.git
cd packet-mod

python3 -m venv venv
. venv/bin/activate
pip install scapy

# optional tools (Debian/Ubuntu)
sudo apt install tcpreplay tshark tcpdump
```

Replay mode needs root. If you installed Scapy in a venv, call the venv's Python under `sudo`:

```bash
sudo venv/bin/python packet-mod.py ens1 vxlan 1G
```

### How the mode is chosen

The script looks at its arguments:

- **Replay mode** if there are at least three arguments, the first one is **not an existing file**, and the third one is not `fragmented` / `fragment` / `frag`. The first argument must then be a network interface listed in `/sys/class/net`.
- **Pcap mode** otherwise.

---

## Pcap mode: encapsulate a capture

```text
python3 packet-mod.py <file.pcap> <PROTOCOL> [fragmented]
```

| Argument | Description |
|----------|-------------|
| `file.pcap` | Input capture (pcap or pcapng). Must be an **Ethernet** capture (link type 1). |
| `PROTOCOL` | One of the names in [Supported encapsulations](#supported-encapsulations). |
| `fragmented` | Optional. Also accepts `fragment` or `frag`. Turns on IPv4 fragmentation, described below. |

### Examples

```bash
# Wrap every packet in VXLAN
python3 packet-mod.py capture.pcap vxlan
# -> wrote 1200 packets to capture-out-vxlan.pcap

# Add an 802.1Q tag to every packet
python3 packet-mod.py capture.pcap vlan

# Make every packet QinQ (S-tag + C-tag; already-tagged packets get just the S-tag)
python3 packet-mod.py capture.pcap qinq

# GTP-U with ~40 % of the packets split into two outer-IP fragments
python3 packet-mod.py capture.pcap gtp fragmented
# -> capture-out-gtp-fragmented.pcap

# Fragment only, with no extra layer (also converts pcapng to pcap)
python3 packet-mod.py capture.pcapng none fragmented
```

### Output files

The output is written **next to the input file** as `<name>-out-<protocol>[-fragmented].pcap`. Existing files are never overwritten. If the name is taken, a counter is added: `capture-out-vxlan-1.pcap`, `capture-out-vxlan-2.pcap`, …

The output is a classic little-endian pcap with microsecond timestamps and Ethernet link type. The original packet timestamps are kept, so a replay at "original speed" reproduces the original timing.

### What gets generated

- **One coherent tunnel per run.** All random values (outer MACs and IPs, VLAN ID and PCP, QinQ S-VID and C-VID, VNI, VSID, TEID, GRE key, PPPoE session ID, TRILL nicknames, …) are chosen **once per run**. The whole output therefore looks like a single tunnel or tag set. Run the tool again to get different values.
- **Outer addressing** for IP tunnels uses random locally administered MACs and `10.x.x.x` IPs. DF is set unless `fragmented` is used.
- **Per-flow entropy.** VXLAN, GENEVE and LISP derive the UDP source port (49152–65535) from a hash of the inner MAC pair, as real VTEPs do. NVGRE uses the same hash for the 8-bit FlowID.
- **GRE** always sets the Key and Sequence Number bits. The sequence number increases by one for every packet.
- **GENEVE** carries one 8-byte option (experimental class `0xFFFF`) with random data.
- **NVGRE and VXLAN** remove any 802.1Q or QinQ tags from the inner frame (RFC 7637 §3.3, RFC 7348 §6.1).
- **TRILL** adds an 802.1Q tag to the inner frame. An inner multicast destination produces a multi-destination (M=1) frame to `01:80:c2:00:00:40`.
- **Pass-through rules:**
  - `l2tp`, `ppp`, `lisp`, `gre` and `gtp` carry IP only. Non-IP frames (ARP, LLDP, …) are copied unchanged.
  - A packet that already carries the requested layer is copied unchanged (for example, VXLAN traffic in `vxlan` mode).
  - Frames shorter than 14 bytes are copied unchanged.

### QinQ

`qinq` behaves like an IEEE 802.1ad provider edge port. The result is always a QinQ frame with an S-tag (TPID `0x88A8`) followed by a C-tag (TPID `0x8100`):

| Input frame | Result |
|-------------|--------|
| Untagged | An S-tag and a C-tag are added, both with random VID and PCP (DEI = 0). |
| 802.1Q tagged (`0x8100`) | Only the S-tag is pushed on top. The existing tag becomes the C-tag and keeps its VID and PCP. |
| Already S-tagged (`0x88A8` or legacy `0x9100`) | Copied unchanged. |

Untagged and tagged packets in the same capture get the same S-VID, so the whole file looks like one service VLAN. Some vendors use `0x9100` or `0x8100` as the S-tag TPID; change `QINQ_S_TPID` at the top of the script to generate those instead.

Every pcap-mode output is itself a valid input, so you can stack layers by running the tool more than once. For example, QinQ frames carried inside GENEVE:

```bash
python3 packet-mod.py capture.pcap qinq              # -> capture-out-qinq.pcap
python3 packet-mod.py capture-out-qinq.pcap geneve   # -> Eth / IPv4 / UDP / GENEVE / Eth / S-tag / C-tag / IP
```

NVGRE and VXLAN remove the tags from the inner frame (see above), so they cannot carry QinQ.

### Fragmented mode

With `fragmented`, about **40 %** of packets (`FRAGMENT_PROBABILITY`) are split into **two IPv4 fragments**. The split point is a random multiple of 8 bytes. The first fragment carries at least 32 bytes of payload, so the full L4 and tunnel header stays in fragment 1.

| Protocol type | What is fragmented |
|---------------|--------------------|
| IP tunnels | The **outer** IPv4 packet. Fragment 1 = outer IP + UDP/GRE + tunnel header + start of the inner packet. Fragment 2 = outer IP + the rest of the payload. |
| L2 tags | The packet's **own** IPv4 header. The tag is then added to each fragment. |

DF is cleared on fragmented packets. Both fragments have the same IP ID and a correct header checksum. Fragment 2 is timestamped 1 µs after fragment 1.

These packets are skipped (left whole): IPv6, packets with IP options, packets that are already fragments, truncated captures, and payloads too small to split.

Edit the constants near the top of the script to change the behaviour:

```python
FRAGMENT_PROBABILITY = 0.4   # share of packets that get fragmented
MIN_FIRST_FRAGMENT   = 32    # minimum payload bytes in fragment 1
```

---

## Replaying pcaps at different speeds

Any pcap from pcap mode can be sent out of an interface with `tcpreplay`. Common speed options:

```bash
IF=eth1
PCAP=capture-out-vxlan.pcap

# Original timing (uses the pcap timestamps)
sudo tcpreplay -i $IF $PCAP

# 10x faster / half speed than the original timing
sudo tcpreplay -i $IF --multiplier=10 $PCAP
sudo tcpreplay -i $IF --multiplier=0.5 $PCAP

# Fixed bit rate in Mbit/s (here 4 Gbit/s)
sudo tcpreplay -i $IF --mbps=4000 $PCAP

# Fixed packet rate
sudo tcpreplay -i $IF --pps=100000 $PCAP

# As fast as the NIC allows
sudo tcpreplay -i $IF --topspeed $PCAP

# Loop forever at 1 Gbit/s, pcap preloaded into RAM (recommended for high rates)
sudo tcpreplay -i $IF --mbps=1000 --loop=0 --preload-pcap $PCAP
```

`tcpreplay` prints the achieved rate, packet count and failed sends at the end of each run. See `man tcpreplay` for more options, such as `--limit`, `--duration` and `--stats`.

> Because pcap mode fixes the tunnel values once per run, looping one file replays the same tunnel. For more variety, generate several files (run the script a few times) and pass them all to `tcpreplay`, or use replay mode.

---

## Replay mode: live traffic at a fixed rate

Replay mode does **not** read a pcap. It builds random, valid packets of the chosen tunnel or tag in memory and sends them out of an interface at a target rate, until a duration expires or you press Ctrl-C. Use it to load-test a device at a fixed speed with a constantly changing mix of tunnel values and flows.

```text
sudo python3 packet-mod.py <iface> <PROTOCOL> <speed> [fragment] [wire] [duration=S] [mtu=N] [workers=N]
```

| Argument | Description |
|----------|-------------|
| `iface` | Interface to send on, e.g. `ens1f0`. |
| `PROTOCOL` | Any name from [Supported encapsulations](#supported-encapsulations). `none` sends plain IPv4. |
| `speed` | Bits per second with an optional decimal `K`/`M`/`G` suffix: `800M`, `2.5G`, `4G` (= 4,000,000,000 bit/s). A trailing `b`/`bps` is accepted. |
| `fragment` | Also accepts `fragmented` or `frag`. Every datagram is larger than the MTU and is sent as a group of **2–4 IPv4 fragments** that reassemble into one valid packet. See [Fragmentation in replay mode](#fragmentation-in-replay-mode). |
| `wire` | Count Ethernet wire overhead (FCS 4 + preamble 8 + IFG 12 = 24 B per frame) toward the rate. By default only L2 frame bytes are counted, which matches `tcpreplay --mbps`. |
| `duration=S` | Stop after `S` seconds. Default: run until Ctrl-C. |
| `mtu=N` | IP MTU used for packet sizing and fragmentation, 576–16000. Default: 1500. For `ppp`, the 8 bytes of PPPoE + PPP come out of this MTU. |
| `workers=N` | Number of sender processes. Default: chosen from the speed, about one per 720 Mbit/s, capped at the CPU count. |

### Examples

```bash
# 4 Gbit/s of GRE until Ctrl-C
sudo python3 packet-mod.py ens1 gre 4G

# 4 Gbit/s of fragmented GRE
sudo python3 packet-mod.py ens1 gre 4G fragment

# 800 Mbit/s of fragmented VXLAN for 60 s
sudo python3 packet-mod.py ens1 vxlan 800M fragment duration=60

# 10 Gbit/s at wire rate with jumbo frames and 8 workers
sudo python3 packet-mod.py ens1 geneve 10G wire mtu=9000 workers=8

# Plain IPv4 traffic with fragmentation, no tunnel
sudo python3 packet-mod.py ens1 none 1G fragment

# 2 Gbit/s of QinQ (S-tag + C-tag, random VIDs per datagram) for 30 s
sudo python3 packet-mod.py ens1 qinq 2G duration=30
```

### Sample output

Illustrative; actual numbers depend on your CPU and NIC.

```text
ens1: gre + outer-IP fragmentation at 4.000 Gbit/s (frame bytes), mtu 1500, 6 worker(s) on 16 cpu(s). Ctrl-C to stop.
[   2s]  3.998 Gbit/s    341,220 frames/s   126,375 groups/s  (total 126,375 groups)
[   3s]  4.001 Gbit/s    341,503 frames/s   126,480 groups/s  (total 252,855 groups)
...
done: 3,413,002 frames, 1,264,075 groups, 5.002 GB in 10.0s = 4.001 Gbit/s (target 4.000)
```

- A *group* is one datagram: either a single frame, or all the fragments of one datagram in `fragment` mode.
- Each worker spends **1–2 seconds** building its packet pool before it starts sending, so the first rate line appears after a short delay.
- If the achieved rate falls below 97 % of the target, the tool prints a warning. In that case, add CPUs or `workers=N`, or lower the speed.
- It also warns if the requested speed exceeds the link speed reported in `/sys/class/net/<iface>/speed`.

### What gets generated

- **Header format is identical to pcap mode.** Replay mode calls the same `add_<protocol>` functions, so a GRE header always has Key + Sequence, GENEVE has one option, TRILL has an inner 802.1Q tag, and so on.
- **Tunnel values vary between datagrams.** Each pre-built datagram gets its own random context: VNI, VSID/FlowID, TEID, GRE key, L2TP tunnel/session IDs, LISP instance ID, VLAN ID/PCP, QinQ S-VID/C-VID, VN-Tag VIFs, FabricPath addresses, TRILL nicknames, PPPoE session ID, … In pcap mode, by contrast, one set of values covers the whole file. Because every datagram has its own context, the GRE sequence number is a random value per datagram here, not a counter.
- **Outer Ethernet:** source MAC is the interface's own MAC. Destination MAC is `02:00:00:00:00:02`.
- **Outer IPv4:** source in `10.0.0.0/8`, destination in `172.16.0.0/24`, TTL 64, DF set unless fragmenting. Every group gets a **unique `(src IP, dst IP, IP ID)` tuple** for up to 2⁴⁸ groups, so fragments from different datagrams can never be reassembled together. This holds across all workers.
- **Inner traffic (IP tunnels):** a random Ethernet frame with about 90 % IPv4 and 10 % IPv6. IPv4 carries UDP, TCP or ICMP, and IPv6 carries UDP or TCP. Inner addresses are random from `10/8` and `2001:db8::/32`.
- **Inner traffic (L2 tags and `none`):** IPv4 carrying UDP, TCP or ICMP.
- **Checksums are valid:** IPv4 header, inner UDP/TCP/ICMP, and the outer UDP checksum of `l2tp`, `lisp`, `geneve` and `gtp`. They are corrected for each group's addresses (see [How it works](#how-it-works)). VXLAN sends an outer UDP checksum of 0, as RFC 7348 recommends.
- **Sizes:** without `fragment`, about 40 % small packets (64–300 B IP) and the rest up to the MTU. With `fragment`, the datagram's IP length is between about the MTU and 3× the MTU. Frames are padded to 60 bytes.

### Fragmentation in replay mode

| Protocol type | What is fragmented |
|---------------|--------------------|
| IP tunnels | The **outer** IPv4 packet. Fragment 1 = outer IP + UDP/GRE + tunnel header + start of the inner packet. Later fragments = outer IP + the rest of the payload. The inner packet is not touched. |
| L2 tags and `none` | The packet's **own** IPv4 packet. The tag or header is added to every fragment. For `ppp`, the PPPoE length is correct for each fragment. |

Every non-last fragment carries a multiple of 8 payload bytes, as RFC 791 requires.

### Saving live traffic to a pcap

To capture replay-mode output as a file, for example to replay it later with `tcpreplay`, send it through a veth pair and record the other end:

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up && sudo ip link set veth1 up

sudo tcpdump -i veth1 -w vxlan-live.pcap -c 100000 &
sudo python3 packet-mod.py veth0 vxlan 200M fragment duration=10

sudo ip link del veth0
```

Keep the rate modest while capturing; `tcpdump` drops packets at multi-gigabit rates.

---

## How it works

### Shared protocol builders

Each protocol is a function `add_<name>(pkt, raw, ctx) -> bytes`. It takes the original frame bytes and a **context** dict of random values (`make_context`) and returns the new frame. Headers are packed with `struct`. Scapy is used to read pcaps and to build the outer Eth/IPv4/UDP for IP tunnels. Both modes call these same functions.

To add a protocol:

1. Write `add_<name>(pkt, raw, ctx)`.
2. Add any random values it needs to `make_context`.
3. Register it in the `PROTOCOLS` dict.
4. Add it to `L2_ONLY` if it has no outer IP header.

It then works in both pcap and replay mode.

### Pcap mode

1. Reads the whole capture with Scapy (`rdpcap`) and checks that it is Ethernet.
2. Builds **one** context for the run.
3. Passes each packet's original bytes to the protocol function.
4. In fragmented mode, `fragment_ipv4` splits the IPv4 packet either *after* encapsulation (IP tunnels, so the outer header is fragmented) or *before* tagging (L2 tags).
5. Writes a classic pcap with its own small writer (`write_pcap`), keeping the original timestamps.

### Replay mode

- **Pre-built pool.** Each worker process builds a pool of 1024 datagrams (`REPLAY_POOL_SIZE`). Each one has a random inner packet, a fresh context and the protocol function applied. Building goes through Scapy and takes about 1 ms per datagram, so the pool is built up front. One entry is replaced every 1024 groups (`REPLAY_REFRESH_EVERY`), so the mix keeps changing without taking CPU from sending.
- **Patch at send time.** Only the outer IPv4 ID, source, destination and header checksum change per group. The IPv4 checksum is updated from a precomputed partial sum.
- **Incremental L4 checksum fix.** Changing the IP addresses invalidates any UDP/TCP checksum that covers them, through the pseudo-header. The tool corrects it incrementally as in RFC 1624: the outer UDP checksum for IP tunnels, and the inner UDP/TCP checksum for L2 tags.
- **Unique fragment IDs.** Group number `n` is mapped through a bijection modulo 2⁴⁸ (`n * 0x9E3779B97F4B`). The result is split into IP ID (16 bits), source (24 bits) and destination (8 bits), so no tuple repeats.
- **Parallel workers.** Each process re-seeds Python's `random` after `fork`, so workers don't produce identical traffic. Each opens its own raw `AF_PACKET` socket (with `PACKET_QDISC_BYPASS` and a 4 MB send buffer) and takes every *N*-th group number. Each worker gets an equal share of the target rate.
- **Pacing.** Workers track the bits sent against `rate × elapsed time`. They sleep or spin-wait when ahead. When more than 100 ms behind, they drop the backlog instead of bursting to catch up. Send-queue-full errors (`ENOBUFS`, `EAGAIN`) are retried.
- **Stats.** Workers publish counters to shared memory every 200 ms. The parent prints a rate line every second and a summary at exit.

---

## Verifying the output

```bash
# Summary view
tshark -r capture-out-vxlan.pcap

# Full protocol stack of each packet
tshark -r capture-out-vxlan.pcap -T fields -e frame.protocols

# Detailed decode of the first packet, with IP reassembly and checksum validation
tshark -r capture-out-gre-fragmented.pcap -o ip.defragment:TRUE \
       -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE -o tcp.check_checksum:TRUE -V -c 1
```

Wireshark decodes VXLAN (4789), GENEVE (6081), LISP (4341), L2TP (1701) and GTP-U (2152) on their standard ports automatically.

Known false alarms in Wireshark/tshark:

- **Summary looks unchanged.** The one-line summary shows the innermost protocol tshark can decode. If the input capture was itself a tunnel or a fragment, the summary can look the same as before. Use `-T fields -e frame.protocols` to see the full stack.
- **FabricPath "IPv4 total length exceeds packet length".** Wireshark's FabricPath dissector assumes every frame ends with a 4-byte FCS and cuts it off. The generated frames carry no FCS, as is normal for captures, so the dissector reports a length error on otherwise correct packets.
- **"Malformed" DNS, SIP, etc. in replay traffic.** Inner UDP/TCP packets go to well-known ports (53, 5060, …) but carry random payload, so the application-layer dissectors complain.

---

## Limitations

- IPv4 outer headers only; there is no IPv6 underlay.
- Pcap mode input must be an Ethernet capture. Other link types (Linux cooked/SLL, raw IP, 802.11) are rejected.
- Pcap mode loads the whole capture into memory, so very large files need a lot of RAM.
- Pcap mode does not enforce an MTU. Encapsulation adds 4–58 bytes per packet, so full-size input packets can exceed 1500 bytes. Use `fragmented` mode or an interface with a larger MTU when replaying.
- In pcap mode with `fragmented`, each selected packet is split into exactly two fragments.
- Replay mode is Linux-only and needs root or `CAP_NET_RAW`. The maximum rate depends on CPU count and NIC driver, since it is pure Python using `send()` with no kernel-bypass.
- Replay mode reuses a pool of 1024 pre-built datagrams per worker that changes slowly. Outer IP addresses and IP IDs are unique per group, but inner flows and tunnel values repeat while an entry stays in the pool.

---

## Contributing

Issues and pull requests are welcome, especially for new encapsulations (MPLS, VXLAN-GPE, IPv6 underlays, …), test pcaps, and performance improvements to the sender.

New protocols only need an `add_<name>` function; see [Shared protocol builders](#shared-protocol-builders).

## License

<!-- TODO: choose a license (e.g. MIT, Apache-2.0, GPL-3.0), add a LICENSE file, and reference it here. -->
To be decided.
