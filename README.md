# packet-mod

Generate tunnelled and tagged test traffic for network devices: packet brokers, DPI engines, firewalls, load balancers and NIC offloads.

The project contains two independent Python tools:

| Tool | What it does | Output |
|------|--------------|--------|
| [`packet-mod.py`](packet-mod.py) | Reads an existing pcap and wraps **every packet** in a tunnel or tag (VXLAN, GRE, GTP-U, VLAN, …). It can also fragment the packets. | A new `.pcap` file |
| [`packet_replay.py`](packet_replay.py) | Builds random tunnelled or tagged traffic from scratch and sends it out of a network interface at a fixed rate (for example `4G`). | Live traffic on the wire |

To replay a `.pcap` produced by `packet-mod.py` at a chosen speed, use [tcpreplay](https://tcpreplay.appneta.com/); see [Replaying pcaps at different speeds](#replaying-pcaps-at-different-speeds).

---

## Contents

- [Supported encapsulations](#supported-encapsulations)
- [Requirements](#requirements)
- [Installation](#installation)
- [packet-mod.py: encapsulate a pcap](#packet-modpy-encapsulate-a-pcap)
- [Replaying pcaps at different speeds](#replaying-pcaps-at-different-speeds)
- [packet_replay.py: live traffic generator](#packet_replaypy-live-traffic-generator)
- [How it works](#how-it-works)
- [Verifying the output](#verifying-the-output)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Supported encapsulations

| Name | Standard | Resulting frame | `packet-mod.py` | `packet_replay.py` |
|------|----------|-----------------|:---:|:---:|
| `vlan` | IEEE 802.1Q | Eth / 802.1Q / payload | ✓ | ✓ |
| `vntag` | Cisco VN-Tag (0x8926) | Eth / VN-Tag / payload | ✓ | ✓ |
| `fabricpath` | Cisco FabricPath (0x8903) | FP outer header / original Eth frame | ✓ | ✓ |
| `trill` | RFC 6325 (0x22F3) | Outer Eth / TRILL / Eth + 802.1Q / payload | ✓ | ✓ |
| `ppp` (`pppoe`) | RFC 2516 / RFC 1661 | Eth / PPPoE session / PPP / IP | ✓ | ✓ |
| `gre` | RFC 2784 / RFC 2890 | Eth / IPv4 / GRE / IP | ✓ | ✓ |
| `nvgre` | RFC 7637 | Eth / IPv4 / GRE (0x6558) / Eth / … | ✓ | ✓ |
| `vxlan` | RFC 7348 | Eth / IPv4 / UDP 4789 / VXLAN / Eth / … | ✓ | ✓ |
| `geneve` | RFC 8926 | Eth / IPv4 / UDP 6081 / GENEVE / Eth / … | ✓ | ✓ |
| `l2tp` | RFC 2661 (L2TPv2) | Eth / IPv4 / UDP 1701 / L2TP / PPP / IP | ✓ | ✓ |
| `lisp` | RFC 9300 | Eth / IPv4 / UDP 4341 / LISP / IP | ✓ | ✓ |
| `gtp` (`gtpu`) | 3GPP TS 29.281 (GTPv1-U) | Eth / IPv4 / UDP 2152 / GTP-U / IP | ✓ | ✓ |
| `none` | — | Unchanged. Combine with `fragmented` to fragment only | ✓ | — |

Both tools can also produce **IPv4 fragments**; see the `fragmented` / `fragment` options below.

---

## Requirements

- **Linux.** `packet_replay.py` uses `AF_PACKET` raw sockets and `fork`.
- **Python 3.9 or newer.**
- **[Scapy](https://scapy.net/)** for `packet-mod.py` (tested with 2.7.0). `packet_replay.py` uses only the standard library.
- **root or `CAP_NET_RAW`** for `packet_replay.py` and `tcpreplay`.
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

---

## packet-mod.py: encapsulate a pcap

```text
python3 packet-mod.py <file.pcap> <PROTOCOL> [fragmented]
```

| Argument | Description |
|----------|-------------|
| `file.pcap` | Input capture (pcap or pcapng). Must be an **Ethernet** capture (link type 1). |
| `PROTOCOL` | One of the names in [Supported encapsulations](#supported-encapsulations). Case is ignored, and `-` / `_` are stripped (`VN-Tag` works). |
| `fragmented` | Optional. Also accepts `fragment` or `frag`. Turns on IPv4 fragmentation, described below. |

### Examples

```bash
# Wrap every packet in VXLAN
python3 packet-mod.py capture.pcap vxlan
# -> wrote 1200 packets to capture-out-vxlan.pcap

# Add an 802.1Q tag to every packet
python3 packet-mod.py capture.pcap vlan

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

- **One coherent tunnel per run.** All random values (outer MACs and IPs, VLAN ID and PCP, VNI, VSID, TEID, GRE key, PPPoE session ID, TRILL nicknames, …) are chosen **once per run**. The whole output therefore looks like a single tunnel or tag set. Run the tool again to get different values.
- **Outer addressing** for IP tunnels uses random locally administered MACs and `10.x.x.x` IPs. DF is set unless `fragmented` is used.
- **Per-flow entropy.** VXLAN, GENEVE and LISP derive the UDP source port (49152–65535) from a hash of the inner MAC pair, as real VTEPs do. NVGRE uses the same hash for the 8-bit FlowID.
- **GRE** sets the Key and Sequence Number bits. The sequence number increases by one for every packet.
- **GENEVE** carries one 8-byte option (experimental class `0xFFFF`) with random data.
- **NVGRE and VXLAN** remove any 802.1Q tag from the inner frame (RFC 7637 §3.3, RFC 7348 §6.1).
- **TRILL** adds an 802.1Q tag to the inner frame. An inner multicast destination produces a multi-destination (M=1) frame to `01:80:c2:00:00:40`.
- **Pass-through rules:**
  - `l2tp`, `ppp`, `lisp`, `gre` and `gtp` carry IP only. Non-IP frames (ARP, LLDP, …) are copied unchanged.
  - A packet that already carries the requested layer is copied unchanged (for example, VXLAN traffic in `vxlan` mode).
  - Frames shorter than 14 bytes are copied unchanged.

### Fragmented mode

With `fragmented`, about **40 %** of packets (`FRAGMENT_PROBABILITY`) are split into **two IPv4 fragments**. The split point is a random multiple of 8 bytes. The first fragment carries at least 32 bytes of payload, so the full L4 and tunnel header stays in fragment 1.

| Mode | What is fragmented |
|------|--------------------|
| IP tunnels: `gre` `nvgre` `vxlan` `geneve` `l2tp` `lisp` `gtp` | The **outer** IPv4 packet. Fragment 1 = outer IP + UDP/GRE + tunnel header + start of the inner packet. Fragment 2 = outer IP + the rest of the payload. |
| L2 tags: `vlan` `vntag` `fabricpath` `trill` `ppp` `none` | The packet's **own** IPv4 header. The tag is then added to each fragment. |

DF is cleared on fragmented packets. Both fragments have the same IP ID and a correct header checksum. Fragment 2 is timestamped 1 µs after fragment 1.

These packets are skipped (left whole): IPv6, packets with IP options, packets that are already fragments, truncated captures, and payloads too small to split.

Edit the constants at the top of the script to change the behaviour:

```python
FRAGMENT_PROBABILITY = 0.4   # share of packets that get fragmented
MIN_FIRST_FRAGMENT   = 32    # minimum payload bytes in fragment 1
```

---

## Replaying pcaps at different speeds

Any pcap from `packet-mod.py` can be sent out of an interface with `tcpreplay`. Common speed options:

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

> Because `packet-mod.py` fixes the tunnel values once per run, looping one file replays the same tunnel. For more variety, generate several files (run it a few times) and pass them all to `tcpreplay`, or use `packet_replay.py`.

---

## packet_replay.py: live traffic generator

`packet_replay.py` does **not** read a pcap. It builds random, valid tunnelled or tagged packets in memory and sends them out of an interface at a target rate, until a duration expires or you press Ctrl-C. Use it to load-test a device at a fixed speed with a constantly changing mix of flows.

```text
sudo python3 packet_replay.py <iface> <tunnel|tag> <speed> [fragment] [wire] [duration=S] [mtu=N] [workers=N]
```

| Argument | Description |
|----------|-------------|
| `iface` | Interface to send on, e.g. `ens1f0`. |
| `tunnel\|tag` | `gre nvgre vxlan geneve l2tp lisp gtp` (outer-IPv4 tunnels) or `vlan vntag fabricpath trill ppp` (L2 tags). Aliases: `vn-tag`, `fabric-path`, `pppoe`, `gtpu`, `gtp-u`, `gtpv1`, `l2tpv2`, `vxlan-gpe` (this one sends plain VXLAN). |
| `speed` | Bits per second with an optional decimal `K`/`M`/`G` suffix: `800M`, `2.5G`, `4G` (= 4,000,000,000 bit/s). A trailing `b`/`bps` is accepted. |
| `fragment` | Every datagram is larger than the MTU and is split at the **outer** IPv4 level into fragments (typically 2–3) that reassemble into one valid tunnel packet. |
| `wire` | Count Ethernet wire overhead (FCS 4 + preamble 8 + IFG 12 = 24 B per frame) toward the rate. By default only L2 frame bytes are counted, which matches `tcpreplay --mbps`. |
| `duration=S` | Stop after `S` seconds. Default: run until Ctrl-C. |
| `mtu=N` | IP MTU used for packet sizing and fragmentation, 576–16000. Default: 1500. |
| `workers=N` | Number of sender processes. Default: chosen from the speed, about one per 720 Mbit/s, capped at the CPU count. |

### Examples

```bash
# 4 Gbit/s of GRE until Ctrl-C
sudo python3 packet_replay.py ens1 gre 4G

# 4 Gbit/s of fragmented GRE
sudo python3 packet_replay.py ens1 gre 4G fragment

# 800 Mbit/s of fragmented VXLAN for 60 s
sudo python3 packet_replay.py ens1 vxlan 800M fragment duration=60

# 10 Gbit/s at wire rate with jumbo frames and 8 workers
sudo python3 packet_replay.py ens1 geneve 10G wire mtu=9000 workers=8
```

### Sample output

Illustrative; actual numbers depend on your CPU and NIC.

```text
ens1: gre + outer-IP fragmentation -> 4.000 Gbit/s (frame bytes) mtu 1500, 6 worker(s) on 16 cpu(s). Ctrl-C to stop.
[   1s]  3.998 Gbit/s    341,220 frames/s   126,375 groups/s  (total 126,375 groups)
[   2s]  4.001 Gbit/s    341,503 frames/s   126,480 groups/s  (total 252,855 groups)
...
done: 3,413,002 frames, 1,264,075 groups, 5.002 GB in 10.0s = 4.001 Gbit/s (target 4.000)
```

A *group* is one datagram: either a single frame, or all the fragments of one datagram in `fragment` mode. If the achieved rate falls below 97 % of the target, the tool prints a warning. In that case, add CPUs or `workers=N`, or lower the speed. It also warns if the requested speed exceeds the link speed reported in `/sys/class/net/<iface>/speed`.

### What gets generated

- **Outer Ethernet:** source MAC is the interface's own MAC. Destination MAC is `02:00:00:00:00:02`.
- **Outer IPv4:** source in `10.0.0.0/8`, destination in `172.16.0.0/24`, TTL 64. Every group gets a **unique `(src IP, dst IP, IP ID)` tuple** for up to 2⁴⁸ groups, so fragments from different datagrams can never be reassembled together.
- **Tunnel fields are randomised per packet:** VNI, VSID/FlowID, TEID, GRE key/seq/checksum flags, GENEVE options (0–2 options), L2TP tunnel/session IDs, VLAN ID/PCP, VN-Tag VIFs, TRILL nicknames, PPPoE session ID, and so on.
- **Inner traffic (IP tunnels):** about 90 % IPv4 and 10 % IPv6. IPv4 carries UDP, TCP or ICMP, and IPv6 carries UDP or TCP. All L3/L4 checksums are valid, and inner addresses are random from `10/8`, `192.168/16` and `2001:db8::/32`.
- **Inner traffic (L2 tags):** IPv4 carrying UDP (checksum 0, which is legal on IPv4) or ICMP.
- **Sizes:** without `fragment`, about 40 % small packets (64–300 B IP) and the rest up to the MTU. With `fragment`, datagrams of 1 to 3 times the MTU. Frames are padded to 60 bytes.

### Saving live traffic to a pcap

To capture `packet_replay.py` output as a file, for example to replay it later with `tcpreplay`, send it through a veth pair and record the other end:

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up && sudo ip link set veth1 up

sudo tcpdump -i veth1 -w vxlan-live.pcap -c 100000 &
sudo python3 packet_replay.py veth0 vxlan 200M fragment duration=10

sudo ip link del veth0
```

Keep the rate modest while capturing; `tcpdump` drops packets at multi-gigabit rates.

---

## How it works

### packet-mod.py

1. Reads the whole capture with Scapy (`rdpcap`) and checks that it is Ethernet.
2. Builds a per-run **context** of random values (`make_context`).
3. For each packet, takes the original captured bytes and passes them to the protocol function (`add_vxlan`, `add_gre`, …). Each function returns new frame bytes. Headers are packed with `struct`; Scapy is used only to build the outer Eth/IP/UDP for IP tunnels and to compute their checksums.
4. In fragmented mode, `fragment_ipv4` splits the IPv4 packet either *after* encapsulation (IP tunnels, so the outer header is fragmented) or *before* tagging (L2 tags).
5. Writes a classic pcap with its own small writer (`write_pcap`), keeping the original timestamps.

To add a protocol, write a function `add_<name>(pkt, raw, ctx) -> bytes`. Add any random values it needs to `make_context`, register it in the `PROTOCOLS` dict, and add it to `L2_ONLY` if it has no outer IP header.

### packet_replay.py

- **Pre-built pool.** Each worker builds a pool of 4096 random datagrams at startup. It replaces one entry every 64 sends, so the traffic mix keeps changing without spending CPU on building every packet.
- **Patch at send time.** Only the outer IPv4 ID, source, destination and header checksum change per group. The checksum is updated from a precomputed partial sum, so each send is cheap.
- **Unique fragment IDs.** Group number `n` is mapped through a bijection modulo 2⁴⁸ (`n * 0x9E3779B97F4B`). The result is split into IP ID (16 bits), source (24 bits) and destination (8 bits), so no tuple repeats.
- **Parallel workers.** Each process owns its own raw `AF_PACKET` socket (with `PACKET_QDISC_BYPASS` and a 4 MB send buffer) and takes every *N*-th group number. Each worker gets an equal share of the target rate.
- **Pacing.** Workers track the bits sent against `rate × elapsed time`. They sleep or spin-wait when ahead. When more than 100 ms behind, they drop the backlog instead of bursting to catch up. Send-queue-full errors (`ENOBUFS`, `EAGAIN`) are retried.
- **Stats.** Workers publish counters to shared memory every 200 ms. The parent prints a rate line every second and a summary at exit.

---

## Verifying the output

```bash
# Summary view
tshark -r capture-out-vxlan.pcap

# Full protocol stack of each packet
tshark -r capture-out-vxlan.pcap -T fields -e frame.protocols

# Detailed decode of the first packet, with IP reassembly
tshark -r capture-out-gre-fragmented.pcap -o ip.defragment:TRUE -V -c 1
```

Wireshark decodes VXLAN (4789), GENEVE (6081), LISP (4341), L2TP (1701) and GTP-U (2152) on their standard ports automatically.

> **Tip:** tshark's one-line summary shows the innermost protocol it can decode. If the input capture was itself a tunnel or a fragment, the summary can look unchanged. Use `-T fields -e frame.protocols` to see the full stack.

---

## Limitations

- IPv4 outer headers only; there is no IPv6 underlay.
- `packet-mod.py` input must be an Ethernet capture. Other link types (Linux cooked/SLL, raw IP, 802.11) are rejected.
- `packet-mod.py` loads the whole capture into memory, so very large files need a lot of RAM.
- `packet-mod.py` does not enforce an MTU. Encapsulation adds 4–58 bytes per packet, so full-size input packets can exceed 1500 bytes. Use `fragmented` mode or an interface with a larger MTU when replaying.
- In `packet-mod.py` fragmented mode, each selected packet is split into exactly two fragments.
- `packet_replay.py` is Linux-only and needs root or `CAP_NET_RAW`. The maximum rate depends on CPU count and NIC driver, since it is pure Python using `send()` with no kernel-bypass.

---

## Contributing

Issues and pull requests are welcome, especially for new encapsulations (MPLS, VXLAN-GPE, IPv6 underlays, …), test pcaps, and performance improvements to the sender.

## License

<!-- TODO: choose a license (e.g. MIT, Apache-2.0, GPL-3.0), add a LICENSE file, and reference it here. -->
To be decided.
