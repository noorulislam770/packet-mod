#!/usr/bin/env python3
"""
packet-mod.py - add an extra layer / tunnel to every packet in a pcap.

Usage:
    python3 packet-mod.py file.pcap PROTOCOL [fragmented]
    python3 packet-mod.py IFACE PROTOCOL SPEED [fragment] [wire] [duration=S] [mtu=N] [workers=N]
        (replay mode, see "Replay mode" below)

PROTOCOL is one of:
    vlan        IEEE 802.1Q tag
    qinq        IEEE 802.1ad QinQ: S-tag (0x88A8) + C-tag (0x8100). A frame that already has
                an 802.1Q tag only gets the S-tag pushed on top (its tag becomes the C-tag).
    vntag       Cisco VN-Tag (ethertype 0x8926)
    fabricpath  Cisco FabricPath (16-byte MAC-in-MAC header, ethertype 0x8903)
    nvgre       NVGRE, RFC 7637 (Eth / IPv4 / GRE 0x6558 / original frame)
    l2tp        L2TPv2 data message, RFC 2661 (Eth / IPv4 / UDP 1701 / L2TP / PPP / IP)
    ppp         PPPoE session + PPP, RFC 2516 / RFC 1661 (ethertype 0x8864)
    lisp        LISP data plane, RFC 9300 (Eth / IPv4 / UDP 4341 / LISP / IP)
    geneve      GENEVE, RFC 8926 (Eth / IPv4 / UDP 6081 / GENEVE / original frame)
    trill       TRILL, RFC 6325 (outer Eth, ethertype 0x22F3, TRILL header, inner frame)
    vxlan       VXLAN, RFC 7348 (Eth / IPv4 / UDP 4789 / VXLAN / original frame)
    gre         GRE with key + sequence number, RFC 2784 / RFC 2890 (Eth / IPv4 / GRE / original IP packet)
    gtp         GTPv1-U G-PDU, 3GPP TS 29.281 (Eth / IPv4 / UDP 2152 / GTP-U / original IP packet)

fragmented (optional third argument):
    Randomly pick about 40% of the packets (FRAGMENT_PROBABILITY) and split each into
    two IPv4 fragments.
      * IP based tunnels (nvgre, gre, l2tp, lisp, geneve, vxlan, gtp): the OUTER IPv4
        packet is fragmented. Fragment 1 = outer IP header + UDP/GRE + tunnel header +
        the start of the inner packet (MF=1). Fragment 2 = outer IP header + the
        remaining payload only, with no UDP or tunnel header.
      * other modes (vlan, qinq, vntag, fabricpath, trill, ppp): the packet's own IPv4
        header is fragmented the same way and the tag is added to each fragment.
    DF is cleared on the fragmented packets. IPv6, IP options and packets that are
    already fragments are left alone.

Output goes next to the input file as <name>-out-<protocol>.pcap, e.g.
file-out-vlan.pcap (file-out-vxlan-fragmented.pcap in fragmented mode). If that
file already exists, a counter is added (file-out-vlan-1.pcap, file-out-vlan-2.pcap,
...) so nothing is overwritten.

Notes:
  * All random values (MACs, IPs, VNIs, keys, ...) are generated once per run so
    the whole capture forms one coherent tunnel / tag set.
  * L2TP, PPP, LISP, GRE and GTP carry IP, so non-IP frames (ARP, LLDP, ...) are
    copied through unchanged.
  * NVGRE and VXLAN strip an 802.1Q tag from the inner frame (RFC 7637 3.3, RFC 7348 6.1).
  * A packet that already carries the layer is copied through unchanged.

Replay mode (no input pcap):
    python3 packet-mod.py ens1 gre 4G
    python3 packet-mod.py ens1 gre 4G fragment
    python3 packet-mod.py ens1 vxlan 800M fragment duration=60

    Generates random traffic of the chosen tunnel / tag and sends it on IFACE at SPEED
    until Ctrl-C (or duration=S). The tunnel / tag headers come from the same functions
    as the pcap mode; the inner packets are random IPv4 (and some IPv6) UDP / TCP / ICMP
    with valid checksums, and every pre-built datagram gets fresh random field values
    (VNI, key, TEID, MACs, ...). PROTOCOL can also be "none" (plain IP traffic).
    Needs root (AF_PACKET).
      SPEED      K / M / G suffix, bits per second (4G = 4,000,000,000). Counted on frame
                 bytes like tcpreplay -M; add "wire" to count FCS + preamble + IFG too.
      fragment   every datagram is split into fragments at the MTU, so the sender emits
                 groups of 2-4 fragments that reassemble into one valid packet.
                   * IP based tunnels: the OUTER IPv4 packet is fragmented (fragment 1 =
                     outer IP + UDP/GRE + tunnel header + start of the inner packet, the
                     rest only outer IP + payload). The inner packet is not touched.
                   * vlan, qinq, vntag, fabricpath, trill, ppp, none: the packet's own IPv4
                     packet is fragmented and the tag is added to every fragment.
                 Every fragment group has its own (src IP, dst IP, IP ID) tuple: the group
                 number is mapped through a bijection, so no tuple is ever repeated, even
                 across the parallel sender processes. UDP / TCP checksums are corrected
                 for the group's addresses.
      mtu=N      IP MTU used for sizing and fragmenting (default 1500; PPPoE takes 8 bytes
                 off it). Outer IPv4 only.
      workers=N  sender processes (default: picked from SPEED, at most one per cpu).
"""
import errno
import math
import multiprocessing as mp
import os
import random
import signal
import socket
import struct
import sys
import time
import zlib

from scapy.all import rdpcap, Ether, IP, UDP, GRE, Raw

VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
S_TAG_TPIDS = (0x88A8, 0x9100)   # outer (service) tag of a QinQ frame: 802.1ad and the legacy 0x9100
QINQ_S_TPID = 0x88A8           # TPID written for the QinQ S-tag (IEEE 802.1ad)
FRAGMENT_PROBABILITY = 0.4     # share of packets that get fragmented in "fragmented" mode
MIN_FIRST_FRAGMENT = 32        # first fragment carries at least this many payload bytes
L2_ONLY = ("vlan", "qinq", "dot1ad", "none", "vntag", "fabricpath", "trill", "ppp", "pppoe")   # no outer IP header


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def rand_mac():
    first = (random.randint(0, 255) & 0xFC) | 0x02   # unicast, locally administered
    return ":".join("%02x" % b for b in [first] + [random.randint(0, 255) for _ in range(5)])
def add_none(pkt,raw,ctx):
    return raw

def rand_ip():
    return "10.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))


def raw_bytes(pkt):
    """Original captured bytes of a packet."""
    orig = getattr(pkt, "original", None)
    return bytes(orig) if orig else bytes(pkt)


def flow_hash(raw):
    """Stable per-flow value (MAC pair) used for GRE FlowID / UDP source port entropy."""
    return zlib.crc32(raw[:12])


def internet_checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def l2_info(raw):
    """Return (L2 header length incl. final ethertype, final ethertype), skipping VLAN tags."""
    off = 12
    et = struct.unpack("!H", raw[off:off + 2])[0]
    while et in VLAN_TPIDS and off + 6 <= len(raw):
        off += 4
        et = struct.unpack("!H", raw[off:off + 2])[0]
    return off + 2, et


def strip_vlan(raw):
    """Remove 802.1Q / 802.1ad tags from an Ethernet frame."""
    l2_len, _ = l2_info(raw)
    return raw[:12] + raw[l2_len - 2:]


def get_l3(raw):
    """Return (l2_len, ethertype, ip_packet_bytes) for IPv4/IPv6 frames, else None."""
    l2_len, et = l2_info(raw)
    data = raw[l2_len:]
    if et == 0x0800 and len(data) >= 20:
        total = struct.unpack("!H", data[2:4])[0]
        return l2_len, et, (data[:total] if total >= 20 else data)
    if et == 0x86DD and len(data) >= 40:
        plen = struct.unpack("!H", data[4:6])[0]
        return l2_len, et, (data[:40 + plen] if plen else data)
    return None


def has_udp_port(pkt, ports):
    return pkt.haslayer(UDP) and (pkt[UDP].sport in ports or pkt[UDP].dport in ports)


def ip_encap(ctx, proto, payload):
    """Outer Ethernet + IPv4 (given protocol number) + payload."""
    p = (Ether(src=ctx["mac_src"], dst=ctx["mac_dst"]) /
         IP(src=ctx["ip_src"], dst=ctx["ip_dst"], proto=proto, ttl=64, flags=ctx["ip_flags"],
            id=random.randint(0, 0xFFFF)) /
         Raw(payload))
    return bytes(p)


def udp_encap(ctx, sport, dport, payload, chksum=None):
    """Outer Ethernet + IPv4 + UDP + payload (checksums computed by scapy unless chksum is given)."""
    p = (Ether(src=ctx["mac_src"], dst=ctx["mac_dst"]) /
         IP(src=ctx["ip_src"], dst=ctx["ip_dst"], ttl=64, flags=ctx["ip_flags"],
            id=random.randint(0, 0xFFFF)) /
         UDP(sport=sport, dport=dport, chksum=chksum) /
         Raw(payload))
    return bytes(p)


def output_path(in_path, tag):
    """<input>-out-<tag>.pcap, or <input>-out-<tag>-<n>.pcap with the first free n >= 1."""
    base = os.path.splitext(in_path)[0] + "-out-" + tag
    path = base + ".pcap"
    n = 1
    while os.path.exists(path):
        path = "%s-%d.pcap" % (base, n)
        n += 1
    return path


def write_pcap(path, frames):
    """Classic little-endian pcap, link type 1 (Ethernet). frames = [(time in us, bytes)]."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for t_us, frame in frames:
            sec, usec = divmod(t_us, 1000000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def entropy_port(raw):
    """UDP source port in the dynamic range, derived from the inner flow."""
    return 49152 + flow_hash(raw) % 16384


def fragment_ipv4(frame):
    """
    Split the IPv4 packet in an Ethernet frame into two fragments (RFC 791).
    Fragment 1 = IP header + the first `cut` payload bytes (MF=1); fragment 2 = a copy
    of the IP header + the remaining payload. `cut` is a random multiple of 8 and at
    least MIN_FIRST_FRAGMENT, so fragment 1 holds the complete L4 / tunnel header.
    Returns [frame] unchanged if it can't be fragmented (not IPv4, IP options,
    already a fragment, truncated capture, or too small).
    """
    l2_len, et = l2_info(frame)
    if et != 0x0800 or len(frame) < l2_len + 20:
        return [frame]
    ip = frame[l2_len:]
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    if ihl != 20 or total < 20 or total > len(ip) or struct.unpack("!H", ip[6:8])[0] & 0x3FFF:
        return [frame]
    payload = ip[ihl:total]
    cuts = list(range(MIN_FIRST_FRAGMENT, len(payload), 8))
    if not cuts:
        return [frame]
    cut = random.choice(cuts)
    ident = ip[4:6] if ip[4:6] != b"\0\0" else struct.pack("!H", random.randint(1, 0xFFFF))
    frags = []
    for offset, chunk, more in ((0, payload[:cut], 1), (cut, payload[cut:], 0)):
        hdr = bytearray(ip[:ihl])
        hdr[2:4] = struct.pack("!H", ihl + len(chunk))
        hdr[4:6] = ident                                             # same ID in both fragments
        hdr[6:8] = struct.pack("!H", (more << 13) | (offset // 8))   # DF=0, MF, offset in 8-byte units
        hdr[10:12] = b"\0\0"
        hdr[10:12] = struct.pack("!H", internet_checksum(bytes(hdr)))
        frags.append(frame[:l2_len] + bytes(hdr) + chunk)
    return frags


def fabricpath_addr(endnode, switch_id, sub_switch_id, lid):
    """
    48-bit FabricPath outer address:
      EndnodeID[5:0] | U/L=1 | I/G=0 | EndnodeID[7:6] | RSVD | OOO/DL |
      Switch ID (12) | Sub-Switch ID (8) | LID (16)
    """
    b0 = ((endnode & 0x3F) << 2) | 0x02
    b1 = (((endnode >> 6) & 0x03) << 6) | ((switch_id >> 8) & 0x0F)
    b2 = switch_id & 0xFF
    return struct.pack("!BBBBH", b0, b1, b2, sub_switch_id, lid)


# --------------------------------------------------------------------------
# per-run random values
# --------------------------------------------------------------------------
def make_context(fragmented):
    sw_dst, sw_src = random.sample(range(1, 4095), 2)
    nick_egress, nick_ingress = random.sample(range(1, 0xFFC0), 2)
    return {
        # outer addressing for the IP based tunnels; DF must be off if they get fragmented
        "mac_src": rand_mac(), "mac_dst": rand_mac(),
        "ip_src": rand_ip(), "ip_dst": rand_ip(),
        "ip_flags": 0 if fragmented else "DF",
        # 802.1Q
        "vlan_id": random.randint(2, 4094), "vlan_pcp": random.randint(0, 7),
        # 802.1ad QinQ: S-tag (service) + C-tag (customer)
        "qinq_svid": random.randint(2, 4094), "qinq_spcp": random.randint(0, 7),
        "qinq_cvid": random.randint(2, 4094), "qinq_cpcp": random.randint(0, 7),
        # VN-Tag
        "vn_dvif": random.randint(1, 0x3FFF), "vn_svif": random.randint(1, 0xFFF),
        # FabricPath
        "fp_dst": fabricpath_addr(random.randint(0, 255), sw_dst, random.randint(0, 255), random.randint(1, 0xFFFF)),
        "fp_src": fabricpath_addr(random.randint(0, 255), sw_src, random.randint(0, 255), random.randint(1, 0xFFFF)),
        "fp_ftag": random.randint(1, 1023), "fp_ttl": random.randint(8, 32),
        # NVGRE (VSID 0-0xFFF and 0xFFFFFF are reserved)
        "nvgre_vsid": random.randint(0x1000, 0xFFFFFE),
        # L2TP / PPPoE
        "l2tp_tid": random.randint(1, 0xFFFF), "l2tp_sid": random.randint(1, 0xFFFF),
        "pppoe_sid": random.randint(1, 0xFFFE),
        # LISP
        "lisp_iid": random.randint(1, 0xFFFFFF), "lisp_lsb": random.randint(1, 255),
        # GENEVE
        "geneve_vni": random.randint(1, 0xFFFFFF), "geneve_opt_type": random.randint(0, 0x7F),
        # TRILL
        "trill_egress": nick_egress, "trill_ingress": nick_ingress,
        "trill_hops": random.randint(16, 63),
        # VXLAN
        "vxlan_vni": random.randint(1, 0xFFFFFF),
        # GRE: random key, sequence number counts up from a random start
        "gre_key": random.getrandbits(32), "gre_seq": random.randint(0, 0xFFFFFF),
        # GTP-U
        "gtp_teid": random.randint(1, 0xFFFFFFFF),
    }


# --------------------------------------------------------------------------
# protocol functions: (scapy_pkt, raw_bytes, ctx) -> new raw bytes
# --------------------------------------------------------------------------
def add_vlan(pkt, raw, ctx):
    if struct.unpack("!H", raw[12:14])[0] in VLAN_TPIDS:
        return raw
    tci = (ctx["vlan_pcp"] << 13) | ctx["vlan_id"]
    return raw[:12] + struct.pack("!HH", 0x8100, tci) + raw[12:]


def add_qinq(pkt, raw, ctx):
    """
    IEEE 802.1ad QinQ: S-tag (TPID 0x88A8) followed by a C-tag (TPID 0x8100), each with
    PCP(3) DEI(1)=0 VID(12). Works like a provider edge port:
      * untagged frame       -> S-tag + C-tag are added
      * 802.1Q tagged frame  -> only the S-tag is pushed; the existing tag becomes the C-tag
      * already S-tagged     -> copied through unchanged
    """
    tpid = struct.unpack("!H", raw[12:14])[0]
    if tpid in S_TAG_TPIDS:
        return raw
    s_tag = struct.pack("!HH", QINQ_S_TPID, (ctx["qinq_spcp"] << 13) | ctx["qinq_svid"])
    if tpid == 0x8100:
        return raw[:12] + s_tag + raw[12:]
    c_tag = struct.pack("!HH", 0x8100, (ctx["qinq_cpcp"] << 13) | ctx["qinq_cvid"])
    return raw[:12] + s_tag + c_tag + raw[12:]


def add_vntag(pkt, raw, ctx):
    """VN-Tag: ethertype 0x8926 + D(1) P(1) DVIF(14) L(1) R(1) Ver(2) SVIF(12)."""
    if struct.unpack("!H", raw[12:14])[0] == 0x8926:
        return raw
    d, p, looped, rsvd, ver = 0, 0, 0, 0, 0
    tag = ((d << 31) | (p << 30) | (ctx["vn_dvif"] << 16) | (looped << 15) |
           (rsvd << 14) | (ver << 12) | ctx["vn_svif"])
    return raw[:12] + struct.pack("!HI", 0x8926, tag) + raw[12:]


def add_fabricpath(pkt, raw, ctx):
    """16-byte header: outer DA(6) outer SA(6) 0x8903 FTAG(10)/TTL(6), then the original frame."""
    if struct.unpack("!H", raw[12:14])[0] == 0x8903:
        return raw
    hdr = (ctx["fp_dst"] + ctx["fp_src"] +
           struct.pack("!HH", 0x8903, (ctx["fp_ftag"] << 6) | ctx["fp_ttl"]))
    return hdr + raw


def add_nvgre(pkt, raw, ctx):
    """GRE with K bit, protocol 0x6558 (Transparent Ethernet Bridging), key = VSID(24)|FlowID(8)."""
    if pkt.haslayer(GRE) and pkt[GRE].proto == 0x6558:
        return raw
    key = (ctx["nvgre_vsid"] << 8) | (flow_hash(raw) & 0xFF)
    gre = struct.pack("!HHI", 0x2000, 0x6558, key)
    return ip_encap(ctx, 47, gre + strip_vlan(raw))


def add_l2tp(pkt, raw, ctx):
    """L2TPv2 data message (T=0, L=1, Ver=2) carrying PPP (FF 03 + protocol + IP packet)."""
    if has_udp_port(pkt, (1701,)):
        return raw
    l3 = get_l3(raw)
    if l3 is None:
        return raw
    _, et, ip_pkt = l3
    ppp = b"\xff\x03" + struct.pack("!H", 0x0021 if et == 0x0800 else 0x0057) + ip_pkt
    l2tp = struct.pack("!HHHH", 0x4002, 8 + len(ppp), ctx["l2tp_tid"], ctx["l2tp_sid"]) + ppp
    return udp_encap(ctx, 1701, 1701, l2tp)


def add_ppp(pkt, raw, ctx):
    """PPPoE session stage (ethertype 0x8864) with a PPP protocol field and the IP packet."""
    l3 = get_l3(raw)
    if l3 is None:
        return raw
    l2_len, et, ip_pkt = l3
    if et in (0x8863, 0x8864):
        return raw
    ppp = struct.pack("!H", 0x0021 if et == 0x0800 else 0x0057) + ip_pkt
    pppoe = struct.pack("!BBHH", 0x11, 0x00, ctx["pppoe_sid"], len(ppp))   # ver/type, code=session data
    return raw[:l2_len - 2] + struct.pack("!H", 0x8864) + pppoe + ppp


def add_lisp(pkt, raw, ctx):
    """LISP header: N, L, I flags | Nonce(24) | Instance ID(24) | LSBs(8), UDP dport 4341."""
    if has_udp_port(pkt, (4341, 4342)):
        return raw
    l3 = get_l3(raw)
    if l3 is None:
        return raw
    _, _, ip_pkt = l3
    flags = 0x80 | 0x40 | 0x08
    hdr = struct.pack("!II", (flags << 24) | random.getrandbits(24),
                      (ctx["lisp_iid"] << 8) | ctx["lisp_lsb"])
    return udp_encap(ctx, entropy_port(raw), 4341, hdr + ip_pkt)


def add_geneve(pkt, raw, ctx):
    """GENEVE: Ver=0, one 8-byte option (experimental class), protocol 0x6558, 24-bit VNI."""
    if has_udp_port(pkt, (6081,)):
        return raw
    option = struct.pack("!HBB", 0xFFFF, ctx["geneve_opt_type"], 1) + os.urandom(4)
    hdr = struct.pack("!BBHI", len(option) // 4, 0x00, 0x6558, ctx["geneve_vni"] << 8)
    return udp_encap(ctx, entropy_port(raw), 6081, hdr + option + raw)


def add_trill(pkt, raw, ctx):
    """
    Outer Ethernet (0x22F3) + 6-byte TRILL header + inner frame. The inner frame
    carries an 802.1Q tag. Multicast inner DA -> multi-destination (M=1) to All-RBridges.
    """
    if struct.unpack("!H", raw[12:14])[0] == 0x22F3:
        return raw
    inner = add_vlan(pkt, raw, ctx)
    multi = raw[0] & 0x01
    outer_dst = bytes.fromhex("0180c2000040") if multi else bytes.fromhex(ctx["mac_dst"].replace(":", ""))
    outer_src = bytes.fromhex(ctx["mac_src"].replace(":", ""))
    # V(2)=0 R(2)=0 M(1) OpLength(5)=0 HopCount(6)
    first = (multi << 11) | ctx["trill_hops"]
    trill = struct.pack("!HHH", first, ctx["trill_egress"], ctx["trill_ingress"])
    return outer_dst + outer_src + struct.pack("!H", 0x22F3) + trill + inner


def add_vxlan(pkt, raw, ctx):
    """
    VXLAN (RFC 7348): UDP dport 4789, source port from the dynamic range, UDP checksum
    0 (SHOULD be zero). Header = flags 0x08 (I bit, VNI valid) + 24 reserved bits,
    then VNI (24) + 8 reserved bits. Followed by the original Ethernet frame.
    """
    if has_udp_port(pkt, (4789,)):
        return raw
    hdr = struct.pack("!II", 0x08000000, ctx["vxlan_vni"] << 8)
    return udp_encap(ctx, entropy_port(raw), 4789, hdr + strip_vlan(raw), chksum=0)


def add_gre(pkt, raw, ctx):
    """
    GRE (RFC 2784 + RFC 2890) carrying the original IP packet: flags 0x3000 (K and S
    set, version 0), protocol type = 0x0800 / 0x86DD, then a random 32-bit Key and a
    Sequence Number that increases by one for every encapsulated packet.
    """
    if pkt.haslayer(GRE):
        return raw
    l3 = get_l3(raw)
    if l3 is None:
        return raw
    _, et, ip_pkt = l3
    seq = ctx["gre_seq"]
    ctx["gre_seq"] = (seq + 1) & 0xFFFFFFFF
    hdr = struct.pack("!HHII", 0x3000, et, ctx["gre_key"], seq)
    return ip_encap(ctx, 47, hdr + ip_pkt)


def add_gtp(pkt, raw, ctx):
    """
    GTPv1-U G-PDU (3GPP TS 29.281): UDP 2152 -> 2152. Header = flags 0x30 (version 1,
    PT=1, no E/S/PN), message type 0xFF, length (bytes after the first 8), TEID.
    The T-PDU is the original IP packet.
    """
    if has_udp_port(pkt, (2152,)):
        return raw
    l3 = get_l3(raw)
    if l3 is None:
        return raw
    _, _, ip_pkt = l3
    hdr = struct.pack("!BBHI", 0x30, 0xFF, len(ip_pkt), ctx["gtp_teid"])
    return udp_encap(ctx, 2152, 2152, hdr + ip_pkt)


PROTOCOLS = {
    "vlan": add_vlan,
    "qinq": add_qinq,
    "dot1ad": add_qinq,
    "none" : add_none,
    "vntag": add_vntag,
    "fabricpath": add_fabricpath,
    "nvgre": add_nvgre,
    "l2tp": add_l2tp,
    "ppp": add_ppp,
    "pppoe": add_ppp,
    "lisp": add_lisp,
    "geneve": add_geneve,
    "trill": add_trill,
    "vxlan": add_vxlan,
    "gre": add_gre,
    "gtp": add_gtp,
    "gtpu": add_gtp,
}


# --------------------------------------------------------------------------
# replay mode: random traffic of one protocol, sent on an interface at a given speed
# --------------------------------------------------------------------------
REPLAY_POOL_SIZE = 1024          # pre-built random datagrams per sender process (~1 ms each to build)
REPLAY_REFRESH_EVERY = 1024      # replace one pool entry every N groups so field values keep changing
REPLAY_MIN_FRAME = 60            # runt frames are padded to this size (no FCS), like a NIC does
REPLAY_FPS_PER_WORKER = 90000    # frames/s one Python process is assumed to manage (picks the worker count)
REPLAY_DST_MAC = "02:00:00:00:00:02"
WIRE_OVERHEAD = 24               # FCS 4 + preamble 8 + IFG 12, counted with the "wire" option
FRAGMENT_WORDS = ("fragmented", "fragment", "frag")
IPV4_HEADER = struct.Struct("!BBHHHBBHII")
GROUP_MASK = (1 << 48) - 1
GROUP_MULTIPLIER = 0x9E3779B97F4B    # odd: n -> n * GROUP_MULTIPLIER mod 2^48 never repeats


def rand_mac_bytes():
    return bytes.fromhex(rand_mac().replace(":", ""))


def words_sum(data):
    """16-bit ones' complement sum of the words in data (folded, not inverted)."""
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def pseudo_header(src, dst, proto, length):
    if len(src) == 4:
        return src + dst + struct.pack("!BBH", 0, proto, length)
    return src + dst + struct.pack("!I3xB", length, proto)


def random_l4(length, src, dst):
    """Random UDP / TCP / ICMP segment of exactly `length` bytes with a valid checksum."""
    r = random.random()
    proto = 17 if r < 0.6 else (6 if r < 0.9 else (1 if len(src) == 4 else 17))
    if proto == 17:
        seg = bytearray(struct.pack("!HHHH", random.randint(1024, 65535),
                                    random.choice((53, 80, 123, 443, 5060, 8080)), length, 0))
        seg += random.randbytes(length - 8)
        seg[6:8] = struct.pack("!H", internet_checksum(pseudo_header(src, dst, 17, length) + bytes(seg)) or 0xFFFF)
    elif proto == 6:
        seg = bytearray(struct.pack("!HHIIBBHHH", random.randint(1024, 65535),
                                    random.choice((80, 443, 8080, 3306)), random.getrandbits(32),
                                    random.getrandbits(32), 5 << 4, random.choice((0x10, 0x18)),
                                    random.getrandbits(16), 0, 0))
        seg += random.randbytes(length - 20)
        seg[16:18] = struct.pack("!H", internet_checksum(pseudo_header(src, dst, 6, length) + bytes(seg)))
    else:
        seg = bytearray(struct.pack("!BBHHH", 8, 0, 0, random.getrandbits(16), random.getrandbits(16)))
        seg += random.randbytes(length - 8)
        seg[2:4] = struct.pack("!H", internet_checksum(bytes(seg)))
    return proto, bytes(seg)


def random_ip_packet(length, allow_v6):
    """Random IPv4 packet (IPv6 about 10% of the time if allowed) of exactly `length` bytes."""
    if allow_v6 and random.random() < 0.1:
        src = b"\x20\x01\x0d\xb8" + random.randbytes(12)
        dst = b"\x20\x01\x0d\xb8" + random.randbytes(12)
        proto, seg = random_l4(length - 40, src, dst)
        return struct.pack("!IHBB", 0x60000000 | random.getrandbits(20), len(seg), proto,
                           random.randint(32, 128)) + src + dst + seg
    src, dst = socket.inet_aton(rand_ip()), socket.inet_aton(rand_ip())
    proto, seg = random_l4(length - 20, src, dst)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, random.choice((0, 0, 0, 0x28, 0xB8)), 20 + len(seg),
                      random.getrandbits(16), 0x4000, random.randint(32, 128), proto, 0, src, dst)
    return hdr[:10] + struct.pack("!H", internet_checksum(hdr)) + hdr[12:] + seg


def random_frame(length, dst_mac, src_mac, allow_v6):
    ip = random_ip_packet(length, allow_v6)
    return dst_mac + src_mac + (b"\x86\xdd" if ip[0] >> 4 == 6 else b"\x08\x00") + ip


def split_datagram(payload, fragment, max_payload):
    """[(offset, chunk, more_fragments)]; non-last chunks are multiples of 8 bytes (RFC 791)."""
    if not fragment:
        return [(0, payload, False)]
    size = max_payload // 8 * 8
    return [(pos, payload[pos:pos + size], pos + size < len(payload)) for pos in range(0, len(payload), size)]


def frag_flags(pos, more, fragment):
    """IPv4 flags + fragment offset: MF and offset when fragmenting, DF otherwise."""
    return ((0x2000 if more else 0) | (pos >> 3)) if fragment else 0x4000


def finish_entry(pieces, fix):
    """pieces = [(head, flags_frag, ip_total_len, proto, chunk)] -> (fragments, frame_bytes, fix).
    Everything that does not depend on the group (IP ID / src / dst) is computed here once."""
    frags, total = [], 0
    for head, ff, tl, proto, chunk in pieces:
        pad = max(0, REPLAY_MIN_FRAME - len(head) - tl)           # pad is not part of the IP length
        frags.append((head, ff, tl, 0x4500 + tl + ff + ((64 << 8) | proto), proto, chunk + bytes(pad)))
        total += len(head) + tl + pad
    return tuple(frags), total, fix


def tunnel_entry(cfg, ctx, length, mtu):
    """IP based tunnel: encapsulate a random inner frame with the pcap-mode function, then
    cut the OUTER IPv4 payload into fragments. None if the size does not fit the mode."""
    raw = random_frame(length, rand_mac_bytes(), rand_mac_bytes(), True)
    out = cfg["func"](Ether(raw), raw, ctx)                       # Ether / IPv4 (no options) / ...
    if out[12:14] != b"\x08\x00" or out[14] != 0x45:
        raise RuntimeError("%s did not return an Ethernet / IPv4 frame" % cfg["name"])
    proto, payload = out[23], out[34:14 + struct.unpack("!H", out[16:18])[0]]
    if (len(payload) > mtu - 20) != cfg["fragment"]:
        return None
    fix = None
    if proto == 17 and payload[6:8] != b"\0\0":                   # UDP checksum covers the outer addresses
        fix = (6, words_sum(out[26:34]))
    pieces = [(out[:14], frag_flags(pos, more, cfg["fragment"]), 20 + len(chunk), proto, chunk)
              for pos, chunk, more in split_datagram(payload, cfg["fragment"], mtu - 20)]
    return finish_entry(pieces, fix)


def l2_entry(cfg, ctx, length, mtu):
    """L2-only mode: fragment the packet's own IPv4 packet and let the pcap-mode function
    add the tag / header to every fragment (as pcap mode does)."""
    ip_pkt = random_ip_packet(length, False)
    proto, src_dst = ip_pkt[9], ip_pkt[12:20]
    fix = (6 if proto == 17 else 16, words_sum(src_dst)) if proto in (6, 17) else None
    src, dst = struct.unpack("!II", src_dst)
    link = cfg["dmac"] + cfg["smac"] + b"\x08\x00"
    pieces = []
    for pos, chunk, more in split_datagram(ip_pkt[20:], cfg["fragment"], mtu - 20):
        ff, tl = frag_flags(pos, more, cfg["fragment"]), 20 + len(chunk)
        ip = IPV4_HEADER.pack(0x45, 0, tl, 0, ff, 64, proto, 0, src, dst) + chunk
        frame = link + ip
        out = cfg["func"](Ether(frame), frame, ctx)
        if not out.endswith(ip):
            raise RuntimeError("%s does not keep the IPv4 packet at the end of the frame" % cfg["name"])
        pieces.append((out[:len(out) - tl], ff, tl, proto, chunk))
    return finish_entry(pieces, fix)


def make_entry(cfg):
    """One random, pre-built datagram. Its fields are fresh random values (own make_context()),
    and nothing in it depends on the group's IP ID / src / dst, which are patched when sending."""
    name, fragment = cfg["name"], cfg["fragment"]
    l2_only = name in L2_ONLY
    mtu = cfg["mtu"] - (8 if name in ("ppp", "pppoe") else 0)      # PPPoE + PPP come out of the MTU
    ctx = make_context(fragment)
    ctx["mac_src"], ctx["mac_dst"] = cfg["mac_src"], cfg["mac_dst"]
    for _ in range(100):
        if fragment:
            length = random.randint(mtu + 1, 3 * mtu) if l2_only else random.randint(mtu - 100, 3 * mtu)
        else:
            top = mtu if l2_only else mtu - 90                       # leave room for the tunnel headers
            length = random.randint(64, min(300, top)) if random.random() < 0.4 else random.randint(min(300, top), top)
        entry = (l2_entry if l2_only else tunnel_entry)(cfg, ctx, max(length, 64), mtu)
        if entry:
            return entry
    raise RuntimeError("could not size a %s datagram for mtu %d" % (name, cfg["mtu"]))


def group_ids(n):
    """Group number -> (IP ID, src, dst). The map is a bijection on 48 bits, so no
    (src, dst, ID) tuple is ever used twice, which random IDs could not guarantee."""
    x = (n * GROUP_MULTIPLIER) & GROUP_MASK
    return x & 0xFFFF, 0x0A000000 | ((x >> 16) & 0xFFFFFF), 0xAC100000 | (x >> 40)


def group_frames(entry, n):
    """Frames of fragment group number n: IPv4 ID / src / dst / checksum patched in, and the
    UDP / TCP checksum in the first fragment corrected for the new addresses (RFC 1624)."""
    frags, _, fix = entry
    ident, src, dst = group_ids(n)
    addr_sum = (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF)
    out = []
    for i, (head, ff, tl, partial, proto, payload) in enumerate(frags):
        if fix and i == 0:
            off, old = fix
            s = (~((payload[off] << 8) | payload[off + 1]) & 0xFFFF) + (~old & 0xFFFF) + addr_sum
            s = (s & 0xFFFF) + (s >> 16)
            s = (s & 0xFFFF) + (s >> 16)
            payload = payload[:off] + struct.pack("!H", ~s & 0xFFFF or 0xFFFF) + payload[off + 2:]
        s = partial + ident + addr_sum
        s = (s & 0xFFFF) + (s >> 16)
        s = (s & 0xFFFF) + (s >> 16)
        out.append(head + IPV4_HEADER.pack(0x45, 0, tl, ident, ff, 64, proto, ~s & 0xFFFF, src, dst) + payload)
    return out


def open_raw_socket(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.bind((iface, 0))
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 22)
    except OSError:
        pass
    try:
        s.setsockopt(263, 20, 1)          # SOL_PACKET, PACKET_QDISC_BYPASS
    except OSError:
        pass
    return s


def replay_worker(idx, nworkers, cfg, stats, stop):
    """Send striped group numbers idx, idx + nworkers, ... paced to this worker's share of the speed."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    random.seed(os.urandom(16))                  # forked workers must not share one random sequence
    pool = [make_entry(cfg) for _ in range(REPLAY_POOL_SIZE)]
    send = open_raw_socket(cfg["iface"]).send
    rate, overhead = cfg["rate"] / nworkers, cfg["overhead"]
    perf = time.perf_counter
    base = 5 * idx                               # stats slots: frames, bytes, groups, errors, active us
    n, k = idx, 0
    frames = nbytes = groups = errs = 0
    bits = 0.0
    t0 = t_begin = perf()
    deadline = t0 + cfg["duration"] if cfg["duration"] else None
    next_pub = t0 + 0.2
    warned = False
    while True:
        entry = pool[random.randrange(REPLAY_POOL_SIZE)]
        fl = group_frames(entry, n)
        for f in fl:
            while True:
                try:
                    send(f)
                    break
                except OSError as e:
                    if e.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR):
                        time.sleep(0.0001)       # tx queue full: wait for the NIC
                        continue
                    errs += 1
                    if not warned:
                        warned = True
                        print("worker %d: send failed: %s (frame of %d bytes)" % (idx, e, len(f)), file=sys.stderr)
                    break
        n += nworkers
        groups += 1
        frames += len(fl)
        nbytes += entry[1]
        bits += (entry[1] + overhead * len(fl)) * 8
        k += 1
        if not k % REPLAY_REFRESH_EVERY:
            pool[random.randrange(REPLAY_POOL_SIZE)] = make_entry(cfg)

        due = t0 + bits / rate
        now = perf()
        if due > now:
            if due - now > 0.0006:
                time.sleep(due - now - 0.0004)
            while perf() < due:
                pass
            now = perf()
        elif now - due > 0.1:
            t0 += now - due - 0.02               # fell far behind: drop the debt, no catch-up burst
        if now >= next_pub:
            stats[base:base + 5] = (frames, nbytes, groups, errs, int((now - t_begin) * 1e6))
            next_pub = now + 0.2
            if stop.is_set() or (deadline and now >= deadline):
                break
    stats[base:base + 5] = (frames, nbytes, groups, errs, int((perf() - t_begin) * 1e6))


def parse_rate(text):
    """'400M' / '4G' / '2.5g' / '10000000' -> bits per second."""
    text = text.strip().lower()
    for suffix in ("bps", "b"):
        if text.endswith(suffix):
            text = text[:-len(suffix)]
            break
    mult = 1
    if text and text[-1] in "kmg":
        mult = {"k": 1e3, "m": 1e6, "g": 1e9}[text[-1]]
        text = text[:-1]
    return float(text) * mult


def replay_main(args):
    """args = IFACE PROTOCOL SPEED [fragment] [wire] [duration=S] [mtu=N] [workers=N]"""
    iface = args[0]
    name = args[1].lower().replace("-", "").replace("_", "")
    func = PROTOCOLS.get(name)
    if func is None:
        print("unknown protocol '%s' (choose from: %s)" % (args[1], ", ".join(PROTOCOLS)), file=sys.stderr)
        return 2
    try:
        rate = parse_rate(args[2])
        assert rate > 0
    except (ValueError, AssertionError):
        print("bad speed '%s' (examples: 400M, 4G, 2.5G)" % args[2], file=sys.stderr)
        return 2
    fragment, overhead, duration, mtu, workers = False, 0, 0.0, 1500, 0
    try:
        for opt in args[3:]:
            opt = opt.lower()
            if opt in FRAGMENT_WORDS:
                fragment = True
            elif opt == "wire":
                overhead = WIRE_OVERHEAD
            elif opt.startswith("duration="):
                duration = float(opt[9:])
            elif opt.startswith("mtu="):
                mtu = int(opt[4:])
            elif opt.startswith("workers="):
                workers = int(opt[8:])
            else:
                print("unknown option '%s'" % opt, file=sys.stderr)
                return 2
    except ValueError:
        print("bad option value in: %s" % " ".join(args[3:]), file=sys.stderr)
        return 2
    if not 576 <= mtu <= 16000:
        print("mtu must be 576..16000", file=sys.stderr)
        return 2

    sysdir = "/sys/class/net/" + iface
    if not os.path.isdir(sysdir):
        print("'%s' is neither a pcap file nor an interface (interfaces: %s)" %
              (iface, " ".join(os.listdir("/sys/class/net"))), file=sys.stderr)
        return 2
    smac = bytes.fromhex(open(sysdir + "/address").read().strip().replace(":", ""))
    try:
        open_raw_socket(iface).close()
    except PermissionError:
        print("raw sockets need root (CAP_NET_RAW)", file=sys.stderr)
        return 1
    try:
        link = int(open(sysdir + "/speed").read())
        if 0 < link * 1e6 < rate:
            print("warning: asked for %.2f Gbit/s but the link speed of %s is %.2f Gbit/s" %
                  (rate / 1e9, iface, link / 1e3), file=sys.stderr)
    except (OSError, ValueError):
        pass

    ncpu = os.cpu_count() or 1
    if not workers:
        workers = max(1, min(ncpu, math.ceil(rate / 8000 / REPLAY_FPS_PER_WORKER)))
    cfg = {"iface": iface, "name": name, "func": func, "fragment": fragment, "mtu": mtu, "rate": rate,
           "overhead": overhead, "duration": duration, "smac": smac, "dmac": bytes.fromhex(REPLAY_DST_MAC.replace(":", "")),
           "mac_src": ":".join("%02x" % b for b in smac), "mac_dst": REPLAY_DST_MAC}
    print("%s: %s%s at %.3f Gbit/s (%s), mtu %d, %d worker(s) on %d cpu(s). Ctrl-C to stop." % (
        iface, name, " + outer-IP fragmentation" if fragment and name not in L2_ONLY else
        (" + IP fragmentation" if fragment else ""), rate / 1e9, "wire rate" if overhead else "frame bytes",
        mtu, workers, ncpu))

    ctx = mp.get_context("fork")
    stats = ctx.RawArray("Q", 5 * workers)
    stop = ctx.Event()
    procs = [ctx.Process(target=replay_worker, args=(i, workers, cfg, stats, stop)) for i in range(workers)]
    for p in procs:
        p.start()

    def totals():
        s = list(stats)
        return [sum(s[j::5]) for j in range(4)]

    t_start = time.monotonic()
    last_t, last = t_start, totals()
    try:
        while any(p.is_alive() for p in procs):
            time.sleep(1.0)
            now, cur = time.monotonic(), totals()
            if cur[0] != last[0]:
                dt = now - last_t
                print("[%4.0fs] %6.3f Gbit/s  %9s frames/s  %8s groups/s  (total %s groups)" % (
                    now - t_start, (cur[1] - last[1]) * 8 / dt / 1e9, format((cur[0] - last[0]) / dt, ",.0f"),
                    format((cur[2] - last[2]) / dt, ",.0f"), format(cur[2], ",")), flush=True)
            last_t, last = now, cur
    except KeyboardInterrupt:
        pass
    stop.set()
    for p in procs:
        p.join()
    frames, nbytes, groups, errs = totals()
    elapsed = max(list(stats)[4::5]) / 1e6 or (time.monotonic() - t_start)   # time spent sending
    achieved = (nbytes + overhead * frames) * 8 / elapsed
    print("done: %s frames, %s groups, %.3f GB in %.1fs = %.3f Gbit/s (target %.3f)%s" % (
        format(frames, ","), format(groups, ","), nbytes / 1e9, elapsed, achieved / 1e9, rate / 1e9,
        ", %d send errors" % errs if errs else ""))
    if achieved < 0.97 * rate:
        print("warning: target speed not sustained - use more cpus / workers=N or a lower speed", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if len(args) >= 3 and not os.path.isfile(args[0]) and args[2].lower() not in FRAGMENT_WORDS:
        sys.exit(replay_main(args))                  # IFACE PROTOCOL SPEED ...: replay mode
    fragmented = len(args) == 3 and args[2].lower() in ("fragmented", "fragment", "frag")
    if len(args) not in (2, 3) or (len(args) == 3 and not fragmented):
        sys.exit("usage: python3 packet-mod.py file.pcap PROTOCOL [fragmented]\n"
                 "protocols: " + ", ".join(PROTOCOLS))

    in_path = args[0]
    name = args[1].lower().replace("-", "").replace("_", "")
    func = PROTOCOLS.get(name)
    if func is None:
        sys.exit("unknown protocol '%s' (choose from: %s)" % (args[1], ", ".join(PROTOCOLS)))

    packets = rdpcap(in_path)
    if len(packets) == 0:
        sys.exit("no packets in %s" % in_path)
    if not isinstance(packets[0], Ether):
        sys.exit("only Ethernet (link type 1) captures are supported")

    ctx = make_context(fragmented)
    frames = []                      # (time in microseconds, frame bytes)
    for pkt in packets:
        raw = raw_bytes(pkt)
        if len(raw) < 14:
            out = [raw]
        elif fragmented and random.random() < FRAGMENT_PROBABILITY:
            if name in L2_ONLY:      # fragment the packet's own IP header, tag each fragment
                out = [func(pkt, f, ctx) for f in fragment_ipv4(raw)]
            else:                    # encapsulate first, then fragment the outer IP packet
                out = fragment_ipv4(func(pkt, raw, ctx))
        else:
            out = [func(pkt, raw, ctx)]
        t_us = int(round(float(pkt.time) * 1e6))
        for i, frame in enumerate(out):
            frames.append((t_us + i, frame))     # fragments follow each other by 1 us

    out_path = output_path(in_path, name + ("-fragmented" if fragmented else ""))
    write_pcap(out_path, frames)
    print("wrote %d packets to %s" % (len(frames), out_path))


if __name__ == "__main__":
    main()