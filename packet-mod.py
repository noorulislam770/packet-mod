#!/usr/bin/env python3
"""
packet-mod.py - add an extra layer / tunnel to every packet in a pcap.

Usage:
    python3 packet-mod.py file.pcap PROTOCOL [fragmented]

PROTOCOL is one of:
    vlan        IEEE 802.1Q tag
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
      * other modes (vlan, vntag, fabricpath, trill, ppp): the packet's own IPv4
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
"""
import os
import random
import struct
import sys
import zlib

from scapy.all import rdpcap, Ether, IP, UDP, GRE, Raw

VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
FRAGMENT_PROBABILITY = 0.4     # share of packets that get fragmented in "fragmented" mode
MIN_FIRST_FRAGMENT = 32        # first fragment carries at least this many payload bytes
L2_ONLY = ("vlan","none", "vntag", "fabricpath", "trill", "ppp", "pppoe")   # no outer IP header


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
# main
# --------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
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


