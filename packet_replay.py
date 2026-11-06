#!/usr/bin/env python3
"""packet_replay.py - random tunnel/tag traffic generator with paced replay.

Replay mode for packet-mod.py:

    packet-mod.py <iface> <tunnel|tag> <speed> [fragment] [wire] [duration=S] [mtu=N] [workers=N]

    packet-mod.py ens1 gre 4G
    packet-mod.py ens1 gre 4G fragment
    packet-mod.py ens1 vxlan 800M fragment duration=60

  tunnel/tag : gre nvgre vxlan geneve l2tp lisp gtp   (outer IPv4 tunnels)
               vlan vntag fabricpath trill ppp        (L2 tags, IPv4 inside)
  speed      : K/M/G suffix, decimal, bits per second (4G = 4,000,000,000 bit/s).
               Counted on L2 frame bytes (no FCS/preamble/IFG) like tcpreplay -M;
               add `wire` to also count FCS+preamble+IFG (24 B per frame).
  fragment   : every datagram is split at the OUTER IPv4 level into fragments that
               reassemble into one valid tunnel packet. Each fragment group has a
               unique (src IP, dst IP, IP ID) tuple.
  duration=S : stop after S seconds (default: run until Ctrl-C)
  mtu=N      : IP MTU used for fragmenting / sizing (default 1500)
  workers=N  : sender processes (default: chosen from the speed)

Needs root (AF_PACKET). Hook into packet-mod.py with:

    if len(sys.argv) >= 4 and os.path.isdir('/sys/class/net/' + sys.argv[1]):
        import packet_replay; sys.exit(packet_replay.main(sys.argv[1:]))
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

POOL_SIZE = 4096          # pre-built random datagrams per worker
REFRESH_EVERY = 64        # replace one pool entry every N groups (keeps inner fields fresh)
DEFAULT_MTU = 1500
MIN_FRAME = 60            # pad runt frames (no FCS) like a NIC would
DST_MAC = bytes.fromhex("020000000002")
WIRE_OVERHEAD = 24        # FCS 4 + preamble 8 + IFG 12
FPS_PER_WORKER = 90_000   # conservative per-process frame rate used to pick worker count

IP_HDR = struct.Struct("!BBHHHBBHII")
MASK48 = (1 << 48) - 1
ID_MULT = 0x9E3779B97F4B  # odd, so n -> n*ID_MULT mod 2^48 is a bijection (no repeats)


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def csum(data):
    """RFC 1071 internet checksum."""
    if len(data) & 1:
        data += b"\0"
    s = sum(memoryview(data).cast("H"))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    if sys.byteorder == "little":
        s = ((s & 0xFF) << 8) | (s >> 8)
    return ~s & 0xFFFF


def rnd_mac(rnd):
    b = bytearray(rnd.randbytes(6))
    b[0] = (b[0] & 0xFC) | 0x02          # unicast, locally administered
    return bytes(b)


def rnd_ip4(rnd):
    if rnd.random() < 0.7:
        return struct.pack("!I", 0x0A000000 | rnd.getrandbits(24))
    return struct.pack("!I", 0xC0A80000 | rnd.getrandbits(16))


def rnd_ip6(rnd):
    return b"\x20\x01\x0d\xb8" + rnd.randbytes(12)


def pseudo_hdr(src, dst, proto, length):
    if len(src) == 4:
        return src + dst + struct.pack("!BBH", 0, proto, length)
    return src + dst + struct.pack("!I3xB", length, proto)


def ip4_header(rnd, total, proto, src, dst):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, rnd.choice((0, 0, 0, 0x28, 0xB8)), total,
                    rnd.getrandbits(16), 0x4000, rnd.randint(32, 128), proto, 0, src, dst)
    return h[:10] + struct.pack("!H", csum(h)) + h[12:]


# ----------------------------------------------------------------------------
# inner packets
# ----------------------------------------------------------------------------
def l4_segment(rnd, seg_len, src=None, dst=None):
    """Random UDP/TCP/ICMP segment of exactly seg_len bytes -> (ip_proto, bytes).
    Without src/dst (L2-tag mode, where the group's IPs are chosen at send time)
    only UDP with checksum 0 (legal over IPv4) and ICMP are used."""
    r = rnd.random()
    if src is None:
        proto = 17 if r < 0.8 else 1
    elif len(src) == 4:
        proto = 17 if r < 0.6 else (6 if r < 0.9 else 1)
    else:
        proto = 17 if r < 0.6 else 6

    if proto == 17:
        seg = bytearray(struct.pack("!HHHH", rnd.randint(1024, 65535),
                                    rnd.choice((53, 80, 123, 443, 5060, 8080)), seg_len, 0))
        seg += rnd.randbytes(seg_len - 8)
        if src is not None:
            seg[6:8] = struct.pack("!H", csum(pseudo_hdr(src, dst, 17, seg_len) + seg) or 0xFFFF)
    elif proto == 6:
        seg = bytearray(struct.pack("!HHIIBBHHH", rnd.randint(1024, 65535),
                                    rnd.choice((80, 443, 8080, 3306)), rnd.getrandbits(32),
                                    rnd.getrandbits(32), 5 << 4, rnd.choice((0x10, 0x18)),
                                    rnd.getrandbits(16), 0, 0))
        seg += rnd.randbytes(seg_len - 20)
        seg[16:18] = struct.pack("!H", csum(pseudo_hdr(src, dst, 6, seg_len) + seg))
    else:
        seg = bytearray(struct.pack("!BBHHH", 8, 0, 0, rnd.getrandbits(16), rnd.getrandbits(16)))
        seg += rnd.randbytes(seg_len - 8)
        seg[2:4] = struct.pack("!H", csum(seg))
    return proto, bytes(seg)


def inner_ip(rnd, ip_len):
    """Random inner IPv4 (90%) or IPv6 (10%) packet of exactly ip_len bytes (>= 64)."""
    if rnd.random() < 0.1:
        src, dst = rnd_ip6(rnd), rnd_ip6(rnd)
        proto, seg = l4_segment(rnd, ip_len - 40, src, dst)
        return struct.pack("!IHBB", 0x60000000 | rnd.getrandbits(20), len(seg), proto,
                           rnd.randint(32, 128)) + src + dst + seg
    src, dst = rnd_ip4(rnd), rnd_ip4(rnd)
    proto, seg = l4_segment(rnd, ip_len - 20, src, dst)
    return ip4_header(rnd, 20 + len(seg), proto, src, dst) + seg


def inner_eth(rnd, ip_len):
    ip = inner_ip(rnd, ip_len)
    return rnd_mac(rnd) + rnd_mac(rnd) + (b"\x86\xdd" if ip[0] >> 4 == 6 else b"\x08\x00") + ip


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload   # csum 0: legal on IPv4


# ----------------------------------------------------------------------------
# outer-IPv4 tunnels: fn(rnd, ip_len) -> (ip_proto, bytes after the outer IPv4 header)
# ----------------------------------------------------------------------------
def t_gre(rnd, ip_len):
    """Plain GRE (RFC 2784/2890): protocol 0x0800/0x86DD, optional checksum/key/seq."""
    inner = inner_ip(rnd, ip_len)
    c, k, s = rnd.random() < 0.2, rnd.random() < 0.4, rnd.random() < 0.2
    hdr = struct.pack("!HH", (c << 15) | (k << 13) | (s << 12), 0x86DD if inner[0] >> 4 == 6 else 0x0800)
    if c:
        hdr += b"\0\0\0\0"                           # checksum + reserved1
    if k:
        hdr += struct.pack("!I", rnd.getrandbits(32))
    if s:
        hdr += struct.pack("!I", rnd.getrandbits(32))
    pkt = hdr + inner
    if c:
        pkt = pkt[:4] + struct.pack("!H", csum(pkt)) + pkt[6:]
    return 47, pkt


def t_nvgre(rnd, ip_len):
    """RFC 7637: C=0 K=1 S=0, proto 0x6558, key = VSID(24) | FlowID(8)."""
    key = (rnd.randint(0x001000, 0xFFFFFE) << 8) | rnd.getrandbits(8)
    return 47, struct.pack("!HHI", 0x2000, 0x6558, key) + inner_eth(rnd, ip_len)


def t_vxlan(rnd, ip_len):
    vx = struct.pack("!II", 0x08000000, rnd.getrandbits(24) << 8)
    return 17, udp(rnd.randint(49152, 65535), 4789, vx + inner_eth(rnd, ip_len))


def t_geneve(rnd, ip_len):
    opts = b""
    for _ in range(rnd.choice((0, 0, 1, 2))):
        n = rnd.randint(1, 3)
        opts += struct.pack("!HBB", rnd.getrandbits(16), rnd.getrandbits(7), n) + rnd.randbytes(4 * n)
    hdr = struct.pack("!BBHI", len(opts) // 4, 0, 0x6558, rnd.getrandbits(24) << 8)
    return 17, udp(rnd.randint(49152, 65535), 6081, hdr + opts + inner_eth(rnd, ip_len))


def t_l2tp(rnd, ip_len):
    """L2TPv2 data message over UDP/1701 carrying PPP (FF 03 + protocol) + IP."""
    ip = inner_ip(rnd, ip_len)
    ppp = b"\xff\x03" + (b"\x00\x57" if ip[0] >> 4 == 6 else b"\x00\x21") + ip
    msg = struct.pack("!HHHH", 0x4002, 8 + len(ppp), rnd.randint(1, 65535), rnd.randint(1, 65535)) + ppp
    return 17, udp(1701, 1701, msg)


def t_lisp(rnd, ip_len):
    """LISP data header with N and I bits: 24-bit nonce, 24-bit instance ID, 8-bit LSBs."""
    hdr = struct.pack("!B3sI", 0x88, rnd.randbytes(3), (rnd.getrandbits(24) << 8) | rnd.getrandbits(8))
    return 17, udp(rnd.randint(49152, 65535), 4341, hdr + inner_ip(rnd, ip_len))


def t_gtp(rnd, ip_len):
    """GTPv1-U G-PDU over UDP/2152, optionally with the sequence-number block."""
    ip = inner_ip(rnd, ip_len)
    teid = rnd.getrandbits(32) | 1
    if rnd.random() < 0.3:
        hdr = struct.pack("!BBHIHBB", 0x32, 0xFF, 4 + len(ip), teid, rnd.getrandbits(16), 0, 0)
    else:
        hdr = struct.pack("!BBHI", 0x30, 0xFF, len(ip), teid)
    return 17, udp(2152, 2152, hdr + ip)


IP_TUNNELS = {"gre": t_gre, "nvgre": t_nvgre, "vxlan": t_vxlan, "geneve": t_geneve,
              "l2tp": t_l2tp, "lisp": t_lisp, "gtp": t_gtp}


# ----------------------------------------------------------------------------
# L2 tags: fn(rnd, ip_len, dmac, smac) -> (ip_proto, ip payload, head_fn)
#   head_fn(ip_total_len) -> every byte of the frame in front of the IPv4 header.
#   The tag is repeated on every fragment (each fragment is its own frame).
# ----------------------------------------------------------------------------
def fixed(h):
    return lambda tl: h


def t_vlan(rnd, ip_len, dmac, smac):
    proto, seg = l4_segment(rnd, ip_len - 20)
    tci = (rnd.getrandbits(3) << 13) | rnd.randint(1, 4094)
    return proto, seg, fixed(dmac + smac + struct.pack("!HHH", 0x8100, tci, 0x0800))


def t_vntag(rnd, ip_len, dmac, smac):
    """Cisco VN-Tag: 0x8926 | d p dvif(14) | l r ver(2) svif(12)."""
    proto, seg = l4_segment(rnd, ip_len - 20)
    tag = struct.pack("!HH", (rnd.getrandbits(1) << 15) | rnd.randint(1, 0x3FFF), rnd.randint(1, 0xFFF))
    return proto, seg, fixed(dmac + smac + b"\x89\x26" + tag + b"\x08\x00")


def t_fabricpath(rnd, ip_len, dmac, smac):
    """FabricPath: outer DA/SA, 0x8903, FTag(10)|TTL(6), then the original Ethernet header."""
    proto, seg = l4_segment(rnd, ip_len - 20)
    fp = b"\x02" + rnd.randbytes(5)
    fp2 = b"\x02" + rnd.randbytes(5)
    ftag = struct.pack("!HH", 0x8903, (rnd.randint(1, 1023) << 6) | rnd.randint(1, 32))
    return proto, seg, fixed(fp + fp2 + ftag + rnd_mac(rnd) + rnd_mac(rnd) + b"\x08\x00")


def t_trill(rnd, ip_len, dmac, smac):
    """TRILL (RFC 6325): V=0 M OpLen=0 Hop, egress/ingress nicknames, inner Ethernet header."""
    proto, seg = l4_segment(rnd, ip_len - 20)
    tr = struct.pack("!HHHH", 0x22F3, (rnd.getrandbits(1) << 11) | rnd.randint(1, 63),
                     rnd.randint(1, 0xFFBF), rnd.randint(1, 0xFFBF))
    return proto, seg, fixed(dmac + smac + tr + rnd_mac(rnd) + rnd_mac(rnd) + b"\x08\x00")


def t_ppp(rnd, ip_len, dmac, smac):
    """PPPoE session (0x8864) carrying PPP protocol 0x0021 + IPv4 (length is per fragment)."""
    proto, seg = l4_segment(rnd, ip_len - 20)
    sid = rnd.randint(1, 0xFFFE)
    return proto, seg, lambda tl: dmac + smac + struct.pack("!HBBHHH", 0x8864, 0x11, 0, sid, tl + 2, 0x0021)


L2_TAGS = {"vlan": t_vlan, "vntag": t_vntag, "fabricpath": t_fabricpath, "trill": t_trill, "ppp": t_ppp}
L2_MTU_COST = {"ppp": 8}     # PPPoE(6)+PPP(2) come out of the link MTU (RFC 2516)
ALIASES = {"vn-tag": "vntag", "fabric-path": "fabricpath", "pppoe": "ppp", "gtpu": "gtp",
           "gtp-u": "gtp", "gtpv1": "gtp", "l2tpv2": "l2tp", "vxlan-gpe": "vxlan"}


# ----------------------------------------------------------------------------
# datagram pool entries and fragmentation
# ----------------------------------------------------------------------------
def make_entry(rnd, cfg):
    """One pre-built datagram -> (fragments, total_frame_bytes).
    fragment = (head, flags_frag, ip_total_len, header_sum_partial, proto, payload+pad).
    Nothing in here depends on the group's IP ID / src / dst, which are patched at send time."""
    name, frag, mtu = cfg["tunnel"], cfg["frag"], cfg["mtu"]
    l2 = name in L2_TAGS
    eff = mtu - L2_MTU_COST.get(name, 0)
    for _ in range(100):
        if frag:
            ip_len = rnd.randint(eff + 1, 3 * eff) if l2 else rnd.randint(eff - 100, 3 * eff)
        else:
            hi = eff if l2 else eff - 90
            ip_len = rnd.randint(64, min(300, hi)) if rnd.random() < 0.4 else rnd.randint(min(300, hi), hi)
        if l2:
            proto, payload, head_fn = L2_TAGS[name](rnd, max(ip_len, 64), cfg["dmac"], cfg["smac"])
        else:
            proto, payload = IP_TUNNELS[name](rnd, max(ip_len, 64))
            head_fn = fixed(cfg["dmac"] + cfg["smac"] + b"\x08\x00")
        if (len(payload) > eff - 20) == frag:
            break
    else:
        raise RuntimeError("could not size a datagram for mtu=%d" % mtu)

    n = len(payload)
    size = ((eff - 20) // 8) * 8 if frag else n        # non-last fragments: multiple of 8 bytes
    frags, total, pos = [], 0, 0
    while pos < n:
        chunk = payload[pos:pos + size]
        end = pos + len(chunk)
        ff = ((0x2000 if end < n else 0) | (pos >> 3)) if frag else 0x4000
        tl = 20 + len(chunk)
        head = head_fn(tl)
        pad = max(0, MIN_FRAME - (len(head) + tl))
        frags.append((head, ff, tl, 0x4500 + tl + ff + ((64 << 8) | proto), proto, chunk + bytes(pad)))
        total += len(head) + tl + pad
        pos = end
    return tuple(frags), total


def group_ids(n):
    """Group number -> (IP ID, src, dst). Bijective over 2^48 groups, so no (src,dst,id)
    tuple is ever reused - guaranteed unique, unlike drawing random IDs."""
    x = (n * ID_MULT) & MASK48
    return x & 0xFFFF, 0x0A000000 | ((x >> 16) & 0xFFFFFF), 0xAC100000 | (x >> 40)


def group_frames(frags, n):
    """Frames of fragment group number n (IP header patched with the group's id/src/dst)."""
    ident, src, dst = group_ids(n)
    gsum = ident + (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF)
    out = []
    for head, ff, tl, partial, proto, payload in frags:
        s = partial + gsum
        s = (s & 0xFFFF) + (s >> 16)
        s = (s & 0xFFFF) + (s >> 16)
        out.append(head + IP_HDR.pack(0x45, 0, tl, ident, ff, 64, proto, ~s & 0xFFFF, src, dst) + payload)
    return out


# ----------------------------------------------------------------------------
# sender
# ----------------------------------------------------------------------------
def open_socket(iface):
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


def worker(idx, nw, cfg, stats, stop):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    rnd = random.Random(int.from_bytes(os.urandom(16), "big"))
    pool = [make_entry(rnd, cfg) for _ in range(POOL_SIZE)]
    sock = open_socket(cfg["iface"])
    send = sock.send
    rate = cfg["rate"] / nw
    ovh = cfg["overhead"]
    perf = time.perf_counter
    base = 5 * idx                                  # stats slots: frames, bytes, groups, errors, active us
    n, k = idx, 0                                   # striped group numbers: worker i owns n = i mod nw
    frames = nbytes = groups = errs = 0
    bits = 0.0
    t0 = t_begin = perf()
    deadline = t0 + cfg["duration"] if cfg["duration"] else None
    next_pub = t0 + 0.2
    warned = False
    while True:
        entry = pool[rnd.randrange(POOL_SIZE)]
        fl = group_frames(entry[0], n)
        for f in fl:
            while True:
                try:
                    send(f)
                    break
                except OSError as e:
                    if e.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR):
                        time.sleep(0.0001)          # tx queue full: wait for the NIC
                        continue
                    errs += 1
                    if not warned:
                        warned = True
                        print("worker %d: send failed: %s (frame %d B)" % (idx, e, len(f)), file=sys.stderr)
                    break
        n += nw
        groups += 1
        frames += len(fl)
        nbytes += entry[1]
        bits += (entry[1] + ovh * len(fl)) * 8
        k += 1
        if not k & (REFRESH_EVERY - 1):
            pool[rnd.randrange(POOL_SIZE)] = make_entry(rnd, cfg)

        due = t0 + bits / rate
        now = perf()
        if due > now:
            if due - now > 0.0006:
                time.sleep(due - now - 0.0004)
            while perf() < due:
                pass
            now = perf()
        elif now - due > 0.1:
            t0 += now - due - 0.02                  # fell far behind: drop the debt, no catch-up burst
        if now >= next_pub:
            stats[base:base + 5] = (frames, nbytes, groups, errs, int((now - t_begin) * 1e6))
            next_pub = now + 0.2
            if stop.is_set() or (deadline and now >= deadline):
                break
    stats[base:base + 5] = (frames, nbytes, groups, errs, int((perf() - t_begin) * 1e6))


def parse_rate(s):
    s = s.strip().lower()
    mult = 1
    if s.endswith("bps"):
        s = s[:-3]
    elif s.endswith("b"):
        s = s[:-1]
    if s and s[-1] in "kmg":
        mult = {"k": 1e3, "m": 1e6, "g": 1e9}[s[-1]]
        s = s[:-1]
    return float(s) * mult


def usage():
    print(__doc__.split("Needs root")[0].strip(), file=sys.stderr)
    return 2


def main(argv):
    if len(argv) < 3:
        return usage()
    iface, name = argv[0], argv[1].lower()
    name = ALIASES.get(name, name)
    if name not in IP_TUNNELS and name not in L2_TAGS:
        print("unknown tunnel/tag %r. choose from: %s" % (argv[1], " ".join(list(IP_TUNNELS) + list(L2_TAGS))),
              file=sys.stderr)
        return 2
    try:
        rate = parse_rate(argv[2])
        assert rate > 0
    except (ValueError, AssertionError):
        print("bad speed %r (examples: 400M, 4G, 2.5G)" % argv[2], file=sys.stderr)
        return 2
    frag, overhead, duration, mtu, workers = False, 0, 0.0, DEFAULT_MTU, 0
    for a in argv[3:]:
        a = a.lower()
        if a in ("fragment", "fragmented", "frag"):
            frag = True
        elif a == "wire":
            overhead = WIRE_OVERHEAD
        elif a.startswith("duration="):
            duration = float(a[9:])
        elif a.startswith("mtu="):
            mtu = int(a[4:])
        elif a.startswith("workers="):
            workers = int(a[8:])
        else:
            print("unknown option %r" % a, file=sys.stderr)
            return usage()
    if mtu < 576 or mtu > 16000:
        print("mtu must be 576..16000", file=sys.stderr)
        return 2

    sysdir = "/sys/class/net/" + iface
    if not os.path.isdir(sysdir):
        print("no such interface %r (have: %s)" % (iface, " ".join(os.listdir("/sys/class/net"))), file=sys.stderr)
        return 2
    smac = bytes.fromhex(open(sysdir + "/address").read().strip().replace(":", ""))
    try:
        open_socket(iface).close()
    except PermissionError:
        print("raw sockets need root (CAP_NET_RAW)", file=sys.stderr)
        return 1
    try:
        speed = int(open(sysdir + "/speed").read())
        if 0 < speed * 1e6 < rate:
            print("warning: requested %.2f Gbit/s but %s link speed is %.2f Gbit/s" % (rate / 1e9, iface, speed / 1e3),
                  file=sys.stderr)
    except (OSError, ValueError):
        pass

    ncpu = os.cpu_count() or 1
    if not workers:
        workers = max(1, min(ncpu, math.ceil(rate / 8000 / FPS_PER_WORKER)))
    cfg = {"iface": iface, "tunnel": name, "frag": frag, "mtu": mtu, "rate": rate, "overhead": overhead,
           "duration": duration, "smac": smac, "dmac": DST_MAC}
    print("%s: %s%s -> %.3f Gbit/s (%s) mtu %d, %d worker(s) on %d cpu(s). Ctrl-C to stop." % (
        iface, name, " + outer-IP fragmentation" if frag else "", rate / 1e9,
        "wire rate" if overhead else "frame bytes", mtu, workers, ncpu))

    ctx = mp.get_context("fork")
    stats = ctx.RawArray("Q", 5 * workers)
    stop = ctx.Event()
    procs = [ctx.Process(target=worker, args=(i, workers, cfg, stats, stop)) for i in range(workers)]
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
            dt = now - last_t
            if cur[0] != last[0]:
                print("[%4.0fs] %6.3f Gbit/s  %9s frames/s  %8s groups/s  (total %s groups)" % (
                    now - t_start, (cur[1] - last[1]) * 8 / dt / 1e9, format((cur[0] - last[0]) / dt, ",.0f"),
                    format((cur[2] - last[2]) / dt, ",.0f"), format(cur[2], ",")), flush=True)
            last_t, last = now, cur
    except KeyboardInterrupt:
        pass
    stop.set()
    for p in procs:
        p.join()
    f, b, g, e = totals()
    elapsed = max(list(stats)[4::5]) / 1e6 or (time.monotonic() - t_start)   # active sending time
    achieved = (b + overhead * f) * 8 / elapsed
    print("done: %s frames, %s groups, %.3f GB in %.1fs = %.3f Gbit/s (target %.3f)%s" % (
        format(f, ","), format(g, ","), b / 1e9, elapsed, achieved / 1e9, rate / 1e9,
        ", %d send errors" % e if e else ""))
    if achieved < 0.97 * rate:
        print("warning: target rate not sustained - add cpus/workers=N or lower the speed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
