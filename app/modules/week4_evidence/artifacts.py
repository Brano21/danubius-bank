"""Low-level artifact writers for the Week-4 evidence bundle (stdlib only).

Nothing here is Flask- or DB-aware, so the generator can run standalone. Three
formats are produced by hand so the bundle needs no third-party packages:

  * a real libpcap file (Ethernet/IPv4/TCP) that Wireshark can "Follow Stream",
  * a well-formed, BENIGN Windows PE32 (.exe) for static-analysis practice,
  * plain-text access.log / auth.log lines.

The PE is deliberately inert: its entry point is `xor eax,eax; ret`. The
"malicious" API and IOC strings live in a data section for `strings` to find;
they are never called. It does nothing when run.
"""
import struct
import time

# --------------------------------------------------------------------------
# PCAP (libpcap, linktype 1 = Ethernet)
# --------------------------------------------------------------------------
_SYN, _SYNACK, _ACK, _PSHACK, _FINACK = 0x02, 0x12, 0x10, 0x18, 0x11


def _ip2b(ip):
    return bytes(int(o) for o in ip.split("."))


def _cksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ipv4(src, dst, payload, ident):
    total = 20 + len(payload)
    fields = (0x45, 0, total, ident, 0x4000, 64, 6, 0, _ip2b(src), _ip2b(dst))
    hdr = struct.pack(">BBHHHBBH4s4s", *fields)
    chk = _cksum(hdr)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, 6, chk,
                      _ip2b(src), _ip2b(dst))
    return hdr + payload


def _tcp(sp, dp, seq, ack, flags, payload, src, dst, win=0xFFFF):
    hdr = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, win, 0, 0)
    pseudo = _ip2b(src) + _ip2b(dst) + struct.pack(">BBH", 0, 6, len(hdr) + len(payload))
    chk = _cksum(pseudo + hdr + payload)
    hdr = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, win, chk, 0)
    return hdr + payload


def _eth(payload, c2s):
    client = b"\x02\x00\x00\x00\x00\x01"
    server = b"\x02\x00\x00\x00\x00\x02"
    dst, src = (server, client) if c2s else (client, server)
    return dst + src + b"\x08\x00" + payload


class Pcap:
    """Accumulates packets; .bytes() renders a libpcap file."""

    def __init__(self):
        self._records = []   # (ts_sec, ts_usec, frame)
        self._ident = 1

    def _pkt(self, ts, src, sp, dst, dp, seq, ack, flags, data, c2s):
        self._ident = (self._ident + 1) & 0xFFFF
        frame = _eth(_ipv4(src, dst, _tcp(sp, dp, seq, ack, flags, data, src, dst),
                           self._ident), c2s)
        usec = int((ts - int(ts)) * 1_000_000)
        self._records.append((int(ts), usec, frame))

    def add_http(self, base_ts, cip, cport, sip, sport, request, response):
        """One request/response HTTP exchange as a full TCP stream."""
        cseq, sseq, t = 1000, 5000, float(base_ts)
        self._pkt(t, cip, cport, sip, sport, cseq, 0, _SYN, b"", True); cseq += 1
        t += 0.0004
        self._pkt(t, sip, sport, cip, cport, sseq, cseq, _SYNACK, b"", False); sseq += 1
        t += 0.0002
        self._pkt(t, cip, cport, sip, sport, cseq, sseq, _ACK, b"", True)
        for who, data in (("c", request), ("s", response)):
            t += 0.0010
            if who == "c":
                self._pkt(t, cip, cport, sip, sport, cseq, sseq, _PSHACK, data, True)
                cseq += len(data)
                t += 0.0003
                self._pkt(t, sip, sport, cip, cport, sseq, cseq, _ACK, b"", False)
            else:
                self._pkt(t, sip, sport, cip, cport, sseq, cseq, _PSHACK, data, False)
                sseq += len(data)
                t += 0.0003
                self._pkt(t, cip, cport, sip, sport, cseq, sseq, _ACK, b"", True)
        t += 0.0010
        self._pkt(t, cip, cport, sip, sport, cseq, sseq, _FINACK, b"", True); cseq += 1
        t += 0.0003
        self._pkt(t, sip, sport, cip, cport, sseq, cseq, _FINACK, b"", False); sseq += 1
        t += 0.0002
        self._pkt(t, cip, cport, sip, sport, cseq, sseq, _ACK, b"", True)

    def bytes(self):
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for sec, usec, frame in self._records:
            out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            out.append(frame)
        return b"".join(out)


# --------------------------------------------------------------------------
# Benign Windows PE32 (.exe)
# --------------------------------------------------------------------------
def _align(n, a):
    return (n + a - 1) // a * a


def build_pe(rdata_strings):
    """A valid, inert PE32. `rdata_strings` (list[str]) land in .rdata for
    `strings`/PE viewers to recover. Entry point is `xor eax,eax; ret`."""
    FILE_ALIGN, SECT_ALIGN, IMAGE_BASE = 0x200, 0x1000, 0x400000

    # IMAGE_DOS_HEADER: e_lfanew (offset to PE header) sits at file offset 0x3C
    dos = b"MZ" + b"\x90\x00\x03\x00" + b"\x00" * 0x36 + struct.pack("<I", 0x80)
    dos += (b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
            b"This program cannot be run in DOS mode.\r\r\n\x24\x00\x00\x00\x00\x00\x00\x00")
    dos = dos.ljust(0x80, b"\x00")

    text = b"\x31\xc0\xc3"                     # xor eax,eax ; ret
    rdata = b"\x00".join(s.encode() for s in rdata_strings) + b"\x00"

    text_va, rdata_va = 0x1000, 0x2000
    text_raw = _align(len(dos) + 24 + 0xE0 + 2 * 40, FILE_ALIGN)   # after headers
    rdata_raw = text_raw + _align(len(text), FILE_ALIGN)
    size_headers = text_raw
    size_image = _align(rdata_va + len(rdata), SECT_ALIGN)

    coff = struct.pack("<HHIIIHH", 0x14C, 2, int(time.time()), 0, 0, 0xE0, 0x102)

    # standard fields (PE32): magic, linker maj/min, SizeOfCode, SizeOfInitData,
    # SizeOfUninitData, EntryPoint, BaseOfCode, BaseOfData
    opt = struct.pack(
        "<HBBIIIIII", 0x10B, 9, 0, _align(len(text), FILE_ALIGN),
        _align(len(rdata), FILE_ALIGN), 0, text_va, text_va, rdata_va)
    # windows-specific fields (21 values)
    opt += struct.pack("<IIIHHHHHHIIIIHHIIIIII",
        IMAGE_BASE, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0,
        0, size_image, size_headers, 0, 3, 0x8540,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)                   # 16 empty data directories
    opt = opt.ljust(0xE0, b"\x00")

    def section(name, vsize, va, rsize, raw, chars):
        return struct.pack("<8sIIIIIIHHI", name, vsize, va, rsize, raw,
                           0, 0, 0, 0, chars)

    sects = (section(b".text", len(text), text_va, _align(len(text), FILE_ALIGN),
                     text_raw, 0x60000020)
             + section(b".rdata", len(rdata), rdata_va, _align(len(rdata), FILE_ALIGN),
                       rdata_raw, 0x40000040))

    pe = (dos + b"PE\x00\x00" + coff + opt + sects).ljust(text_raw, b"\x00")
    pe += text.ljust(_align(len(text), FILE_ALIGN), b"\x00")
    pe += rdata.ljust(_align(len(rdata), FILE_ALIGN), b"\x00")
    return pe


# --------------------------------------------------------------------------
# Access / auth log line helpers
# --------------------------------------------------------------------------
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
           "Oct", "Nov", "Dec"]


def clf_time(epoch):
    t = time.gmtime(epoch)
    return "%02d/%s/%04d:%02d:%02d:%02d +0000" % (
        t.tm_mday, _MONTHS[t.tm_mon - 1], t.tm_year, t.tm_hour, t.tm_min, t.tm_sec)


def iso_time(epoch):
    t = time.gmtime(epoch)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (
        t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def clf_line(ip, epoch, method, path, status, size, ua):
    return '%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"' % (
        ip, clf_time(epoch), method, path, status, size, ua)
