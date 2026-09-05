#!/usr/bin/env python3
"""Offline regression for the Week-4 evidence bundle.

Unlike run_tests.py (which drives the live app through the gate), this does not
need Docker or the running stack: it generates the bundle in-process and confirms
each flag is genuinely recoverable by the intended investigation technique -
log grep, packet-capture stream reassembly, and static deobfuscation of the
sample. Standard library only.

    python tests/test_week4.py
"""
import base64
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "app", "modules", "week4_evidence"))
import generator  # noqa: E402  (resolved via sys.path above, stdlib-only)

# distinctive values so a match cannot be a coincidence
FLAGS = {
    "W4-01": "RPC{w4_01_entry_TESTVAL}",
    "W4-02": "RPC{w4_02_leak_TESTVAL}",
    "W4-03": "RPC{w4_03_lateral_TESTVAL}",
    "W4-04": "RPC{w4_04_sample_TESTVAL}",
    "W4-05": "RPC{w4_05_c2_TESTVAL}",
}

_fail = 0


def check(name, ok, detail=""):
    global _fail
    if not ok:
        _fail += 1
    print("  [%s] %-32s %s" % ("PASS" if ok else "FAIL", name, detail))


def recover_w4_04(exe):
    """.rdata holds 'cfg=<base64(single-byte XOR)>'; brute-force the 1-byte key."""
    m = re.search(rb"cfg=([A-Za-z0-9+/=]+)", exe)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1))
    except Exception:  # noqa: BLE001
        return None
    for key in range(256):
        cand = bytes(b ^ key for b in raw)
        if cand.startswith(b"RPC{") and cand.endswith(b"}"):
            return cand.decode("latin1")
    return None


def recover_w4_05(pcap):
    """Reassemble the C2 beacon: concat the base64 d= chunks in n= order."""
    parts = re.findall(rb"n=(\d+)&d=([A-Za-z0-9+/=]+)", pcap)
    if not parts:
        return None
    parts.sort(key=lambda p: int(p[0]))
    try:
        return base64.b64decode(b"".join(d for _, d in parts)).decode("latin1")
    except Exception:  # noqa: BLE001
        return None


def main():
    files = generator.build_bundle(FLAGS)
    access = files["access.log"].decode()
    auth = files["auth.log"].decode()
    pcap = files["capture.pcap"]
    exe = files[generator.scenario.SAMPLE_NAME]

    print("Week 4 evidence bundle:")
    check("bundle has all artifacts",
          {"access.log", "auth.log", "capture.pcap", "README-for-players.txt",
           "sha256sums.txt"}.issubset(files) and generator.scenario.SAMPLE_NAME in files)
    check("access.log shows the attack",
          "198.51.100.66" in access and "UNION%20SELECT" in access.replace("+", "%20") or
          "UNION" in access, "attacker IP + SQLi visible")
    check("capture.pcap is a libpcap file", pcap[:4].hex() == "d4c3b2a1", pcap[:4].hex())
    check("sample is a PE (MZ/PE)",
          exe[:2] == b"MZ" and exe[int.from_bytes(exe[0x3c:0x40], "little"):
                                    int.from_bytes(exe[0x3c:0x40], "little") + 4] == b"PE\x00\x00")

    check("W4-01 entry point (auth.log token)", FLAGS["W4-01"] in auth,
          FLAGS["W4-01"] if FLAGS["W4-01"] in auth else "not found")
    check("W4-02 leak scope (pcap UNION dump)", FLAGS["W4-02"].encode() in pcap,
          FLAGS["W4-02"] if FLAGS["W4-02"].encode() in pcap else "not found")
    check("W4-03 lateral movement (pcap VIP)", FLAGS["W4-03"].encode() in pcap,
          FLAGS["W4-03"] if FLAGS["W4-03"].encode() in pcap else "not found")
    got4 = recover_w4_04(exe)
    check("W4-04 static analysis (deobfuscate)", got4 == FLAGS["W4-04"], got4 or "not recovered")
    got5 = recover_w4_05(pcap)
    check("W4-05 C2 reconstruction (reassemble)", got5 == FLAGS["W4-05"], got5 or "not recovered")

    # negative control: the sample must not leak the flag in clear text
    check("W4-04 flag is NOT clear-text in sample", FLAGS["W4-04"].encode() not in exe,
          "obfuscated" if FLAGS["W4-04"].encode() not in exe else "LEAKED!")

    print()
    if _fail:
        print("RESULT: %d Week-4 check(s) FAILED" % _fail)
        sys.exit(1)
    print("RESULT: all Week-4 checks PASSED")


if __name__ == "__main__":
    main()
