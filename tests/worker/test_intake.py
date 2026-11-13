"""The intake Worker under the pinned workerd (ADR-0006 parts 2 to 7, 11).

Run by the `worker` step of tools/check.sh (python3 -I -B -m unittest),
which exports WORKERD_BIN from tools/pins.env. workerd serves
tests/worker/config.capnp on loopback sockets the test binds first; the
bindings are emulated there (capture.js for EMAIL, burst.js for
RATE_LIMITER, a SQLite Durable Object in a temporary directory for
LIMITER), and probe.js reaches the Worker's pure helpers and the limiter
with an injected time. Multipart bodies are built by hand, as a browser
sends them. Every rule branch of the Worker has a case here; the numbers
come from the INTAKE_* constants of tools/sitecheck.py, the single source
(test_constants_match_worker proves the Worker enforces the same).
"""

import hashlib
import hmac
import http.client
import importlib.util
import json
import math
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "tests" / "worker" / "config.capnp"
SOCKETS = ("intake", "intake-broken-limiter", "intake-bad-key", "intake-broken-reserve", "intake-no-burst",
           "intake-missing-burst", "intake-record", "probe")
# The Worker answers only its own host (fix round 5), so every request
# names it; the loopback address would otherwise be the Host.
INTAKE_HOST = "intake.interviewscam.com"
LOG_LINE = re.compile(r"^intake event=[a-z-]+( code=[A-Z_]+)?$")
FAR_FUTURE = 8_000_000_000_000  # ms, year 2223: purges every limiter row

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + bytes(8)
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(6)
GIF87 = b"GIF87a" + bytes(10)
GIF89 = b"GIF89a" + bytes(10)
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + bytes(8)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SC = None    # tools/sitecheck.py
TOOL = None  # tools/intake.py
SERVER = {}


def setUpModule():
    global SC, TOOL
    SC = load("sitecheck", ROOT / "tools" / "sitecheck.py")
    TOOL = load("intake_tool", ROOT / "tools" / "intake.py")
    binary = os.environ.get("WORKERD_BIN", "")
    if not binary or not os.access(binary, os.X_OK):
        raise RuntimeError(f"WORKERD_BIN is not an executable workerd: {binary!r}; "
                           "run through tools/check.sh, which fetches the pinned one")
    work = tempfile.TemporaryDirectory(prefix="intake-worker-")
    store = Path(work.name) / "limiter-store"
    store.mkdir()
    listeners, args = {}, []
    for name in SOCKETS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(64)
        listeners[name] = sock
        args += ["--socket-fd", f"{name}={sock.fileno()}"]
    stdout = open(Path(work.name) / "stdout.log", "wb")
    stderr = open(Path(work.name) / "stderr.log", "wb")
    proc = subprocess.Popen(
        [binary, "serve", str(CONFIG), "--verbose", *args,
         "--directory-path", f"limiter-store={store}"],
        stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
        pass_fds=[s.fileno() for s in listeners.values()])
    SERVER.update(work=work, proc=proc, stdout=stdout, stderr=stderr,
                  ports={n: s.getsockname()[1] for n, s in listeners.items()},
                  listeners=listeners)
    deadline = time.monotonic() + 60
    while True:
        try:
            probe("constants", timeout=5)
            break
        except (OSError, http.client.HTTPException, AssertionError, ValueError):
            if proc.poll() is not None or time.monotonic() > deadline:
                stderr.flush()
                log = (Path(work.name) / "stderr.log").read_text(errors="replace")[-4000:]
                tearDownModule()
                raise RuntimeError(f"workerd did not come up:\n{log}")
            time.sleep(0.2)


def tearDownModule():
    proc = SERVER.get("proc")
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for key in ("stdout", "stderr"):
        if key in SERVER:
            SERVER[key].close()
    for sock in SERVER.get("listeners", {}).values():
        sock.close()
    if "work" in SERVER:
        SERVER["work"].cleanup()
    SERVER.clear()


def stdout_lines():
    SERVER["stdout"].flush()
    path = Path(SERVER["work"].name) / "stdout.log"
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def request(port, method, path, body=b"", headers=None, timeout=120):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Host": INTAKE_HOST, **(headers or {})}
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, \
            [v for k, v in resp.getheaders() if k.lower() == "set-cookie"], data
    finally:
        conn.close()


def probe(target, fn=None, *args, timeout=120):
    status, _, _, data = request(SERVER["ports"]["probe"], "POST", "/",
                                 json.dumps({"target": target, "fn": fn, "args": list(args)}).encode(),
                                 {"Content-Type": "application/json"}, timeout=timeout)
    reply = json.loads(data)
    assert reply.get("ok"), reply
    return reply["result"]


def base_now(wall_ms=None):
    """Noon UTC of the day after wall_ms (default: the wall clock), in ms: an
    injected time whose alarms (an hour later, or the next 00:00 UTC) lie in
    the future, so the limiter's own alarm never fires during a case."""
    day = 86_400_000
    wall = int(time.time() * 1000) if wall_ms is None else wall_ms
    return (wall // day + 1) * day + day // 2


PIN_KEY = "f" * 64


def pin_day():
    """Fix round 5: the Worker reserves at its own Date.now(), which can
    pass 00:00 UTC during a case. An attempt() at base_now() makes it the
    newest time the limiter has seen, and reserve() never counts on an
    older day (fix round 1), so every Worker reserve of the case counts on
    that one day, whatever the wall clock reads (test_pinned_day_*)."""
    probe("limiter", "attempt", PIN_KEY, base_now())


_IP = [0]


def fresh_ip():
    """A client of its own: each call is a new IPv6 /64, so a new limiter key."""
    _IP[0] += 1
    return f"2001:db8:{_IP[0]:x}:1::1"


def quote(value):
    # The HTML form encoding of a name or file name in Content-Disposition.
    return value.replace("\r", "%0D").replace("\n", "%0A").replace('"', "%22")


def multipart(parts, boundary=None):
    """parts: (name, str) or (name, (file name, content type, bytes))."""
    boundary = boundary or "----intaketest" + secrets.token_hex(12)
    out = []
    for name, value in parts:
        out.append(f"--{boundary}\r\n".encode())
        if isinstance(value, tuple):
            # A fourth member "raw" sends the file name unescaped, as a
            # hand-made request can (a browser escapes CR, LF and quotes).
            fname, ctype, data, *raw = value
            fname = fname if raw else quote(fname)
            out.append(f'Content-Disposition: form-data; name="{quote(name)}"; '
                       f'filename="{fname}"\r\nContent-Type: {ctype}\r\n\r\n'.encode("utf-8"))
            out.append(data)
        else:
            out.append(f'Content-Disposition: form-data; name="{quote(name)}"\r\n\r\n'.encode())
            out.append(value.encode("utf-8"))
        out.append(b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def report(**over):
    fields = {"channel": "report", "name": "Example Front Co", "contact_start": "A message on a job board",
              "details": "They asked me to run a repository before the call.", "headers": "",
              "email": "reporter@example.com", "website": ""}
    fields.update(over)
    return [(k, v) for k, v in fields.items() if v is not None]


def correction(**over):
    fields = {"channel": "correction", "page_url": "https://interviewscam.com/reports/example/",
              "request": "The domain listed is ours and was never used by the campaign.",
              "email": "owner@example.com", "website": ""}
    fields.update(over)
    return [(k, v) for k, v in fields.items() if v is not None]


class Outcome:
    def __init__(self, status, headers, cookies, body):
        self.status, self.headers, self.cookies, self.body = status, headers, cookies, body
        self.location = headers.get("location", "")
        if self.location == SC.INTAKE_SENT_URL:
            self.id = "sent"
        elif self.location.startswith(SC.INTAKE_NOT_SENT_URL + "#"):
            self.id = self.location[len(SC.INTAKE_NOT_SENT_URL) + 1:]
        else:
            self.id = None


def check_response(test, out):
    """The response contract of ADR-0006 part 6, on every response."""
    test.assertEqual(out.cookies, [], "Set-Cookie on a response")
    test.assertEqual(out.headers.get("cache-control"), "no-store")
    test.assertEqual(out.headers.get("referrer-policy"), "no-referrer")
    test.assertEqual(out.body, b"", "a response body")
    if out.status == 303:
        test.assertTrue(out.id == "sent" or out.id in SC.INTAKE_RESULT_IDS,
                        f"Location outside the closed set: {out.location!r}")


def send(test, parts=None, *, ip=None, origin="https://interviewscam.com", service="intake",
         body=None, ctype=None, headers=None, method="POST", path="/submit"):
    if body is None:
        body, mp_type = multipart(parts if parts is not None else report())
        ctype = ctype or mp_type
    hdrs = {"Content-Type": ctype} if ctype else {}
    if origin is not None:
        hdrs["Origin"] = origin
    hdrs["CF-Connecting-IP"] = ip or fresh_ip()
    hdrs.update(headers or {})
    out = Outcome(*request(SERVER["ports"][service], method, path, body, hdrs))
    check_response(test, out)
    return out


def mails():
    return probe("capture", "list")


def submissions():
    return [m for m in mails() if not m["subject"].startswith("Intake paused")]


class WorkerCase(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        probe("limiter", "purge", FAR_FUTURE)
        probe("capture", "clear")
        probe("burst", "reset", {"limit": SC.INTAKE_BURST_LIMIT, "period": SC.INTAKE_BURST_PERIOD_S,
                                 "mode": "on"})

    def assertOutcome(self, out, expected, msg=None):
        self.assertEqual(out.status, 303, msg)
        self.assertEqual(out.id, expected, msg)


class RequestHandling(WorkerCase):
    def test_non_post_405(self):
        for method in ("GET", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"):
            with self.subTest(method=method):
                for path in ("/submit", "/"):
                    out = send(self, body=b"", ctype=None, method=method, path=path)
                    self.assertEqual(out.status, 405)
                    self.assertEqual(out.headers.get("allow"), "POST")
        self.assertEqual(mails(), [])

    def test_other_path_404(self):
        for path in ("/", "/submit/", "/SUBMIT", "/submit2", "/x/submit"):
            with self.subTest(path=path):
                out = send(self, report(), path=path)
                self.assertEqual(out.status, 404)
        self.assertEqual(mails(), [])

    def test_origin_rejected_table(self):
        for origin in ("https://evil.example", "null", "https://www.interviewscam.com",
                       "HTTPS://INTERVIEWSCAM.COM", "http://interviewscam.com",
                       "https://interviewscam.com:443", "https://interviewscam.com/",
                       "https://interviewscam.com, https://evil.example"):
            with self.subTest(origin=origin):
                ip = fresh_ip()
                out = send(self, report(), ip=ip, origin=origin)
                self.assertOutcome(out, "not-accepted")
        self.assertEqual(mails(), [])
        rows = probe("limiter", "rows")
        self.assertEqual(rows["attempts"], [], "a refused Origin was counted")

    def test_origin_absent_accepted(self):
        self.assertOutcome(send(self, report(), origin=None), "sent")
        # Measured: workerd's HTTP layer drops a header with an empty value,
        # so an empty Origin reaches the Worker as an absent one (a browser
        # never sends it empty).
        self.assertOutcome(send(self, report(), origin=""), "sent")
        self.assertEqual(len(mails()), 2)

    def test_not_multipart_rejected(self):
        cases = [(b"channel=report&name=x", "application/x-www-form-urlencoded"),
                 (json.dumps(dict(report())).encode(), "application/json"),
                 (b"channel=report", "text/plain"),
                 (multipart(report())[0], None)]
        for body, ctype in cases:
            with self.subTest(ctype=ctype):
                self.assertOutcome(send(self, body=body, ctype=ctype), "not-accepted")
        self.assertEqual(mails(), [])

    def test_malformed_multipart(self):
        body, ctype = multipart(report(), boundary="AAA")
        for bad_body, bad_type in ((body, "multipart/form-data; boundary=BBB"),
                                   (body[:-30], ctype),
                                   (b"--AAA\r\nnot a header\r\n\r\nx\r\n--AAA--\r\n", ctype),
                                   (body, "multipart/form-data")):
            with self.subTest(ctype=bad_type, size=len(bad_body)):
                out = send(self, body=bad_body, ctype=bad_type)
                self.assertOutcome(out, "not-accepted")
        self.assertEqual(mails(), [])

    def padded(self, size):
        """A valid report whose body is exactly size bytes: the padding is a
        multipart preamble, which every parser skips."""
        body, ctype = multipart(report())
        pad = size - len(body) - 2
        self.assertGreater(pad, 0)
        return b"p" * pad + b"\r\n" + body, ctype

    def test_content_length_bounds(self):
        body, ctype = self.padded(SC.INTAKE_MAX_BODY)
        self.assertOutcome(send(self, body=body, ctype=ctype), "sent", "a body of INTAKE_MAX_BODY")
        self.assertEqual(len(mails()), 1)
        # One byte over the cap, the body is never read: the headers alone,
        # with no body byte sent, get the answer (a client that sends the
        # whole body meets a closed connection).
        conn = http.client.HTTPConnection("127.0.0.1", SERVER["ports"]["intake"], timeout=20)
        try:
            conn.putrequest("POST", "/submit", skip_host=True)
            for k, v in (("Host", INTAKE_HOST), ("Content-Type", ctype), ("Content-Length", str(SC.INTAKE_MAX_BODY + 1)),
                         ("Origin", "https://interviewscam.com"), ("CF-Connecting-IP", fresh_ip())):
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
            out = Outcome(resp.status, {k.lower(): v for k, v in resp.getheaders()}, [], b"")
        finally:
            conn.close()
        self.assertOutcome(out, "too-large")

    def test_content_length_missing(self):
        body, ctype = multipart(report())
        conn = http.client.HTTPConnection("127.0.0.1", SERVER["ports"]["intake"], timeout=30)
        try:
            conn.request("POST", "/submit", body=iter([body[:100], body[100:]]), encode_chunked=True,
                         headers={"Host": INTAKE_HOST, "Content-Type": ctype, "Transfer-Encoding": "chunked",
                                  "Origin": "https://interviewscam.com", "CF-Connecting-IP": fresh_ip()})
            resp = conn.getresponse()
            resp.read()
            out = Outcome(resp.status, {k.lower(): v for k, v in resp.getheaders()}, [], b"")
        finally:
            conn.close()
        self.assertOutcome(out, "too-large")
        for value in ("abc", "-1", "1e3", " 12", "12, 12"):
            with self.subTest(content_length=value):
                status, headers = self.raw_post(body, ctype, value)
                # A malformed Content-Length is refused by the HTTP layer (400)
                # or by the Worker (too-large); it never reaches a mail.
                self.assertIn(status, (303, 400))
        self.assertEqual(mails(), [])

    def raw_post(self, body, ctype, content_length):
        sock = socket.create_connection(("127.0.0.1", SERVER["ports"]["intake"]), timeout=20)
        try:
            head = (f"POST /submit HTTP/1.1\r\nHost: intake.interviewscam.com\r\nContent-Type: {ctype}\r\n"
                    f"Content-Length: {content_length}\r\nOrigin: https://interviewscam.com\r\n"
                    f"CF-Connecting-IP: {fresh_ip()}\r\nConnection: close\r\n\r\n").encode()
            sock.sendall(head + body)
            sock.shutdown(socket.SHUT_WR)
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
        finally:
            sock.close()
        status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0
        return status, data

    def test_content_length_lies(self):
        body, ctype = multipart(report(), boundary="LIE")
        status, data = self.raw_post(body, ctype, str(len(body) - 40))
        self.assertIn(b"not-sent/#not-accepted", data)
        self.assertEqual(mails(), [], "a truncated body was mailed")


class Fields(WorkerCase):
    def test_unknown_field_rejected(self):
        for parts in (report() + [("extra", "x")], report() + [("own_name", "yes")],
                      correction() + [("name", "x")], report() + [("Name", "x")]):
            with self.subTest(parts=[p[0] for p in parts]):
                self.assertOutcome(send(self, parts), "not-accepted")
        self.assertEqual(mails(), [])

    def test_channel_closed_set(self):
        base = [p for p in report() if p[0] != "channel"]
        for parts in (base, [("channel", "foo")] + base, [("channel", "Report")] + base,
                      [("channel", "report"), ("channel", "report")] + base,
                      [("channel", "report"), ("channel", "correction")] + base):
            with self.subTest(channel=[v for k, v in parts if k == "channel"]):
                self.assertOutcome(send(self, parts), "not-accepted")
        self.assertEqual(mails(), [])

    def test_duplicate_field_rejected(self):
        for channel, parts in (("report", report()), ("correction", correction(own_name="yes"))):
            for name in [k for k, _ in parts if k != "channel"]:
                with self.subTest(channel=channel, field=name):
                    value = dict(parts)[name]
                    self.assertOutcome(send(self, parts + [(name, value)]), "not-accepted")
        self.assertEqual(mails(), [])

    def test_text_field_sent_as_file_rejected(self):
        parts = [(k, ("x.txt", "text/plain", v.encode())) if k == "details" else (k, v)
                 for k, v in report()]
        self.assertOutcome(send(self, parts), "not-accepted")
        parts = report() + [("files", "not a file")]
        self.assertOutcome(send(self, parts), "not-accepted")
        self.assertEqual(mails(), [])

    def test_own_name_value_closed(self):
        self.assertOutcome(send(self, correction(own_name="yes")), "sent")
        for value in ("on", "Yes", "", "yes "):
            with self.subTest(value=value):
                self.assertOutcome(send(self, correction(own_name=value)), "not-accepted")
        self.assertEqual(len(mails()), 1)

    BLANKS = ("", " ", "\t", "\n", "\r\n", "\u00A0", "\u3000", "\u200B", "\uFEFF", "\u2060",
              "\u0085", "\u2028", " \u200B\t\u00A0")

    def test_required_blank_table(self):
        for channel, build in (("report", report), ("correction", correction)):
            required = [f["name"] for f in SC.INTAKE_FIELDS[channel]
                        if f["required"] and f["type"] != "hidden"]  # channel: test_channel_closed_set
            self.assertTrue(required)
            for name in required:
                with self.subTest(channel=channel, field=name, form="missing"):
                    self.assertOutcome(send(self, build(**{name: None})), "missing-field")
                for blank in self.BLANKS:
                    with self.subTest(channel=channel, field=name, blank=ascii(blank)):
                        self.assertOutcome(send(self, build(**{name: blank})), "missing-field")
        self.assertEqual(mails(), [])

    def at_length(self, name, n):
        if name == "email":
            domain = "@example.com"
            return "a" * (n - len(domain)) + domain
        if name == "page_url":
            prefix = "https://interviewscam.com/reports/"
            return prefix + "a" * (n - len(prefix))
        return "x" * n

    def test_length_bounds_table(self):
        expected = 0
        for channel, build in (("report", report), ("correction", correction)):
            for field in SC.INTAKE_FIELDS[channel]:
                if field["cap"] is None:
                    continue
                name, cap = field["name"], field["cap"]
                with self.subTest(channel=channel, field=name, length=cap):
                    self.assertOutcome(send(self, build(**{name: self.at_length(name, cap)})), "sent")
                    expected += 1
                with self.subTest(channel=channel, field=name, length=cap + 1):
                    self.assertOutcome(send(self, build(**{name: self.at_length(name, cap + 1)})),
                                       "too-long")
        self.assertEqual(len(mails()), expected)

    def test_crlf_counts_once(self):
        cap = next(f["cap"] for f in SC.INTAKE_FIELDS["report"] if f["name"] == "details")
        value = "a\r\n" * (cap // 2)
        self.assertOutcome(send(self, report(details=value)), "sent")
        self.assertOutcome(send(self, report(details="a\r" * (cap // 2))), "sent")
        self.assertOutcome(send(self, report(details="a\r\n" * (cap // 2) + "a")), "too-long")
        for mail in submissions():
            self.assertNotIn("\r", mail["text"])
            self.assertIn("a\na\na\n", mail["text"], "a CR (alone or before LF) becomes one LF")

    def test_length_utf16_units(self):
        cap = next(f["cap"] for f in SC.INTAKE_FIELDS["report"] if f["name"] == "details")
        emoji = "\U0001F600"
        self.assertOutcome(send(self, report(details=emoji * (cap // 2))), "sent")
        self.assertOutcome(send(self, report(details=emoji * (cap // 2 + 1))), "too-long")

    def test_email_grammar_table(self):
        for value in ("reporter", "a@@example.com", "a@b@example.com", "a b@example.com",
                      "x@y.example\r\nBcc: z@y.example", "x@y.example\nBcc: z@y.example",
                      " x@example.com", "x@-example.com", "x@example..com", "<x@example.com>",
                      "x@exa_mple.com", "\u0430@example.com", "x@example.com\u200B"):
            with self.subTest(email=ascii(value)):
                self.assertOutcome(send(self, report(email=value)), "bad-address")
                self.assertOutcome(send(self, correction(email=value)), "bad-address")
        self.assertEqual(mails(), [])
        for value in ("x@example.com", "first.last+tag@sub.example.co", "x@localhost", "!#$%&'*+/=?^_`{|}~-@example.com"):
            with self.subTest(valid=value):
                self.assertOutcome(send(self, report(email=value)), "sent")
        self.assertEqual([m["replyTo"] for m in mails()],
                         ["x@example.com", "first.last+tag@sub.example.co", "x@localhost",
                          "!#$%&'*+/=?^_`{|}~-@example.com"])

    def test_page_url_table(self):
        for value in ("http://interviewscam.com/x/", "https://interviewscam.com.evil.example/",
                      "https://interviewscam.com@evil.example/", "https://interviewsc\u0430m.com/x/",
                      "//interviewscam.com/x/", "/reports/x/", "file:///x", "https://evil.example/",
                      "https://www.interviewscam.com/", "javascript:alert(1)", "interviewscam.com/x/",
                      "https://interviewscam.com:8443/x/"):
            with self.subTest(page_url=ascii(value)):
                self.assertOutcome(send(self, correction(page_url=value)), "bad-page-url")
        self.assertEqual(mails(), [])
        for value in ("https://interviewscam.com/reports/a/../b/", "https://interviewscam.com",
                      "HTTPS://INTERVIEWSCAM.COM/x/", "https://interviewscam.com:443/x/"):
            with self.subTest(valid=value):
                self.assertOutcome(send(self, correction(page_url=value)), "sent")
        self.assertEqual(len(mails()), 4)


class Honeypot(WorkerCase):
    def test_honeypot_table(self):
        for value in ("x", " ", "\u200B", "https://example.com", None):
            with self.subTest(website=ascii(value)):
                self.assertOutcome(send(self, report(website=value)), "not-accepted")
                self.assertOutcome(send(self, correction(website=value)), "not-accepted")
        self.assertEqual(mails(), [])


class Files(WorkerCase):
    def files(self, *items):
        return [("files", item) for item in items]

    def test_no_file_chosen_part_ignored(self):
        out = send(self, report() + self.files(("", "application/octet-stream", b"")))
        self.assertOutcome(out, "sent")
        self.assertEqual(mails()[0]["attachments"], [])
        out = send(self, report() + self.files(("", "application/octet-stream", b""), ("a.png", "image/png", PNG)))
        self.assertOutcome(out, "sent")
        self.assertEqual(len(mails()[1]["attachments"]), 1)

    def test_named_empty_file_rejected(self):
        self.assertOutcome(send(self, report() + self.files(("a.png", "image/png", b""))), "not-an-image")
        self.assertOutcome(send(self, report() + self.files(("", "image/png", PNG))), "not-accepted")
        self.assertEqual(mails(), [])

    def test_magic_accepted_table(self):
        for data, mime, ext in ((PNG, "image/png", "png"), (JPEG, "image/jpeg", "jpg"),
                                (GIF87, "image/gif", "gif"), (GIF89, "image/gif", "gif"),
                                (WEBP, "image/webp", "webp")):
            with self.subTest(ext=ext, head=data[:6]):
                probe("capture", "clear")
                self.assertOutcome(send(self, report() + self.files(("shot", "application/octet-stream", data))),
                                   "sent")
                (att,) = mails()[0]["attachments"]
                self.assertEqual((att["filename"], att["type"], att["disposition"], att["size"]),
                                 (f"evidence-1.{ext}", mime, "attachment", len(data)))
                self.assertEqual(att["sha256"], hashlib.sha256(data).hexdigest())
                self.assertTrue(att["binary"])

    def test_magic_rejected_table(self):
        for label, data in (("text", b"just some text, named .png"), ("pe", b"MZ\x90\x00" + bytes(60)),
                            ("svg", b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"),
                            ("html", b"<!doctype html><title>x</title>"), ("pdf", b"%PDF-1.7\n"),
                            ("heic", b"\x00\x00\x00\x18ftypheic" + bytes(8)), ("png7", PNG[:7]),
                            ("wave", b"RIFF\x24\x00\x00\x00WAVEfmt " + bytes(8)), ("riff-short", b"RIFF\x00\x00"),
                            ("gif88", b"GIF88a" + bytes(8)), ("jpeg2", b"\xff\xd8"), ("zip", b"PK\x03\x04" + bytes(20))):
            with self.subTest(kind=label):
                self.assertOutcome(send(self, report() + self.files(("evidence.png", "image/png", data))),
                                   "not-an-image")
        self.assertOutcome(send(self, report() + self.files(("a.png", "image/png", PNG),
                                                            ("b.png", "image/png", b"MZ" + bytes(10)))),
                           "not-an-image")
        self.assertEqual(mails(), [])

    def test_client_type_ignored(self):
        self.assertOutcome(send(self, report() + self.files(("photo.png", "image/png", JPEG))), "sent")
        (att,) = mails()[0]["attachments"]
        self.assertEqual((att["filename"], att["type"]), ("evidence-1.jpg", "image/jpeg"))

    def test_file_name_sanitized(self):
        name = '../../x\r\n"\x07\u202E' + "y" * 500 + ".png"
        self.assertOutcome(send(self, report() + self.files((name, "image/png", PNG),
                                                            ("https://evil.example/a.png", "image/png", PNG))),
                           "sent")
        mail = mails()[0]
        self.assertEqual([a["filename"] for a in mail["attachments"]], ["evidence-1.png", "evidence-2.png"])
        lines = [line for line in mail["text"].split("\n") if line.startswith("evidence-")]
        self.assertEqual(len(lines), 2, mail["text"])
        listed = lines[0].split(": ", 1)[1]
        self.assertLessEqual(len(listed), SC.INTAKE_FILE_NAME_CAP)
        self.assertNotIn("\x07", listed)
        self.assertTrue(listed.startswith("../../x"), listed)
        self.assertIn("hxxps://evil", lines[1])

    def test_file_count_bounds(self):
        n = SC.INTAKE_MAX_FILES
        self.assertOutcome(send(self, report() + self.files(*[(f"{i}.png", "image/png", PNG) for i in range(n)])),
                           "sent")
        self.assertEqual(len(mails()[0]["attachments"]), n)
        self.assertOutcome(send(self, report() + self.files(*[(f"{i}.png", "image/png", PNG)
                                                              for i in range(n + 1)])), "too-many-files")
        self.assertEqual(len(mails()), 1)

    @staticmethod
    def big_files(total, count=10):
        """count PNG files of total bytes together."""
        size, rest = divmod(total, count)
        sizes = [size + (1 if i < rest else 0) for i in range(count)]
        return [("files", (f"{i}.png", "image/png", PNG + bytes(s - len(PNG)))) for i, s in enumerate(sizes)]

    def test_upload_total_bounds(self):
        cap = SC.INTAKE_MAX_UPLOAD_BYTES
        self.assertOutcome(send(self, report() + self.big_files(cap)), "sent")
        self.assertEqual(sum(a["size"] for a in mails()[0]["attachments"]), cap)
        self.assertOutcome(send(self, report() + self.big_files(cap + 1)), "too-large")
        self.assertOutcome(send(self, report() + self.big_files(cap + 1, count=1)), "too-large")
        self.assertEqual(len(mails()), 1)


class Limiter(WorkerCase):
    KEY = "a" * 64

    def burst_off(self):
        probe("burst", "reset", {"limit": SC.INTAKE_BURST_LIMIT, "period": SC.INTAKE_BURST_PERIOD_S,
                                 "mode": "off"})

    def test_client_limit_6_7(self):
        self.burst_off()
        ip = fresh_ip()
        for i in range(SC.INTAKE_CLIENT_LIMIT):
            self.assertOutcome(send(self, report(website="x"), ip=ip), "not-accepted", f"attempt {i + 1}")
        self.assertOutcome(send(self, report(), ip=ip), "too-many-attempts")
        self.assertEqual(len(probe("limiter", "rows")["attempts"]), SC.INTAKE_CLIENT_LIMIT,
                         "the refused 7th attempt wrote a row")
        self.assertEqual(mails(), [])

    def test_burst_binding_limits_first(self):
        ip = fresh_ip()
        for i in range(SC.INTAKE_BURST_LIMIT):
            self.assertOutcome(send(self, report(website="x"), ip=ip), "not-accepted", f"attempt {i + 1}")
        self.assertOutcome(send(self, report(), ip=ip), "too-many-attempts")
        self.assertEqual(len(probe("limiter", "rows")["attempts"]), SC.INTAKE_BURST_LIMIT,
                         "an attempt the binding refused reached the Durable Object")
        keys = probe("burst", "keys")
        self.assertEqual(len(keys), 1)
        self.assertRegex(keys[0], r"^[0-9a-f]{64}$")

    def test_burst_binding_failure_fails_closed(self):
        probe("burst", "reset", {"limit": 6, "period": 60, "mode": "throw"})
        self.assertOutcome(send(self, report()), "error")
        self.assertEqual(mails(), [])

    def test_client_limit_counts_rejections(self):
        self.burst_off()
        ip = fresh_ip()
        for parts in (report(website="x"), correction(page_url="/x/"), report(email="bad"),
                      report(name=""), report() + [("files", ("a.png", "image/png", b"MZ"))],
                      report() + [("x", "y")]):
            send(self, parts, ip=ip)
        self.assertOutcome(send(self, report(), ip=ip), "too-many-attempts")
        self.assertEqual(mails(), [])

    def test_client_daily_mail_cap(self):
        pin_day()
        self.burst_off()
        ip = fresh_ip()
        for i in range(SC.INTAKE_CLIENT_DAILY_MAILS):
            self.assertOutcome(send(self, report(), ip=ip), "sent", f"mail {i + 1}")
        before = probe("limiter", "rows")
        self.assertOutcome(send(self, report(), ip=ip), "too-many-attempts")
        after = probe("limiter", "rows")
        self.assertEqual(before, after, "a refused attempt over the daily mail cap wrote a row")
        self.assertEqual(len(mails()), SC.INTAKE_CLIENT_DAILY_MAILS)
        self.assertOutcome(send(self, report()), "sent", "another client still mails")

    def test_limiter_window_exclusive_bound(self):
        now = base_now()
        window = SC.INTAKE_CLIENT_WINDOW_MS
        self.assertTrue(probe("limiter", "attempt", self.KEY, now)["ok"])
        for i in range(SC.INTAKE_CLIENT_LIMIT - 1):
            self.assertTrue(probe("limiter", "attempt", self.KEY, now + 1 + i)["ok"])
        self.assertFalse(probe("limiter", "attempt", self.KEY, now + window - 1)["ok"],
                         "3,599,999 ms later the first attempt still counts")
        self.assertTrue(probe("limiter", "attempt", self.KEY, now + window)["ok"],
                        "3,600,000 ms later the first attempt no longer counts")
        self.assertEqual(probe("helper", "limiterDecide", [now], now + window - 1),
                         {"count": 1, "allowed": True})
        self.assertEqual(probe("helper", "limiterDecide", [now], now + window),
                         {"count": 0, "allowed": True})
        full = [now + i for i in range(SC.INTAKE_CLIENT_LIMIT)]
        self.assertEqual(probe("helper", "limiterDecide", full, now + 10)["allowed"], False)

    def test_limiter_same_ms(self):
        now = base_now()
        for _ in range(SC.INTAKE_CLIENT_LIMIT):
            self.assertTrue(probe("limiter", "attempt", self.KEY, now)["ok"])
        self.assertFalse(probe("limiter", "attempt", self.KEY, now)["ok"])
        self.assertEqual(len(probe("limiter", "rows")["attempts"]), SC.INTAKE_CLIENT_LIMIT)

    def test_limiter_future_row_counts(self):
        now = base_now()
        for i in range(SC.INTAKE_CLIENT_LIMIT):
            self.assertTrue(probe("limiter", "attempt", self.KEY, now + 600_000 + i)["ok"])
        self.assertFalse(probe("limiter", "attempt", self.KEY, now)["ok"],
                         "rows from a clock ahead must count")

    def test_client_key_table(self):
        groups = [("v6:2001:db8:1:2", ["2001:db8:1:2::1", "2001:0DB8:1:2:ffff::9", "2001:db8:1:2:0:0:0:1",
                                       "2001:db8:1:2:abcd:ef01:2345:6789", "2001:db8:0001:0002::"]),
                  ("v6:2001:db8:1:3", ["2001:db8:1:3::1"]),
                  ("v4:192.0.2.1", ["192.0.2.1", "::ffff:192.0.2.1", "::FFFF:c000:201", "0:0:0:0:0:ffff:192.0.2.1"]),
                  ("v4:192.0.2.2", ["192.0.2.2"]),
                  ("v6:0:0:0:0", ["::1", "::"]),
                  ("unknown", ["", None, "not an ip", "256.0.0.1", "1.2.3", "01.2.3.4", "1:2:3:4:5:6:7:8:9",
                               "fe80::1%eth0", "2001:db8::1::2", "1.2.3.4 "])]
        for expected, ips in groups:
            for ip in ips:
                with self.subTest(ip=ip):
                    self.assertEqual(probe("helper", "clientKeyMaterial", ip), expected)

    def test_missing_client_ip(self):
        self.burst_off()
        for i in range(SC.INTAKE_CLIENT_LIMIT):
            out = Outcome(*request(SERVER["ports"]["intake"], "POST", "/submit",
                                   *self.body_headers(report(website="x"))))
            self.assertOutcome(out, "not-accepted", f"attempt {i + 1}")
        out = Outcome(*request(SERVER["ports"]["intake"], "POST", "/submit", *self.body_headers(report())))
        self.assertOutcome(out, "too-many-attempts", "clients without an IP share one key")

    @staticmethod
    def body_headers(parts):
        body, ctype = multipart(parts)
        return body, {"Content-Type": ctype, "Origin": "https://interviewscam.com"}

    def test_limiter_stores_no_ip(self):
        pin_day()
        ip4 = "198.51.100.77"
        send(self, report(), ip=ip4)
        send(self, report(), ip="2001:db8:dead:beef::5")
        rows = probe("limiter", "rows")
        for table in ("attempts", "mails"):
            for row in rows[table]:
                self.assertRegex(row["key"], r"^[0-9a-f]{64}$")
        # The needles are scanned in the strings only (fix round 7): the rows
        # also hold times in ms, and a time can contain "2001" by chance.
        strings, numbers = [], []

        def walk(value):
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, bool):
                pass
            elif isinstance(value, (int, float)):
                numbers.append(value)
            elif isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(rows)
        for needle in ("198.51.100", "51.100.77", "dead", "beef", "2001", "db8"):
            self.assertFalse([text for text in strings if needle in text], needle)
        self.assertNotIn(3325256781, numbers, "the IPv4 address stored as an integer")
        self.assertEqual([r["key"] for r in rows["attempts"]].count(PIN_KEY), 1)
        self.assertEqual(len([r for r in rows["attempts"] if r["key"] != PIN_KEY]), 2)
        self.assertEqual(len(rows["mails"]), 2)
        self.assertNotIn(ip4, "\n".join(stdout_lines()))

    def test_limiter_alarm_purges(self):
        now = base_now()
        window = SC.INTAKE_CLIENT_WINDOW_MS
        probe("limiter", "attempt", self.KEY, now)
        probe("limiter", "attempt", "b" * 64, now + 1000)
        rows = probe("limiter", "rows")
        self.assertEqual(rows["alarm"], now + window, "the alarm is set to the earliest expiry")
        probe("limiter", "purge", now + window)
        rows = probe("limiter", "rows")
        self.assertEqual([r["key"] for r in rows["attempts"]], ["b" * 64])
        self.assertEqual(rows["alarm"], now + 1000 + window, "the alarm moves to the next expiry")
        probe("limiter", "purge", now + 1000 + window)
        rows = probe("limiter", "rows")
        self.assertEqual(rows["attempts"], [])
        self.assertIsNone(rows["alarm"])

    def test_daily_rows_purged_at_day_end(self):
        now = base_now()
        self.assertTrue(probe("limiter", "attempt", self.KEY, now)["ok"])
        self.assertTrue(probe("limiter", "reserve", self.KEY, now)["ok"])
        rows = probe("limiter", "rows")
        day = probe("helper", "dayKey", now)
        midnight = (now // 86_400_000 + 1) * 86_400_000
        self.assertEqual(rows["mails"], [{"day": day, "key": self.KEY, "n": 1}])
        self.assertEqual(rows["days"], [{"day": day, "n": 1}])
        probe("limiter", "purge", now + SC.INTAKE_CLIENT_WINDOW_MS)
        rows = probe("limiter", "rows")
        self.assertEqual(rows["alarm"], midnight, "the day rows keep the alarm at 00:00 UTC")
        probe("limiter", "purge", midnight - 1)
        self.assertEqual(len(probe("limiter", "rows")["mails"]), 1)
        probe("limiter", "purge", midnight)
        rows = probe("limiter", "rows")
        self.assertEqual((rows["mails"], rows["days"], rows["alarm"]), ([], [], None))
        # A reserve() alone sets the alarm to the end of its day.
        self.assertTrue(probe("limiter", "reserve", self.KEY, now)["ok"])
        self.assertEqual(probe("limiter", "rows")["alarm"], midnight)

    def test_limiter_failure_fails_closed(self):
        self.assertOutcome(send(self, report(), service="intake-broken-limiter"), "error")
        self.assertEqual(mails(), [])


class GlobalCap(WorkerCase):
    def test_daily_cap_50_51(self):
        pin_day()
        cap, per = SC.INTAKE_DAILY_CAP, SC.INTAKE_CLIENT_DAILY_MAILS
        ips = [fresh_ip() for _ in range(math.ceil((cap + 2) / per))]
        for i in range(cap):
            self.assertOutcome(send(self, report(name=f"Report {i + 1}"), ip=ips[i // per]), "sent",
                               f"mail {i + 1}")
        self.assertOutcome(send(self, report(), ip=ips[cap // per]), "paused")
        all_mails = mails()
        notices = [m for m in all_mails if m["subject"].startswith("Intake paused")]
        self.assertEqual(len(all_mails), cap + 1)
        self.assertEqual(len(notices), 1)
        self.assertNotIn("replyTo", notices[0])
        self.assertOutcome(send(self, report(), ip=ips[(cap + 1) // per]), "paused")
        self.assertEqual(len(mails()), cap + 1, "a second notice the same day")
        day = probe("limiter", "rows")["days"]
        self.assertEqual(len(day), 1)

    def test_day_key_utc_boundary(self):
        a = probe("helper", "dayKey", 1_798_761_599_999)  # 2026-12-31T23:59:59.999Z
        b = probe("helper", "dayKey", 1_798_761_600_000)  # 2027-01-01T00:00:00.000Z
        self.assertEqual((a, b), ("2026-12-31", "2027-01-01"))

    def test_send_failure_refunds(self):
        pin_day()
        ip = fresh_ip()
        probe("capture", "setFail", "throw")
        self.assertOutcome(send(self, report(), ip=ip), "error")
        rows = probe("limiter", "rows")
        self.assertEqual(sum(r["n"] for r in rows["days"]), 0, "the global slot was not refunded")
        self.assertEqual(sum(r["n"] for r in rows["mails"]), 0, "the client's mail was not refunded")
        probe("capture", "setFail", "")
        for _ in range(SC.INTAKE_CLIENT_DAILY_MAILS):
            self.assertOutcome(send(self, report(), ip=ip), "sent")
        self.assertEqual(sum(r["n"] for r in probe("limiter", "rows")["days"]), SC.INTAKE_CLIENT_DAILY_MAILS)

    def test_exception_maps_to_error(self):
        out = send(self, report(), service="intake-bad-key")
        self.assertOutcome(out, "error")
        self.assertEqual(mails(), [])


class ResponsesAndMail(WorkerCase):
    def test_redirect_targets_closed(self):
        seen = set()
        for parts, kw in ((report(), {}), (report(website="x"), {}), (report(name=""), {}),
                          (report(email="x"), {}), (correction(page_url="/x/"), {}),
                          (report(name="x" * 201), {}),
                          (report() + [("files", ("a.png", "image/png", b"MZ"))], {}),
                          (report() + [("files", (f"{i}.png", "image/png", PNG)) for i in range(11)], {}),
                          (report(), {"origin": "https://evil.example"})):
            out = send(self, parts, **kw)
            self.assertEqual(out.status, 303)
            self.assertTrue(out.location.startswith("https://interviewscam.com/"))
            seen.add(out.id)
        self.assertEqual(seen, {"sent", "not-accepted", "missing-field", "bad-address", "bad-page-url",
                                "too-long", "not-an-image", "too-many-files"})
        self.assertEqual(set(SC.INTAKE_RESULT_IDS),
                         {"too-large", "too-many-files", "not-an-image", "missing-field", "too-long",
                          "bad-address", "bad-page-url", "too-many-attempts", "paused", "not-accepted", "error"})

    def test_response_headers(self):
        for kw in ({"method": "GET", "body": b"", "ctype": None}, {"path": "/x"}, {},
                   {"origin": "null"}, {"service": "intake-bad-key"}, {"service": "intake-broken-limiter"}):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                send(self, report(), **kw)  # check_response asserts the headers

    def test_mail_envelope_fixed(self):
        self.assertOutcome(send(self, report(email="r@example.com")), "sent")
        self.assertOutcome(send(self, correction(own_name="yes")), "sent")
        for mail in mails():
            self.assertEqual(mail["from"], SC.INTAKE_SENDER)
            self.assertNotIn("to", mail["keys"])
            self.assertNotIn("html", mail["keys"])
            self.assertNotIn("cc", mail["keys"])
            self.assertNotIn("bcc", mail["keys"])
            self.assertNotIn("headers", mail["keys"])
            self.assertEqual(set(mail["keys"]) - {"attachments"}, {"from", "replyTo", "subject", "text"})
        self.assertEqual([m["replyTo"] for m in mails()], ["r@example.com", "owner@example.com"])

    def test_subject_table(self):
        url = "https://interviewscam.com/reports/x/"
        rows = [(report(name="Example Co"), "Report: Example Co"),
                (report(name="\u0007A\u202EB\u200BC  \t D\u2066E\u0085F\u200DG\uFEFFH"), "Report: ABC DE FGH"),
                (report(name="x" * 200), "Report: " + "x" * 200),
                (report(name="Acme https://evil.example/login"), "Report: Acme hxxps://evil.example/login"),
                (report(name="Acme HTTP://a ftp://b"), "Report: Acme hxxp://a fxp://b"),
                (correction(page_url=url), "Correction: hxxps" + url[5:]),
                (correction(page_url=url, own_name="yes"), "Correction, own name: hxxps" + url[5:]),
                (correction(page_url=url + "\u200b"), "Correction: hxxps" + url[5:])]
        for parts, _ in rows:
            self.assertOutcome(send(self, parts), "sent")
        self.assertEqual([m["subject"] for m in mails()], [s for _, s in rows])
        self.assertEqual(probe("helper", "cleanSubject", "a\r\nb\u202Ac"), "a bc")
        long_url = "https://interviewscam.com/" + "\u00E9" * 900
        self.assertEqual(probe("helper", "subjectFor", "correction", {"page_url": long_url, "own_name": "yes"}),
                         "Correction, own name: hxxps" + long_url[5:], "the raw value, not the percent-encoded one")

    def test_defang_table(self):
        for raw, want in (("https://evil.example/x", "hxxps://evil.example/x"),
                          ("HtTpS://evil.example", "hxxps://evil.example"),
                          ("http://a ftp://b FTP://c", "hxxp://a fxp://b fxp://c"),
                          ("hxxps://already", "hxxps://already"), ("https and http: not urls", "https and http: not urls"),
                          ("xhttps://a", "xhxxps://a"), ("https:/one-slash", "https:/one-slash")):
            with self.subTest(raw=raw):
                self.assertEqual(probe("helper", "defangSchemes", raw), want)
        self.assertOutcome(send(self, report(details="see https://evil.example/x and HTTP://b")), "sent")
        text = mails()[0]["text"]
        self.assertIn("see hxxps://evil.example/x and hxxp://b", text)
        self.assertNotRegex(text.lower(), r"https?://")

    def test_defang_idempotent(self):
        for raw in ("https://a http://b ftp://c", "HTTPS://X", "hxxps://y", "fxp://z", "https://https://q"):
            once = probe("helper", "defangSchemes", raw)
            self.assertEqual(probe("helper", "defangSchemes", once), once)

    def test_body_controls_stripped(self):
        self.assertOutcome(send(self, report(details="a\x00b\x07c\td\r\ne\x1bf\x7fg\u0085h")), "sent")
        text = mails()[0]["text"]
        self.assertIn("abc\td\ne", text)
        self.assertNotRegex(text, "[\x00-\x08\x0b-\x1f]")

    def test_mail_size_at_caps(self):
        caps = {f["name"]: f["cap"] for f in SC.INTAKE_FIELDS["report"] if f["cap"]}
        fields = {name: "\u20AC" * cap for name, cap in caps.items()}  # 3 UTF-8 bytes per unit
        fields["email"] = "a" * (caps["email"] - len("@example.com")) + "@example.com"
        parts = report(**fields) + Files.big_files(SC.INTAKE_MAX_UPLOAD_BYTES)
        body, _ = multipart(parts)
        self.assertLessEqual(len(body), SC.INTAKE_MAX_BODY)
        self.assertOutcome(send(self, parts), "sent")
        mail = mails()[0]
        text_bytes = len(mail["text"].encode("utf-8")) + len(mail["subject"].encode("utf-8"))
        qp = text_bytes * 3 * 76 / 75
        self.assertLessEqual(qp, 419_430, "the mail text bound of ADR-0006 Numbers")
        att = sum(math.ceil(a["size"] / 3) * 4 * 78 / 76 for a in mail["attachments"])
        self.assertLessEqual(att + qp, 14.1 * 1024 * 1024)
        self.assertLess(att + qp, 25 * 1024 * 1024)

    def test_logs_event_codes_only(self):
        secret_name = "Sentinel Name 7f3a"
        ip = "203.0.113.99"
        send(self, report(name=secret_name), ip=ip)
        send(self, report(name=secret_name, website="x"), ip=ip)
        send(self, report(name=secret_name), origin="https://evil.example")
        send(self, report(), service="intake-bad-key")
        send(self, report(), service="intake-broken-limiter")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any("code=" in line for line in stdout_lines()):
            time.sleep(0.1)
        lines = stdout_lines()
        self.assertGreater(len(lines), 5)
        bad = [line for line in lines if not LOG_LINE.match(line)]
        self.assertEqual(bad, [])
        joined = "\n".join(lines)
        for needle in (secret_name, ip, "example.com", "f17474ac"):
            self.assertNotIn(needle, joined)

    def test_constants_match_worker(self):
        worker = probe("constants")
        expect = {
            "SITE_ORIGIN": SC.SITE_ORIGIN, "SENT_URL": SC.INTAKE_SENT_URL,
            "NOT_SENT_URL": SC.INTAKE_NOT_SENT_URL, "ORIGIN": SC.INTAKE_ORIGIN, "ACTION": SC.INTAKE_ACTION,
            "SENDER": SC.INTAKE_SENDER, "FIELDS": SC.INTAKE_FIELDS,
            "IMAGE_TYPES": SC.INTAKE_IMAGE_TYPES,
            "MAX_FILES": SC.INTAKE_MAX_FILES, "MAX_UPLOAD_BYTES": SC.INTAKE_MAX_UPLOAD_BYTES,
            "MAX_BODY": SC.INTAKE_MAX_BODY, "CLIENT_LIMIT": SC.INTAKE_CLIENT_LIMIT,
            "CLIENT_WINDOW_MS": SC.INTAKE_CLIENT_WINDOW_MS, "CLIENT_DAILY_MAILS": SC.INTAKE_CLIENT_DAILY_MAILS,
            "DAILY_CAP": SC.INTAKE_DAILY_CAP, "FILE_NAME_CAP": SC.INTAKE_FILE_NAME_CAP,
            "NOTICE_TRIES": SC.INTAKE_NOTICE_TRIES,
            "NOTICE_STALE_MS": SC.INTAKE_NOTICE_STALE_MS,
            "RESULT_IDS": list(SC.INTAKE_RESULT_IDS), "LIMITER_KEY_BYTES": SC.INTAKE_LIMITER_KEY_BYTES,
            "BURST_ABSENT_BINDING": SC.INTAKE_BURST_ABSENT_BINDING,
            "BURST_ABSENT_VALUE": SC.INTAKE_BURST_ABSENT_VALUE,
        }
        self.assertEqual(sorted(worker), sorted(expect))
        for key, value in expect.items():
            with self.subTest(key=key):
                self.assertEqual(worker[key], json.loads(json.dumps(value)))
        # ADR-0006 Numbers: `headers` is 2x the largest measured header block
        # (12,767 bytes, 2026-11-13) rounded up to the next 1,000; the body
        # allowance is 3 UTF-8 bytes per text unit plus 18 parts of 1,024
        # bytes, doubled and rounded up to a whole 64 KiB.
        caps = {f["name"]: f["cap"] for f in SC.INTAKE_FIELDS["report"] if f["cap"]}
        self.assertEqual(caps["headers"], -(-2 * 12_767 // 1000) * 1000)
        allowance = -(-2 * (3 * sum(caps.values()) + 18 * 1024) // 65_536) * 65_536
        self.assertEqual((sum(caps.values()), allowance), (36_654, 262_144))
        self.assertEqual(SC.INTAKE_MAX_BODY, SC.INTAKE_MAX_UPLOAD_BYTES + allowance)
        self.assertEqual(SC.INTAKE_ACTION, SC.INTAKE_ORIGIN + "/submit")

    def test_config_matches_pins(self):
        pins = TOOL.read_pins(ROOT / "tools" / "pins.env")
        text = CONFIG.read_text(encoding="utf-8")
        self.assertEqual(set(re.findall(r'compatibilityDate = "([0-9-]+)"', text)),
                         {pins["WORKERD_COMPAT_DATE"]})

    def test_live_suite_against_workerd(self):
        """The suite `tools/intake.py live-test` runs against production
        (PR 4), here against workerd, without the 2.5 s spacing."""
        ip = fresh_ip()
        results = TOOL.live_suite(f"http://127.0.0.1:{SERVER['ports']['intake']}", spacing=0,
                                  extra_headers={"CF-Connecting-IP": ip, "Host": INTAKE_HOST})
        failed = [r for r in results if not r[1]]
        self.assertEqual(failed, [])
        self.assertEqual({r[0] for r in results},
                         {"live_valid_report", "live_oversize", "live_not_image", "live_honeypot",
                          "live_headers", "live_rate_limit"})
        self.assertEqual(len(mails()), 1)


def logged(action):
    """The log lines workerd printed while action() ran."""
    before = len(stdout_lines())
    action()
    deadline = time.monotonic() + 5
    lines = stdout_lines()
    while time.monotonic() < deadline and len(lines) == before:
        time.sleep(0.05)
        lines = stdout_lines()
    time.sleep(0.2)
    return stdout_lines()[before:]


def body_lines(mail):
    return mail["text"].split("\n")


def probe_error(target, fn, *args):
    """The error a probe call ends in, or None when it succeeds."""
    _, _, _, data = request(SERVER["ports"]["probe"], "POST", "/",
                            json.dumps({"target": target, "fn": fn, "args": list(args)}).encode(),
                            {"Content-Type": "application/json"})
    reply = json.loads(data)
    return None if reply.get("ok") else reply.get("error")


class FixRound1(WorkerCase):
    """Fix round 1 of PR 2: the review findings and QA's gap rows."""

    # --- review 1: the daily caps across 00:00 UTC
    def midnight(self):
        day = 86_400_000
        return (base_now() // day + 1) * day

    def test_reserve_after_rollover_counts_on_new_day(self):
        d = self.midnight()
        key, other = "a" * 64, "b" * 64
        for _ in range(SC.INTAKE_CLIENT_DAILY_MAILS):
            self.assertTrue(probe("limiter", "attempt", key, d - 1000)["ok"])
            self.assertTrue(probe("limiter", "reserve", key, d - 1000)["ok"])
        self.assertFalse(probe("limiter", "reserve", key, d - 1000)["ok"])
        self.assertTrue(probe("limiter", "attempt", other, d + 1000)["ok"])  # deletes the old day's rows
        late = probe("limiter", "reserve", key, d - 1000)  # a straggler whose body ran past 00:00
        new_day = probe("helper", "dayKey", d + 1000)
        self.assertEqual(late.get("day"), new_day, "counted on a day whose rows are gone")
        self.assertTrue(late["ok"])
        rows = probe("limiter", "rows")
        self.assertEqual(rows["mails"], [{"day": new_day, "key": key, "n": 1}])
        self.assertEqual(rows["days"], [{"day": new_day, "n": 1}])

    def test_global_cap_after_rollover_counts_on_new_day(self):
        d = self.midnight()
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", d - 1000)["ok"])
        self.assertFalse(probe("limiter", "reserve", "c" * 64, d - 1000)["ok"])
        probe("limiter", "attempt", "e" * 64, d + 1000)
        late = probe("limiter", "reserve", "d" * 64, d - 1000)
        self.assertEqual((late["ok"], late["day"]), (True, probe("helper", "dayKey", d + 1000)))
        self.assertEqual(probe("limiter", "rows")["days"], [{"day": late["day"], "n": 1}])

    def test_refund_names_its_day(self):
        now = base_now()
        slot = probe("limiter", "reserve", "a" * 64, now)
        probe("limiter", "refund", "a" * 64, slot["day"])
        self.assertEqual(probe("limiter", "rows")["days"], [{"day": slot["day"], "n": 0}])

    # --- review 3: the explicit no-binding mode
    def test_no_binding_mode_relies_on_limiter(self):
        ip = fresh_ip()
        self.assertOutcome(send(self, report(), ip=ip, service="intake-no-burst"), "sent")
        for _ in range(SC.INTAKE_CLIENT_LIMIT - 1):
            send(self, report(website="x"), ip=ip, service="intake-no-burst")
        self.assertOutcome(send(self, report(), ip=ip, service="intake-no-burst"), "too-many-attempts")
        self.assertEqual(probe("burst", "keys"), [], "the no-binding mode reached a binding")

    def test_missing_binding_fails_closed(self):
        lines = logged(lambda: self.assertOutcome(send(self, report(), service="intake-missing-burst"), "error"))
        self.assertIn("intake event=error code=E_BURST_MISSING", lines)
        self.assertEqual(mails(), [])

    # --- review 4: the subject defang, and page_url without white space
    WHITE_SPACE = [chr(c) for c in (*range(0x09, 0x0e), 0x20, 0x85, 0xa0, 0x1680, *range(0x2000, 0x200b),
                                    0x2028, 0x2029, 0x202f, 0x205f, 0x3000)]

    def test_page_url_white_space_members(self):
        self.assertEqual(len(self.WHITE_SPACE), 25)
        for ch in self.WHITE_SPACE:
            for value in (f"https://interviewscam.com/x{ch}https://evil.example/", f"{ch}https://interviewscam.com/x/",
                          f"https://interviewscam.com/x/{ch}"):
                with self.subTest(ch=hex(ord(ch)), at=value.index(ch)):
                    self.assertFalse(probe("helper", "pageUrlOk", value))
        self.assertTrue(probe("helper", "pageUrlOk", "https://interviewscam.com/x/\u200B"))
        self.assertOutcome(send(self, correction(page_url="https://interviewscam.com/x https://evil.example/payload")),
                           "bad-page-url")

    def test_subject_scheme_members(self):
        for raw, want in (("https://a", "hxxps://a"), ("http://a", "hxxp://a"), ("ftp://a", "fxp://a"),
                          ("HTTPS://a", "hxxps://a"), ("FtP://a", "fxp://a"), ("hxxps://a", "hxxps://a")):
            with self.subTest(raw=raw):
                self.assertEqual(probe("helper", "subjectFor", "report", {"name": raw}), "Report: " + want)
                self.assertEqual(probe("helper", "subjectFor", "correction", {"page_url": raw}), "Correction: " + want)

    # --- review 5: single-line fields stay on one line
    def test_single_line_fields_one_line(self):
        for name in ("name", "contact_start"):
            for brk in ("\n", "\r\n", "\r", "\t"):
                with self.subTest(field=name, brk=ascii(brk)):
                    probe("capture", "clear")
                    forged = f"Acme{brk}Reply address: someone-else@example.org{brk}Own name: yes"
                    self.assertOutcome(send(self, report(**{name: forged})), "sent")
                    lines = body_lines(mails()[0])
                    self.assertFalse([line for line in lines if line.startswith(("Reply address: someone",
                                                                                  "Own name:"))], lines)
                    label = {"name": "Name: ", "contact_start": "Where the contact started: "}[name]
                    self.assertIn(label + "Acme Reply address: someone-else@example.org Own name: yes", lines)

    # --- review 10: the send_email stand-in enforces the documented rules
    def test_capture_enforces_send_email_rules(self):
        ok = {"from": "intake@interviewscam.com", "subject": "s", "text": "t"}
        self.assertIsNone(probe_error("capture", "send", ok))
        self.assertIsNone(probe_error("capture", "send", dict(ok, to="operator@example.com")))
        att = {"content": "x", "filename": "a", "type": "t", "disposition": "attachment"}
        bad = {
            "sender off the domain": dict(ok, **{"from": "x@evil.example"}),
            "to another address": dict(ok, to="other@example.com"),
            "no subject": {k: v for k, v in ok.items() if k != "subject"},
            "subject over 998": dict(ok, subject="s" * 999),
            "replyTo not an address": dict(ok, replyTo=5),
            "attachments not a list": dict(ok, attachments="x"),
            "bad disposition": dict(ok, attachments=[dict(att, disposition="x")]),
            "33 attachments": dict(ok, attachments=[att] * 33),
            "attachment without content": dict(ok, attachments=[{k: v for k, v in att.items() if k != "content"}]),
            "attachment without filename": dict(ok, attachments=[{k: v for k, v in att.items() if k != "filename"}]),
            "attachment without type": dict(ok, attachments=[{k: v for k, v in att.items() if k != "type"}]),
            "over 25 MiB": dict(ok, text="x" * (25 * 1024 * 1024 + 1)),
        }
        for label, message in bad.items():
            with self.subTest(case=label):
                self.assertIsNotNone(probe_error("capture", "send", message))
        self.assertIsNone(probe_error("capture", "send", dict(ok, attachments=[att] * 32)))

    def test_notice_failure_retried(self):
        pin_day()
        now = base_now()
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])
        probe("capture", "setFail", "notice")
        lines = logged(lambda: self.assertOutcome(send(self, report()), "paused"))
        self.assertEqual(lines, ["intake event=paused code=E_NOTICE"])
        self.assertEqual(mails(), [])
        probe("capture", "setFail", "")
        lines = logged(lambda: self.assertOutcome(send(self, report()), "paused"))
        self.assertEqual(lines, ["intake event=paused code=E_DAILY_CAP"])
        self.assertOutcome(send(self, report()), "paused")
        (notice,) = mails()
        day = probe("limiter", "rows")["days"][0]["day"]
        self.assertEqual(notice["subject"], f"Intake paused: {SC.INTAKE_DAILY_CAP} submissions on {day}")
        self.assertEqual(notice["text"], f"The daily cap of {SC.INTAKE_DAILY_CAP} mailed submissions was reached on "
                         f"{day} (UTC). Until 00:00 UTC the form answers /not-sent/#paused, which points reporters "
                         "to the email address.\n")
        self.assertEqual(sorted(notice["keys"]), ["from", "subject", "text"])

    # --- QA: rule branches without a killing case
    def test_urlencoded_complete_rejected(self):
        body = urllib.parse.urlencode(dict(report())).encode()
        self.assertOutcome(send(self, body=body, ctype="application/x-www-form-urlencoded"), "not-accepted")
        self.assertEqual(mails(), [])

    def test_burst_refusal_distinct_from_limiter(self):
        probe("burst", "reset", {"limit": 3, "period": 60, "mode": "on"})
        ip = fresh_ip()
        for _ in range(3):
            self.assertOutcome(send(self, report(website="x"), ip=ip), "not-accepted")
        lines = logged(lambda: self.assertOutcome(send(self, report(website="x"), ip=ip), "too-many-attempts"))
        self.assertEqual(lines, ["intake event=too-many-attempts code=E_BURST_LIMIT"])
        self.assertEqual(len(probe("limiter", "rows")["attempts"]), 3)

    def test_limiter_key_is_hmac(self):
        send(self, report(website="x"), ip="2001:db8:abc:1::1")
        secret = bytes.fromhex("f17474ac183f5727b19cad79d6bcc87ce754d404e1b5ffaf7ff3f83346bf0246")
        want = hmac.new(secret, b"v6:2001:db8:abc:1", hashlib.sha256).hexdigest()
        self.assertEqual(probe("burst", "keys"), [want])
        self.assertEqual([r["key"] for r in probe("limiter", "rows")["attempts"]], [want])

    def test_reserve_failure_fails_closed(self):
        lines = logged(lambda: self.assertOutcome(send(self, report(), service="intake-broken-reserve"), "error"))
        self.assertEqual(lines, ["intake event=error code=E_LIMITER"])
        self.assertEqual(mails(), [])

    def test_reserve_rechecks_client_mails(self):
        now, key = base_now(), "b" * 64
        for _ in range(SC.INTAKE_CLIENT_DAILY_MAILS):
            self.assertTrue(probe("limiter", "reserve", key, now)["ok"])
        self.assertEqual(probe("limiter", "reserve", key, now)["reason"], "client-mails")

    def test_notice_reopen_only_after_notice(self):
        now = base_now()
        slots = [probe("limiter", "reserve", f"{i:064x}", now) for i in range(10)]
        probe("limiter", "noticeFailed", slots[0]["day"], SC.INTAKE_DAILY_CAP + 1)
        self.assertEqual(probe("limiter", "rows")["days"], [{"day": slots[0]["day"], "n": 10}])
        # After a failed try (an even step) a second report of failure changes nothing.
        for i in range(10, SC.INTAKE_DAILY_CAP):
            probe("limiter", "reserve", f"{i:064x}", now)
        first = probe("limiter", "reserve", "c" * 64, now)
        self.assertTrue(first["notice"])
        probe("limiter", "noticeFailed", slots[0]["day"], first["noticeTry"])
        probe("limiter", "noticeFailed", slots[0]["day"], first["noticeTry"])
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"], SC.INTAKE_DAILY_CAP + 2)

    def test_reserve_refusal_code_client_mails(self):
        """The mail cap checked again at reserve(): a key reaches it while its
        body is still uploading (the race attempt() cannot see)."""
        pin_day()
        probe("burst", "reset", {"limit": 6, "period": 60, "mode": "off"})
        ip = fresh_ip()
        secret = bytes.fromhex("f17474ac183f5727b19cad79d6bcc87ce754d404e1b5ffaf7ff3f83346bf0246")
        key = hmac.new(secret, probe("helper", "clientKeyMaterial", ip).encode(), hashlib.sha256).hexdigest()
        body, ctype = multipart(report())

        def race():
            sock = socket.create_connection(("127.0.0.1", SERVER["ports"]["intake"]), timeout=30)
            try:
                sock.sendall((f"POST /submit HTTP/1.1\r\nHost: intake.interviewscam.com\r\nContent-Type: {ctype}\r\n"
                              f"Content-Length: {len(body)}\r\nOrigin: https://interviewscam.com\r\n"
                              f"CF-Connecting-IP: {ip}\r\nConnection: close\r\n\r\n").encode() + body[:50])
                deadline = time.monotonic() + 15
                while not any(r["key"] == key for r in probe("limiter", "rows")["attempts"]):
                    self.assertLess(time.monotonic(), deadline, "the attempt never reached the limiter")
                    time.sleep(0.05)
                now = base_now()
                for _ in range(SC.INTAKE_CLIENT_DAILY_MAILS):
                    self.assertTrue(probe("limiter", "reserve", key, now)["ok"])
                sock.sendall(body[50:])
                data = b""
                while chunk := sock.recv(65536):
                    data += chunk
            finally:
                sock.close()
            self.assertIn(b"not-sent/#too-many-attempts", data)

        self.assertEqual(logged(race), ["intake event=too-many-attempts code=E_CLIENT_MAILS"])
        self.assertEqual(mails(), [])

    def test_refund_after_notice_keeps_pause(self):
        now = base_now()
        slots = [probe("limiter", "reserve", f"{i:064x}", now) for i in range(SC.INTAKE_DAILY_CAP)]
        first = probe("limiter", "reserve", "c" * 64, now)
        self.assertEqual((first["ok"], first.get("notice")), (False, True))
        probe("limiter", "refund", f"{0:064x}", slots[0]["day"])
        again = probe("limiter", "reserve", "d" * 64, now)
        self.assertEqual((again["ok"], again.get("notice")), (False, False))

    # --- QA: per-member sets
    SUBJECT_STRIP = [chr(c) for c in (*range(0x200b, 0x2010), 0x2060, 0xfeff, *range(0x202a, 0x202f),
                                      *range(0x2066, 0x206a))]
    CONTROLS = [chr(c) for c in (*range(0x00, 0x09), *range(0x0e, 0x20), *range(0x7f, 0x85),
                                 *range(0x86, 0xa0))]

    def test_subject_strip_members(self):
        self.assertEqual(len(self.SUBJECT_STRIP), 16)
        for ch in self.SUBJECT_STRIP + self.CONTROLS:
            with self.subTest(ch=hex(ord(ch))):
                self.assertEqual(probe("helper", "cleanSubject", "a" + ch + "b"), "ab")
        for raw, want in (("a \t\n b", "a b"), ("  a  ", "a"), ("a \u0007 b", "a b"), ("a \u0080 \u200B b", "a b"), ("a\u0085b", "a b"), ("a\u3000\u00A0b", "a b"),
                          ("a\u000bb", "a b"), ("a\u000cb", "a b"), ("a\rb", "a b")):
            with self.subTest(raw=ascii(raw)):
                self.assertEqual(probe("helper", "cleanSubject", raw), want)

    def test_body_control_members(self):
        controls = "".join(chr(c) for c in (*range(0x00, 0x09), 0x0b, 0x0c, *range(0x0e, 0x20)))
        self.assertOutcome(send(self, report(details="a" + controls + "b\tc\nd\u007f\u0085e")), "sent")
        self.assertIn("\nab\tc\nd\u007f\u0085e\n", mails()[0]["text"])

    def test_email_members(self):
        for value, ok in (("@example.com", False), ("x@a-b.example", True), ("x@" + "a" * 63 + ".example", True),
                          ("x@" + "a" * 64 + ".example", False), ("x@example.", False), ("x@-a.example", False),
                          ("x@a-.example", False), ("x@a", True), ("x@a.b-c.d", True), ("x@.example", False),
                          ("xexample.com", False), ("x@a.b", True)):
            with self.subTest(value=value):
                self.assertEqual(probe("helper", "isValidEmail", value), ok)

    def test_magic_byte_members(self):
        for mime, ext, signature in SC.INTAKE_IMAGE_TYPES:
            data = bytearray(16)
            for offset, hexes in signature:
                data[offset:offset + len(hexes) // 2] = bytes.fromhex(hexes)
            self.assertEqual(probe("helper", "detectImageType", data.hex()), {"type": mime, "ext": ext})
            for offset, hexes in signature:
                for i in range(len(hexes) // 2):
                    with self.subTest(ext=ext, byte=offset + i):
                        loose = bytearray(data)
                        loose[offset + i] ^= 0x01
                        self.assertIsNone(probe("helper", "detectImageType", loose.hex()))
            end = max(o + len(h) // 2 for o, h in signature)
            with self.subTest(ext=ext, truncated=end - 1):
                self.assertIsNone(probe("helper", "detectImageType", bytes(data[:end - 1]).hex()))

    def test_file_name_boundary(self):
        cap = SC.INTAKE_FILE_NAME_CAP
        for name, want in (("a" * cap, "a" * cap), ("a" * (cap + 1), "a" * cap),
                           ("a" * (cap - 1) + "\U0001F600", "a" * (cap - 1)),
                           ("a" * (cap - 2) + "\U0001F600", "a" * (cap - 2) + "\U0001F600"),
                           ("a\tb\tc", "a b c")):
            with self.subTest(length=len(name)):
                probe("capture", "clear")
                self.assertOutcome(send(self, report() + [("files", (name, "image/png", PNG, "raw"))]), "sent")
                lines = [line for line in body_lines(mails()[0]) if line.startswith("evidence-1.png: ")]
                self.assertEqual(lines, ["evidence-1.png: " + want])

    # --- QA: the mail text and the log codes
    def test_mail_text_exact(self):
        self.assertOutcome(send(self, report(name="N", contact_start="C", details="D", headers="H",
                                             email="r@example.com") + [("files", ("s.png", "image/png", PNG))]),
                           "sent")
        self.assertOutcome(send(self, correction(page_url="https://interviewscam.com/p/", request="R",
                                                 email="o@example.com", own_name="yes")), "sent")
        self.assertOutcome(send(self, correction(page_url="https://interviewscam.com/p/", request="R",
                                                 email="o@example.com")), "sent")
        notice = ("Notice: the URL schemes http, https and ftp in this message were rewritten to hxxp, hxxps "
                  "and fxp; bare domains were not changed.")
        self.assertEqual([m["text"] for m in mails()], [
            f"{notice}\nChannel: report\nName: N\nWhere the contact started: C\n\nDetails:\nD\n\n\n"
            "Mail headers:\nH\n\nReply address: r@example.com\n\n"
            "Files (attachment: original name, cut to 100 characters):\nevidence-1.png: s.png\n",
            f"{notice}\nChannel: correction\nPage: hxxps://interviewscam.com/p/\n\nRequest:\nR\n\n"
            "Own name: yes\nReply address: o@example.com\n",
            f"{notice}\nChannel: correction\nPage: hxxps://interviewscam.com/p/\n\nRequest:\nR\n\n"
            "Own name: no\nReply address: o@example.com\n"])

    def test_log_codes_table(self):
        pin_day()
        body, ctype = multipart(report(), boundary="AAA")
        rows = [
            (lambda: send(self, report(), origin="https://evil.example"), "not-accepted", "E_ORIGIN"),
            (lambda: send(self, body=b"a=b", ctype="application/x-www-form-urlencoded"), "not-accepted",
             "E_CONTENT_TYPE"),
            (lambda: send(self, body=body[:-30], ctype=ctype), "not-accepted", "E_PARSE"),
            (lambda: send(self, report()[1:]), "not-accepted", "E_CHANNEL"),
            (lambda: send(self, report() + [("x", "y")]), "not-accepted", "E_FIELD"),
            (lambda: send(self, report() + [("name", "x")]), "not-accepted", "E_DUPLICATE"),
            (lambda: send(self, report(website="x")), "not-accepted", "E_HONEYPOT"),
            (lambda: send(self, report(name=" ")), "missing-field", "E_REQUIRED"),
            (lambda: send(self, report(name="x" * 201)), "too-long", "E_LENGTH"),
            (lambda: send(self, report(email="x")), "bad-address", "E_EMAIL"),
            (lambda: send(self, correction(page_url="/x")), "bad-page-url", "E_PAGE_URL"),
            (lambda: send(self, report() + [("files", (f"{i}", "image/png", PNG)) for i in range(11)]),
             "too-many-files", "E_FILE_COUNT"),
            (lambda: send(self, report() + Files.big_files(SC.INTAKE_MAX_UPLOAD_BYTES + 1)), "too-large",
             "E_UPLOAD_SIZE"),
            (lambda: send(self, report() + [("files", ("a", "image/png", b"MZ"))]), "not-an-image", "E_FILE_TYPE"),
            (lambda: send(self, report(), service="intake-broken-limiter"), "error", "E_LIMITER"),
            (lambda: send(self, report(), service="intake-bad-key"), "error", "E_UNCAUGHT"),
            (lambda: send(self, report()), "sent", None),
        ]
        for action, event, code in rows:
            with self.subTest(event=event, code=code):
                want = f"intake event={event}" + (f" code={code}" if code else "")
                self.assertEqual(logged(action), [want])
        probe("burst", "reset", {"limit": 6, "period": 60, "mode": "throw"})
        self.assertEqual(logged(lambda: send(self, report())), ["intake event=error code=E_BURST"])
        probe("burst", "reset", {"limit": 6, "period": 60, "mode": "off"})
        ip = fresh_ip()
        for _ in range(SC.INTAKE_CLIENT_LIMIT):
            send(self, report(website="x"), ip=ip)
        self.assertEqual(logged(lambda: send(self, report(), ip=ip)),
                         ["intake event=too-many-attempts code=E_CLIENT_LIMIT"])
        ip = fresh_ip()
        for _ in range(SC.INTAKE_CLIENT_DAILY_MAILS):
            send(self, report(), ip=ip)
        self.assertEqual(logged(lambda: send(self, report(), ip=ip)),
                         ["intake event=too-many-attempts code=E_CLIENT_MAILS"])
        probe("capture", "setFail", "throw")
        self.assertEqual(logged(lambda: send(self, report())), ["intake event=error code=E_SEND"])


class FixRound2(WorkerCase):
    """Fix round 2 of PR 2: the delta review (N3, N7) and QA's recheck."""

    def setUp(self):
        super().setUp()
        probe("record", "setup", False, False, False)

    def raw_submit(self, port_name, parts=None, pause=0.0):
        """One POST over a raw socket; the body after its first 50 bytes is
        held back for pause seconds, as a slow upload would be."""
        body, mp = multipart(parts if parts is not None else report())
        head = ("POST /submit HTTP/1.1\r\nHost: intake.interviewscam.com\r\nOrigin: https://interviewscam.com\r\n"
                f"CF-Connecting-IP: {fresh_ip()}\r\nContent-Type: {mp}\r\nContent-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n").encode()
        sock = socket.create_connection(("127.0.0.1", SERVER["ports"][port_name]), timeout=30)
        try:
            sock.sendall(head + body[:50])
            time.sleep(pause)
            sock.sendall(body[50:])
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
        finally:
            sock.close()
        return data

    # --- QA: the fresh time and the reserved day reach the limiter
    def test_reserve_gets_fresh_time_after_slow_body(self):
        data = self.raw_submit("intake-record", pause=1.5)
        self.assertIn(b"/sent/", data)
        times = probe("record")
        attempt = [t for k, t in times if k == "attempt"][-1]
        reserve = [t for k, t in times if k == "reserve"][-1]
        self.assertGreaterEqual(reserve - attempt, 1000, times)

    def test_refund_uses_reserved_day(self):
        probe("capture", "setFail", "throw")
        self.assertIn(b"#error", self.raw_submit("intake-record"))
        self.assertIn(["refund", "2000-01-01"], probe("record"))

    def test_notice_names_reserved_day(self):
        probe("record", "setup", True, False, False)
        self.assertIn(b"#paused", self.raw_submit("intake-record"))
        (notice,) = mails()
        self.assertIn("on 2000-01-01", notice["subject"])

    def test_attempt_failure_fails_closed_even_if_reserve_works(self):
        probe("record", "setup", False, True, False)
        lines = logged(lambda: self.assertIn(b"#error", self.raw_submit("intake-record")))
        self.assertEqual(lines, ["intake event=error code=E_LIMITER"])
        self.assertEqual([k for k, _ in probe("record")], ["attempt"])
        self.assertEqual(mails(), [])

    def test_refund_failure_is_logged_and_still_error(self):
        probe("record", "setup", False, False, True)
        probe("capture", "setFail", "throw")
        lines = logged(lambda: self.assertIn(b"#error", self.raw_submit("intake-record")))
        self.assertEqual(lines, ["intake event=error code=E_REFUND", "intake event=error code=E_SEND"])

    def test_notice_reopen_failure_is_logged_and_still_paused(self):
        probe("record", "setup", True, False, True)
        probe("capture", "setFail", "notice")
        lines = logged(lambda: self.assertIn(b"#paused", self.raw_submit("intake-record")))
        self.assertEqual(lines, ["intake event=paused code=E_NOTICE_REOPEN", "intake event=paused code=E_NOTICE"])
        self.assertIn(["noticeFailed", "2000-01-01"], probe("record"))  # the reserved day, not today

    def test_notice_reopen_touches_only_its_own_day(self):
        day = 86_400_000
        first = base_now()
        for t in (first, first + day):
            for i in range(SC.INTAKE_DAILY_CAP):
                self.assertTrue(probe("limiter", "reserve", f"{i:064x}", t)["ok"])
            self.assertTrue(probe("limiter", "reserve", "c" * 64, t)["notice"])
        days = {r["day"]: r["n"] for r in probe("limiter", "rows")["days"]}
        self.assertEqual(sorted(days.values()), [SC.INTAKE_DAILY_CAP + 1] * 2, days)
        probe("limiter", "noticeFailed", sorted(days)[-1], SC.INTAKE_DAILY_CAP + 1)
        days = {r["day"]: r["n"] for r in probe("limiter", "rows")["days"]}
        self.assertEqual(sorted(days.values()), [SC.INTAKE_DAILY_CAP + 1, SC.INTAKE_DAILY_CAP + 2], days)

    def test_reserve_alarm_is_end_of_counted_day(self):
        day = 86_400_000
        older = base_now()
        newer = older + day
        self.assertTrue(probe("limiter", "reserve", "a" * 64, newer)["ok"])
        self.assertTrue(probe("limiter", "reserve", "b" * 64, older)["ok"])  # counted on the newer day
        self.assertEqual(probe("limiter", "rows")["alarm"], (newer // day + 1) * day)

    # --- fix round 3, R4: a try in flight does not block the day forever
    def test_stale_notice_try_counts_as_failed(self):
        now = base_now()
        stale = SC.INTAKE_NOTICE_STALE_MS
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])
        self.assertTrue(probe("limiter", "reserve", "c" * 64, now)["notice"])  # try 1, then cancelled
        self.assertFalse(probe("limiter", "reserve", "c" * 64, now + stale)["notice"], "a try in flight 60 s")
        self.assertTrue(probe("limiter", "reserve", "c" * 64, now + stale + 1)["notice"], "a stale try blocked the day")
        days = probe("limiter", "rows")
        self.assertEqual(days["days"][0]["n"], SC.INTAKE_DAILY_CAP + 3)
        self.assertEqual(days["notices"][0]["at"], now + stale + 1)
        later = now + 2 * stale + 2
        self.assertTrue(probe("limiter", "reserve", "c" * 64, later)["notice"])  # try 3
        last = later + stale + 1
        self.assertFalse(probe("limiter", "reserve", "c" * 64, last)["notice"], "a fourth try")
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"], SC.INTAKE_DAILY_CAP + 2 * SC.INTAKE_NOTICE_TRIES)

    def test_sent_notice_is_final(self):
        pin_day()
        now = base_now()
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])
        self.assertOutcome(send(self, report()), "paused")
        self.assertEqual(len(mails()), 1)
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"], SC.INTAKE_DAILY_CAP + 2 * SC.INTAKE_NOTICE_TRIES)
        late = probe("limiter", "reserve", "d" * 64, now + 10 * SC.INTAKE_NOTICE_STALE_MS)
        self.assertFalse(late["notice"], "a sent notice was tried again")

    def test_notice_sent_recorded_with_reserved_day(self):
        probe("record", "setup", True, False, False)
        self.assertIn(b"#paused", self.raw_submit("intake-record"))
        self.assertIn(["noticeSent", "2000-01-01"], probe("record"))

    def test_notice_sent_failure_is_logged_and_still_paused(self):
        probe("record", "setup", True, False, True)
        lines = logged(lambda: self.assertIn(b"#paused", self.raw_submit("intake-record")))
        self.assertEqual(lines, ["intake event=paused code=E_NOTICE_SENT", "intake event=paused code=E_DAILY_CAP"])

    def test_notice_sent_touches_only_its_own_day(self):
        day = 86_400_000
        first = base_now()
        for t in (first, first + day):
            for i in range(SC.INTAKE_DAILY_CAP):
                self.assertTrue(probe("limiter", "reserve", f"{i:064x}", t)["ok"])
            self.assertTrue(probe("limiter", "reserve", "c" * 64, t)["notice"])
        days = {r["day"]: r["n"] for r in probe("limiter", "rows")["days"]}
        self.assertEqual(sorted(days.values()), [SC.INTAKE_DAILY_CAP + 1] * 2, days)
        probe("limiter", "noticeSent", sorted(days)[-1])
        days = {r["day"]: r["n"] for r in probe("limiter", "rows")["days"]}
        self.assertEqual(sorted(days.values()),
                         [SC.INTAKE_DAILY_CAP + 1, SC.INTAKE_DAILY_CAP + 2 * SC.INTAKE_NOTICE_TRIES], days)

    def test_notice_try_clock_is_the_counted_time(self):
        now = base_now()
        stale = SC.INTAKE_NOTICE_STALE_MS
        late = now + 500_000
        for i in range(SC.INTAKE_DAILY_CAP - 1):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])
        self.assertTrue(probe("limiter", "reserve", "d" * 64, late)["ok"])  # the newest time seen is late
        self.assertTrue(probe("limiter", "reserve", "c" * 64, now + 1_000)["notice"])  # counted at late
        self.assertEqual(probe("limiter", "rows")["notices"][0]["at"], late)
        probe("limiter", "attempt", "e" * 64, late + stale + 1)  # the clock moves on
        self.assertTrue(probe("limiter", "reserve", "c" * 64, late + 1_000)["notice"], "stale by the counted time")

    def test_notice_sent_only_from_flight(self):
        now = base_now()
        slots = [probe("limiter", "reserve", f"{i:064x}", now) for i in range(10)]
        probe("limiter", "noticeSent", slots[0]["day"])
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"], 10)

    # --- fix round 4, T2: a late report moves only its own try
    def paused_day(self, now):
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])

    def test_late_failure_of_stale_try_keeps_newer_try(self):
        now, stale = base_now(), SC.INTAKE_NOTICE_STALE_MS
        self.paused_day(now)
        one = probe("limiter", "reserve", "c" * 64, now)
        two = probe("limiter", "reserve", "c" * 64, now + stale + 1)
        self.assertEqual((one["noticeTry"], two["noticeTry"]), (SC.INTAKE_DAILY_CAP + 1, SC.INTAKE_DAILY_CAP + 3))
        probe("limiter", "noticeFailed", one["day"], one["noticeTry"])  # try 1 fails late
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"], SC.INTAKE_DAILY_CAP + 3)
        self.assertFalse(probe("limiter", "reserve", "c" * 64, now + stale + 2)["notice"],
                         "a third try while the second is in flight")

    def test_late_success_of_stale_try_ends_the_day(self):
        now, stale = base_now(), SC.INTAKE_NOTICE_STALE_MS
        self.paused_day(now)
        one = probe("limiter", "reserve", "c" * 64, now)
        two = probe("limiter", "reserve", "c" * 64, now + stale + 1)
        probe("limiter", "noticeFailed", two["day"], two["noticeTry"])  # try 2 fails fast
        probe("limiter", "noticeSent", one["day"])  # try 1 went out late
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"], SC.INTAKE_DAILY_CAP + 2 * SC.INTAKE_NOTICE_TRIES)
        self.assertFalse(probe("limiter", "reserve", "c" * 64, now + 3 * stale)["notice"],
                         "a try after a notice went out")

    def test_notice_failed_needs_a_try(self):
        now = base_now()
        self.paused_day(now)
        day = probe("limiter", "reserve", "c" * 64, now)["day"]
        for bad in (None, SC.INTAKE_DAILY_CAP, SC.INTAKE_DAILY_CAP + 2, "51"):
            with self.subTest(noticeTry=bad):
                self.assertIsNotNone(probe_error("limiter", "noticeFailed", day, bad))

    # --- fix round 5, D4-1: the pinned day holds across 00:00 UTC
    def test_pinned_day_holds_across_midnight(self):
        day = 86_400_000
        midnight = (int(time.time() * 1000) // day + 1) * day  # the next 00:00 UTC, always ahead of the wall clock
        for wall in (midnight - 5 * 60_000, midnight - 1000):  # 23:55:00Z and 23:59:59Z of today
            with self.subTest(wall=wall):
                probe("limiter", "purge", FAR_FUTURE)
                pinned = base_now(wall)
                probe("limiter", "attempt", PIN_KEY, pinned)
                before = probe("limiter", "reserve", "a" * 64, wall)            # the Worker before 00:00
                after = probe("limiter", "reserve", "b" * 64, wall + 10 * 60_000)  # and after it
                self.assertEqual((before["day"], after["day"]), (probe("helper", "dayKey", pinned),) * 2)
                self.assertEqual((wall + 10 * 60_000) // day, wall // day + 1, "the second time is past 00:00")

    # --- fix round 5, D4-6: the notice runs under ctx.waitUntil
    def test_notice_runs_under_wait_until(self):
        probe("record", "setup", True, False, False)
        body, ctype = multipart(report())
        _, _, _, data = request(SERVER["ports"]["probe"], "POST", "/waituntil", body,
                                {"Content-Type": ctype, "Origin": "https://interviewscam.com",
                                 "CF-Connecting-IP": fresh_ip()})
        result = json.loads(data)["result"]
        self.assertEqual((result["status"], result["location"]), (303, SC.INTAKE_NOT_SENT_URL + "#paused"))
        self.assertEqual((result["waited"], result["settled"]), (1, [True]))
        self.assertEqual(result["pending"], [True], "the promise is the running notice, not a settled stand-in")
        self.assertEqual(result["order"], ["sent", "recorded", "settled", "returned"],
                         "the promise must cover the send and its report, and the response waits for both")
        self.assertIn(["noticeSent", "2000-01-01"], probe("record"))
        self.assertEqual(len(mails()), 1)

    # --- fix round 9, D8-1: the failure report runs under ctx.waitUntil too
    def test_failed_notice_report_runs_under_wait_until(self):
        probe("record", "setup", True, False, False)
        probe("capture", "setFail", "notice")
        try:
            body, ctype = multipart(report())
            _, _, _, data = request(SERVER["ports"]["probe"], "POST", "/waituntil", body,
                                    {"Content-Type": ctype, "Origin": "https://interviewscam.com",
                                     "CF-Connecting-IP": fresh_ip()})
        finally:
            probe("capture", "setFail", "")
        result = json.loads(data)["result"]
        self.assertEqual((result["status"], result["location"]), (303, SC.INTAKE_NOT_SENT_URL + "#paused"))
        self.assertEqual((result["waited"], result["settled"]), (1, [False]))
        self.assertEqual(result["pending"], [True], "the promise is the running notice, not a settled stand-in")
        self.assertEqual(result["order"], ["sent", "recorded", "settled", "returned"],
                         "the promise must cover the failed send and its report")
        self.assertIn(["noticeFailed", "2000-01-01"], probe("record"))
        self.assertEqual(mails(), [])

    # --- fix round 5, D4-4a: only the intake host
    def test_other_host_refused_before_limiter(self):
        for host in ("evil.example", "intake.interviewscam.com.evil.example", "interviewscam.com", "127.0.0.1",
                     "xintake.interviewscam.com", "evil.intake.interviewscam.com"):
            with self.subTest(host=host):
                out = send(self, report(), headers={"Host": host})
                self.assertEqual(out.status, 404)
        self.assertEqual(probe("burst", "keys"), [])
        self.assertEqual(probe("limiter", "rows")["attempts"], [])
        self.assertEqual(mails(), [])

    def test_intake_host_with_a_port_is_the_intake_host(self):
        """Cloudflare proxies HTTPS on 8443 too; the URL then carries the port, the host is the same one."""
        self.assertOutcome(send(self, report(), headers={"Host": INTAKE_HOST + ":8443"}), "sent")

    # --- QA: the limiter's own rows
    def test_access_expiry_is_own_key_only(self):
        now, a, b = base_now(), "a" * 64, "b" * 64
        self.assertTrue(probe("limiter", "attempt", a, now)["ok"])
        self.assertTrue(probe("limiter", "attempt", b, now)["ok"])
        later = now + SC.INTAKE_CLIENT_WINDOW_MS + 1
        self.assertTrue(probe("limiter", "attempt", a, later)["ok"])
        rows = [(r["key"][0], r["at"]) for r in probe("limiter", "rows")["attempts"]]
        self.assertEqual(sorted(rows), sorted([("a", later), ("b", now)]))

    def test_paused_refusal_writes_no_mail_row(self):
        now = base_now()
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])
        before = probe("limiter", "rows")
        probe("limiter", "reserve", "c" * 64, now)  # the notice refusal
        probe("limiter", "reserve", "d" * 64, now)  # a plain paused refusal
        after = probe("limiter", "rows")
        self.assertEqual(before["mails"], after["mails"])
        self.assertEqual(after["days"][0]["n"], SC.INTAKE_DAILY_CAP + 1)

    # --- N3: every White_Space character stays inside its line
    WHITE_SPACE = FixRound1.WHITE_SPACE

    def forged_lines(self, mail):
        return [line for line in mail["text"].splitlines()
                if line.startswith(("Reply address: someone", "Own name:"))]

    def test_single_line_white_space_members(self):
        for name in ("name", "contact_start"):
            for ch in self.WHITE_SPACE:
                with self.subTest(field=name, ch=hex(ord(ch))):
                    probe("capture", "clear")
                    forged = f"Acme{ch}Reply address: someone-else@example.org{ch}Own name: yes"
                    self.assertOutcome(send(self, report(**{name: forged})), "sent")
                    mail = mails()[0]
                    self.assertEqual(self.forged_lines(mail), [])
                    self.assertNotRegex(mail["text"].split("\nReply address: ")[0], "[\u0085\u2028\u2029]")

    def test_file_name_white_space_members(self):
        for ch in self.WHITE_SPACE:
            if ch in "\n\r\x0b\x0c":
                continue  # a browser escapes CR and LF, and the C0 strip removes VT and FF first
            with self.subTest(ch=hex(ord(ch))):
                probe("capture", "clear")
                name = f"a{ch}Own name: yes.png"
                self.assertOutcome(send(self, report() + [("files", (name, "image/png", PNG, "raw"))]), "sent")
                mail = mails()[0]
                self.assertEqual(self.forged_lines(mail), [])
                self.assertIn("evidence-1.png: a Own name: yes.png", mail["text"].splitlines())

    # --- N7: the notice is tried at most NOTICE_TRIES times a day
    def test_notice_tries_bounded(self):
        pin_day()
        now = base_now()
        for i in range(SC.INTAKE_DAILY_CAP):
            self.assertTrue(probe("limiter", "reserve", f"{i:064x}", now)["ok"])
        probe("capture", "setFail", "notice")
        codes = []
        for _ in range(SC.INTAKE_NOTICE_TRIES + 2):
            codes += logged(lambda: self.assertOutcome(send(self, report()), "paused"))
        self.assertEqual(codes, ["intake event=paused code=E_NOTICE"] * SC.INTAKE_NOTICE_TRIES
                         + ["intake event=paused code=E_DAILY_CAP"] * 2)
        self.assertEqual(probe("limiter", "rows")["days"][0]["n"],
                         SC.INTAKE_DAILY_CAP + 2 * SC.INTAKE_NOTICE_TRIES)
        probe("capture", "setFail", "")
        self.assertOutcome(send(self, report()), "paused")
        self.assertEqual(mails(), [], "a fourth notice after the tries ran out")


if __name__ == "__main__":
    unittest.main()
