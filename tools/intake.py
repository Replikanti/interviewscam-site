#!/usr/bin/env python3
"""The intake Worker's deploy tool (ADR-0006 part 10), for the operator only.

    python3 -I tools/intake.py deploy
    python3 -I tools/intake.py verify
    python3 -I tools/intake.py live-test --target https://intake.interviewscam.com

deploy uploads worker/intake.js as the one script interviewscam-intake,
with its bindings, and maps intake.interviewscam.com to it, then runs
verify. verify reads back what decides where submissions go: the deployed
script bytes against INTAKE_WORKER_SHA256, the bindings (the send_email
destination among them), tail consumers, Logpush, observability and the
custom domain. live-test runs the live suite of ADR-0006 Consequences
against the endpoint; tests/worker/test_intake.py runs the same code
against workerd.

deploy and verify refuse to run under CI or GITHUB_ACTIONS, on a tree with
uncommitted or untracked changes, on a HEAD other than site/main, and when
worker/intake.js is a symlink or differs from its pin. The API token comes
from CLOUDFLARE_API_TOKEN or a hidden prompt; the account ID, the zone ID
and the destination address are prompted. None of them is written, logged
or printed, and every line the tool prints passes through a redaction of
the token and the generated limiter key. The tool never creates a token.

Python standard library only (urllib, ssl, json), always run as python3 -I.
Exit 0 on success, 1 on an API error, a mismatch or a failed live case, 2
on a refusal or a usage error.
"""

import argparse
import email.parser
import email.policy
import getpass
import hashlib
import http.client
import importlib.util
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
API_BASE = "https://api.cloudflare.com/client/v4"
# The tests' stub API (tests/worker/test_intake_tool.py). Only this exact
# loopback form is accepted, so the variable cannot send the token elsewhere.
LOOPBACK_API = re.compile(r"http://127\.0\.0\.1:[0-9]{1,5}/client/v4")
LOOPBACK_TARGET = re.compile(r"http://127\.0\.0\.1:[0-9]{1,5}")
REMOTE_REF = "site/main"
WORKER_FILE = "worker/intake.js"
MODULE_NAME = "intake.js"
HEX32 = re.compile(r"[0-9a-f]{32}")
TOKEN_FORM = re.compile(r"[\x21-\x7e]{20,400}")
EMAIL_RE = re.compile(r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                      r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")
# The live suite's spacing between two attempts (ADR-0006 Consequences): at
# most 5 in any 10 s, so the WAF rule, which blocks a sixth, never answers.
LIVE_SPACING_S = 2.5
LIVE_RATE_ATTEMPTS = 7


class Refusal(Exception):
    """Exit 2: the tool will not act."""


class Failure(Exception):
    """Exit 1: an API error, a mismatch or a failed live case."""


class Out:
    """Every printed line, with the token and the limiter key redacted."""

    def __init__(self):
        self.secrets = []

    def add_secret(self, value):
        if value:
            self.secrets.append(value)

    def redact(self, text):
        text = str(text)
        for value in self.secrets:
            text = text.replace(value, "[token]" if value is self.secrets[0] else "[secret]")
        return text

    def say(self, text="", stream=None):
        print(self.redact(text), file=stream or sys.stdout, flush=True)


OUT = Out()


def load_sitecheck(root):
    spec = importlib.util.spec_from_file_location("sitecheck", root / "tools" / "sitecheck.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_pins(path):
    """tools/pins.env, parsed as fetch-tools.sh parses it (never sourced)."""
    pins = {}
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(\S+)", line)
        if not m:
            raise Refusal(f"{path}:{n}: not a KEY=VALUE line")
        pins[m.group(1)] = m.group(2)
    return pins


def git(root, *args):
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


# ---------------------------------------------------------------------------
# Preflight (ADR-0006 part 10)

def refuse_ci():
    for var in ("CI", "GITHUB_ACTIONS"):
        if os.environ.get(var, ""):
            raise Refusal(f"tools/intake.py refuses to run under CI or GITHUB_ACTIONS ({var} is set): "
                          "the deploy credential never enters CI (ADR-0006 part 10)")


def api_base():
    base = os.environ.get("INTAKE_API_BASE", "")
    if not base:
        return API_BASE
    if not LOOPBACK_API.fullmatch(base):
        raise Refusal("INTAKE_API_BASE may only name the tests' stub API on loopback "
                      "(http://127.0.0.1:<port>/client/v4); unset it to reach Cloudflare")
    return base


def check_tree(root, sc):
    rc, status = git(root, "status", "--porcelain", "--untracked-files=all")
    if rc != 0:
        raise Refusal(f"{root} is not a git work tree")
    if status:
        raise Refusal("the tree has uncommitted or untracked changes; deploy and verify run only "
                      f"on a clean checkout of {REMOTE_REF}")
    rc_head, head = git(root, "rev-parse", "--verify", "HEAD^{commit}")
    rc_main, main = git(root, "rev-parse", "--verify", f"{REMOTE_REF}^{{commit}}")
    if rc_main != 0:
        raise Refusal(f"no {REMOTE_REF} in this clone; add the public code repo as the remote `site` "
                      "and fetch it")
    if rc_head != 0 or head != main:
        raise Refusal(f"HEAD is not {REMOTE_REF} ({main[:12]}): deploy and verify run only on the "
                      "reviewed, merged code; fetch the remote and check it out")
    worker_dir = root / "worker"
    path = root / WORKER_FILE
    if worker_dir.is_symlink() or path.is_symlink():
        raise Refusal(f"{WORKER_FILE} or its directory is a symlink; the pin names a regular file")
    if not path.is_file():
        raise Refusal(f"{WORKER_FILE} is missing")
    data = path.read_bytes()
    pinned = sc.INTAKE_WORKER_SHA256.get(WORKER_FILE)
    digest = hashlib.sha256(data).hexdigest()
    if digest != pinned:
        raise Refusal(f"{WORKER_FILE} has SHA-256 {digest}, not its pin in tools/sitecheck.py "
                      "(INTAKE_WORKER_SHA256)")
    return data, main


def prompt(label, form, what):
    try:
        value = input(f"{label}: ").strip()
    except EOFError:
        raise Refusal(f"no {what} given") from None
    if not form(value):
        raise Refusal(f"that is not a {what}")
    return value


def read_token():
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if not token:
        try:
            token = getpass.getpass("Cloudflare API token (not shown): ")
        except EOFError:
            token = ""
    token = token.strip()
    OUT.add_secret(token)
    if not TOKEN_FORM.fullmatch(token):
        raise Refusal("no usable API token (CLOUDFLARE_API_TOKEN or the prompt)")
    return token


# ---------------------------------------------------------------------------
# The API

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a redirect is an error answer, never followed with the token


class Api:
    def __init__(self, base, token):
        self.base = base
        self.token = token
        handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
        if base.startswith("https://"):
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        self.opener = urllib.request.build_opener(*handlers)

    def call(self, method, path, body=None, ctype=None, raw=False, ok_404=False):
        req = urllib.request.Request(self.base + path, data=body, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with self.opener.open(req, timeout=120) as resp:
                status, headers, data = resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as exc:
            status, headers, data = exc.code, exc.headers, exc.read()
        label = f"{method} {urllib.parse.urlsplit(path).path}"
        if raw and 200 <= status < 300:
            return headers, data
        try:
            payload = json.loads(data)
        except ValueError:
            raise Failure(f"{label}: HTTP {status}, not a JSON answer") from None
        if ok_404 and status == 404 and any(e.get("code") == 10007 for e in payload.get("errors") or []):
            return None
        if not (200 <= status < 300) or payload.get("success") is not True:
            errors = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in payload.get("errors") or [])
            raise Failure(f"{label}: HTTP {status}, {errors or 'no error detail'}")
        return payload.get("result")


def script_path(sc, account, suffix=""):
    return f"/accounts/{account}/workers/scripts/{sc.INTAKE_SCRIPT_NAME}{suffix}"


def expected_bindings(sc, destination):
    return [
        {"type": "send_email", "name": "EMAIL", "destination_address": destination},
        {"type": "durable_object_namespace", "name": "LIMITER", "class_name": "IntakeLimiter"},
        {"type": "ratelimit", "name": "RATE_LIMITER", "namespace_id": str(sc.INTAKE_RATELIMIT_NAMESPACE_ID),
         "simple": {"limit": sc.INTAKE_BURST_LIMIT, "period": sc.INTAKE_BURST_PERIOD_S}},
        {"type": "secret_text", "name": "LIMITER_KEY"},
    ]


def build_metadata(sc, pins, destination, first, limiter_key):
    bindings = expected_bindings(sc, destination)
    bindings[-1] = ({"type": "secret_text", "name": "LIMITER_KEY", "text": limiter_key} if limiter_key
                    else {"type": "inherit", "name": "LIMITER_KEY"})
    meta = {"main_module": MODULE_NAME, "compatibility_date": pins["WORKERD_COMPAT_DATE"],
            "bindings": bindings, "tags": [sc.INTAKE_SCRIPT_TAG], "logpush": False, "tail_consumers": [],
            "observability": {"enabled": True, "logs": {"enabled": True, "invocation_logs": False}}}
    if first:
        meta["migrations"] = {"new_tag": "v1", "new_sqlite_classes": ["IntakeLimiter"]}
    return meta


def multipart(parts):
    """parts: (name, file name or None, content type, bytes)."""
    boundary = "intake-" + secrets.token_hex(16)
    out = []
    for name, filename, ctype, data in parts:
        disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        out.append(f"--{boundary}\r\nContent-Disposition: {disposition}\r\nContent-Type: {ctype}\r\n\r\n"
                   .encode())
        out.append(data)
        out.append(b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# verify

def deployed_module(headers, data):
    ctype = headers.get("Content-Type", "") if headers else ""
    if ctype.lower().startswith("multipart/"):
        msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            f"Content-Type: {ctype}\r\n\r\n".encode() + data)
        for part in msg.iter_parts():
            if part.get_param("name", header="content-disposition") == MODULE_NAME:
                return part.get_payload(decode=True)
        return None
    return data


def binding_problems(sc, actual, destination):
    problems = []
    want = {b["name"]: b for b in expected_bindings(sc, destination)}
    have = {}
    for b in actual or []:
        if not isinstance(b, dict) or b.get("name") in have:
            problems.append(f"binding listed twice or malformed: {b!r}")
            continue
        have[b.get("name")] = b
    if sorted(have) != sorted(want):
        problems.append(f"bindings are {sorted(have)}, expected exactly {sorted(want)}")
    for name, w in want.items():
        b = have.get(name)
        if b is None:
            continue
        for key, value in w.items():
            if key == "simple":
                simple = b.get("simple") or {}
                if (simple.get("limit"), simple.get("period")) != (value["limit"], value["period"]):
                    problems.append(f"{name}: simple is {simple!r}, expected {value!r}")
            elif str(b.get(key)) != str(value):
                problems.append(f"{name}: {key} is {b.get(key)!r}, expected {value!r}")
        if w["type"] == "send_email":
            extra = sorted(set(b) - {"name", "type", "destination_address"})
            if extra:
                problems.append(f"{name}: unexpected routing keys {extra}")
        if w["type"] == "durable_object_namespace" and b.get("script_name") not in (None, sc.INTAKE_SCRIPT_NAME):
            problems.append(f"{name}: bound to the class of another script ({b.get('script_name')!r})")
    return problems


def settings_problems(sc, pins, settings, destination):
    problems = binding_problems(sc, settings.get("bindings"), destination)
    if sc.INTAKE_SCRIPT_TAG not in (settings.get("tags") or []):
        problems.append(f"the tag {sc.INTAKE_SCRIPT_TAG} is missing")
    if settings.get("tail_consumers"):
        problems.append(f"tail consumers are set: {settings.get('tail_consumers')!r}")
    if settings.get("logpush") not in (None, False):
        problems.append("Logpush is on")
    obs = settings.get("observability") or {}
    logs = obs.get("logs") or {}
    if logs.get("invocation_logs") is not False:
        problems.append("invocation logs are not off")
    for area in ("logs", "traces"):
        dests = (obs.get(area) or {}).get("destinations") or []
        if any(d != "cloudflare" for d in dests):
            problems.append(f"observability {area} export to {dests!r}")
    if settings.get("compatibility_date") != pins["WORKERD_COMPAT_DATE"]:
        problems.append(f"compatibility_date is {settings.get('compatibility_date')!r}, "
                        f"expected {pins['WORKERD_COMPAT_DATE']}")
    return problems


def verify_deployed(api, sc, pins, account, destination):
    problems = []
    headers, data = api.call("GET", script_path(sc, account, "/content/v2"), raw=True)
    module = deployed_module(headers, data)
    pinned = sc.INTAKE_WORKER_SHA256[WORKER_FILE]
    digest = hashlib.sha256(module).hexdigest() if module is not None else None
    if digest != pinned:
        problems.append(f"deployed script SHA-256 is {digest}, the pin is {pinned}")
    settings = api.call("GET", script_path(sc, account, "/settings"), ok_404=True)
    if settings is None:
        problems.append(f"no script {sc.INTAKE_SCRIPT_NAME} is deployed")
    else:
        problems += settings_problems(sc, pins, settings, destination)
    query = urllib.parse.urlencode({"hostname": sc.INTAKE_HOSTNAME})
    domains = api.call("GET", f"/accounts/{account}/workers/domains?{query}") or []
    mapped = [d for d in domains if isinstance(d, dict) and d.get("hostname") == sc.INTAKE_HOSTNAME]
    if [d.get("service") for d in mapped] != [sc.INTAKE_SCRIPT_NAME]:
        problems.append(f"{sc.INTAKE_HOSTNAME} maps to {[d.get('service') for d in mapped]!r}, "
                        f"expected exactly [{sc.INTAKE_SCRIPT_NAME!r}]")
    for problem in problems:
        OUT.say(f"verify: MISMATCH: {problem}")
    if not problems:
        OUT.say(f"verify: ok: script bytes equal the pin, bindings, tags, tail consumers, Logpush, "
                f"observability and the custom domain {sc.INTAKE_HOSTNAME} are as expected")
        OUT.say("verify: check in the dashboard that the Email Routing rules and destination "
                "addresses are the expected ones (the deploy token cannot read them)")
    return not problems


# ---------------------------------------------------------------------------
# Commands

def session(sc, need_zone):
    refuse_ci()
    base = api_base()
    pins = read_pins(ROOT / "tools" / "pins.env")
    check_tree(ROOT, sc)
    token = read_token()
    account = prompt("Cloudflare account ID", HEX32.fullmatch, "32-hex account ID")
    zone = prompt("Zone ID of interviewscam.com", HEX32.fullmatch, "32-hex zone ID") if need_zone else None
    destination = prompt("Destination address (verified in Email Routing)",
                         lambda v: len(v) <= 254 and EMAIL_RE.fullmatch(v), "mail address")
    return Api(base, token), pins, account, zone, destination


def cmd_deploy(sc):
    api, pins, account, zone, destination = session(sc, need_zone=True)
    source = (ROOT / WORKER_FILE).read_bytes()
    settings = api.call("GET", script_path(sc, account, "/settings"), ok_404=True)
    if settings is not None and sc.INTAKE_SCRIPT_TAG not in (settings.get("tags") or []):
        raise Refusal(f"a script named {sc.INTAKE_SCRIPT_NAME} exists without the tag "
                      f"{sc.INTAKE_SCRIPT_TAG}; it is not this site's Worker, so nothing is uploaded")
    first = settings is None
    has_key = settings is not None and any(isinstance(b, dict) and b.get("name") == "LIMITER_KEY"
                                           for b in settings.get("bindings") or [])
    limiter_key = None if has_key else secrets.token_hex(sc.INTAKE_LIMITER_KEY_BYTES)
    OUT.add_secret(limiter_key)
    metadata = build_metadata(sc, pins, destination, first, limiter_key)
    body, ctype = multipart([("metadata", None, "application/json", json.dumps(metadata).encode()),
                             (MODULE_NAME, MODULE_NAME, "application/javascript+module", source)])
    OUT.say(f"deploy: uploading {WORKER_FILE} as {sc.INTAKE_SCRIPT_NAME}"
            f"{' (first deploy: Durable Object migration, new LIMITER_KEY)' if first else ''}")
    api.call("PUT", script_path(sc, account), body, ctype)
    domain = {"environment": "production", "hostname": sc.INTAKE_HOSTNAME,
              "service": sc.INTAKE_SCRIPT_NAME, "zone_id": zone}
    api.call("PUT", f"/accounts/{account}/workers/domains", json.dumps(domain).encode(), "application/json")
    OUT.say(f"deploy: {sc.INTAKE_HOSTNAME} mapped to {sc.INTAKE_SCRIPT_NAME}")
    ok = verify_deployed(api, sc, pins, account, destination)
    OUT.say("deploy: revoke the deploy token in the dashboard now (ADR-0006 part 10)")
    return 0 if ok else 1


def cmd_verify(sc):
    api, pins, account, _zone, destination = session(sc, need_zone=False)
    return 0 if verify_deployed(api, sc, pins, account, destination) else 1


# ---------------------------------------------------------------------------
# The live suite (ADR-0006 Consequences, PR 4; under workerd in the tests)

LIVE_PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f"
            b"\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00"
            b"\x00IEND\xaeB`\x82")


def live_target(target, sc):
    if target == sc.INTAKE_ORIGIN or LOOPBACK_TARGET.fullmatch(target):
        return target
    raise Refusal(f"--target must be {sc.INTAKE_ORIGIN} (or the tests' workerd on http://127.0.0.1:<port>)")


def live_report(sc, extra=(), **over):
    fields = {"channel": "report", "name": "interviewscam live test", "contact_start": "",
              "details": "Live test of the intake Worker (ADR-0006 part 12 step 9). No scam is reported.",
              "headers": "", "email": "live-test@example.com", "website": ""}
    fields.update(over)
    parts = [(k, None, "text/plain; charset=utf-8", v.encode()) for k, v in fields.items()]
    parts += list(extra)
    return multipart(parts)


def live_post(target, body, ctype, extra_headers):
    split = urllib.parse.urlsplit(target)
    if split.scheme == "https":
        conn = http.client.HTTPSConnection(split.hostname, split.port or 443, timeout=120,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(split.hostname, split.port, timeout=120)
    headers = {"Content-Type": ctype, "Origin": "https://interviewscam.com"}
    headers.update(extra_headers or {})
    try:
        conn.request("POST", "/submit", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, resp.getheaders(), data
    finally:
        conn.close()


def outcome(sc, location):
    if location == sc.INTAKE_SENT_URL:
        return "sent"
    if location.startswith(sc.INTAKE_NOT_SENT_URL + "#"):
        frag = location[len(sc.INTAKE_NOT_SENT_URL) + 1:]
        if frag in sc.INTAKE_RESULT_IDS:
            return frag
    return None


def live_suite(target, spacing=LIVE_SPACING_S, extra_headers=None, sc=None):
    """Returns [(case, ok, detail)]. The rate-limit case predicts the first
    limited attempt from the suite's earlier attempts in both windows, the
    binding's 60 s and the hour, so it assumes a key with no other attempt
    in the last hour."""
    sc = sc or load_sitecheck(ROOT)
    results, header_problems, times = [], [], []
    last = [None]

    def attempt(body, ctype):
        if last[0] is not None and spacing:
            time.sleep(max(0.0, spacing - (time.monotonic() - last[0])))
        last[0] = time.monotonic()
        times.append(last[0])
        status, headers, data = live_post(target, body, ctype, extra_headers)
        hmap = {}
        cookies = 0
        for k, v in headers:
            hmap[k.lower()] = v
            cookies += k.lower() == "set-cookie"
        got = outcome(sc, hmap.get("location", ""))
        if status != 303 or got is None or cookies or data or hmap.get("cache-control") != "no-store" \
                or hmap.get("referrer-policy") != "no-referrer":
            header_problems.append(f"status {status}, Location {hmap.get('location')!r}, "
                                   f"Set-Cookie {cookies}, body {len(data)} bytes, "
                                   f"Cache-Control {hmap.get('cache-control')!r}")
        return got

    def case(name, expected, body_ctype):
        got = attempt(*body_ctype)
        results.append((name, got == expected, f"expected {expected}, got {got}"))

    case("live_valid_report", "sent",
         live_report(sc, [("files", "screenshot.png", "image/png", LIVE_PNG)]))
    size, rest = divmod(sc.INTAKE_MAX_UPLOAD_BYTES + 1, sc.INTAKE_MAX_FILES)
    big = [("files", f"{i}.png", "image/png", LIVE_PNG + bytes(size + (i < rest) - len(LIVE_PNG)))
           for i in range(sc.INTAKE_MAX_FILES)]
    case("live_oversize", "too-large", live_report(sc, big))
    case("live_not_image", "not-an-image",
         live_report(sc, [("files", "screenshot.png", "image/png", b"MZ" + bytes(62))]))
    case("live_honeypot", "not-accepted", live_report(sc, website="x"))
    details = []
    ok = True
    for i in range(LIVE_RATE_ATTEMPTS):
        now = time.monotonic()
        hour = sum(1 for t in times if t > now - sc.INTAKE_CLIENT_WINDOW_MS / 1000)
        minute = sum(1 for t in times if t > now - sc.INTAKE_BURST_PERIOD_S)
        limited = hour >= sc.INTAKE_CLIENT_LIMIT or minute >= sc.INTAKE_BURST_LIMIT
        expected = "too-many-attempts" if limited else "not-accepted"
        got = attempt(*live_report(sc, website="x"))
        details.append(f"{len(times)}:{got}")
        ok = ok and got == expected
    results.append(("live_rate_limit", ok, "attempt:outcome " + " ".join(details)))
    results.append(("live_headers", not header_problems,
                    "; ".join(header_problems) or f"{len(times)} responses: 303, closed Location set, "
                    "no Set-Cookie, no body, no-store, no-referrer"))
    return results


def cmd_live_test(sc, target):
    target = live_target(target, sc)
    results = live_suite(target, sc=sc)
    for name, ok, detail in results:
        OUT.say(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
    OUT.say("live-test: confirm in the mailbox that exactly one mail 'Report: interviewscam live test' "
            "arrived, with dkim=pass in Authentication-Results")
    return 0 if all(ok for _, ok, _ in results) else 1


def build_parser():
    parser = argparse.ArgumentParser(prog="intake", description=__doc__.split("\n")[0], allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("deploy", allow_abbrev=False)
    sub.add_parser("verify", allow_abbrev=False)
    p = sub.add_parser("live-test", allow_abbrev=False)
    p.add_argument("--target", required=True)
    return parser


def main(argv):
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        sc = load_sitecheck(ROOT)
        if args.command == "deploy":
            return cmd_deploy(sc)
        if args.command == "verify":
            return cmd_verify(sc)
        return cmd_live_test(sc, args.target)
    except Refusal as exc:
        OUT.say(f"intake: REFUSED: {exc}", sys.stderr)
        return 2
    except Failure as exc:
        OUT.say(f"intake: FAILED: {exc}", sys.stderr)
        return 1
    except KeyboardInterrupt:
        OUT.say("intake: interrupted", sys.stderr)
        return 2
    except Exception as exc:  # never a traceback: it could carry a request
        OUT.say(f"intake: ERROR: {type(exc).__name__}: {exc}", sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
