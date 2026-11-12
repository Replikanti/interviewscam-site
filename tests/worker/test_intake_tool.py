"""tools/intake.py, the operator's deploy tool (ADR-0006 part 10).

Never against Cloudflare: every case runs the tool as the operator would
(python3 -I tools/intake.py ...) in a throwaway git repository whose
remote `site` is a bare repository on disk, against a stub of the
Cloudflare API on loopback (INTAKE_API_BASE, which the tool accepts only
as http://127.0.0.1:<port>/client/v4). The token is a sentinel that must
never appear in the tool's output.
"""

import copy
import email.parser
import email.policy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
SENTINEL = "SENTINELtoken-0123456789abcdefSENTINEL"
ACCOUNT = "0123456789abcdef0123456789abcdef"
ZONE = "fedcba9876543210fedcba9876543210"
DEST = "operator@example.com"
SCRIPT = "interviewscam-intake"
COPIED = ("tools/intake.py", "tools/sitecheck.py", "tools/pins.env", "worker/intake.js")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Stub:
    """The parts of the Cloudflare API v4 the tool calls, in memory."""

    def __init__(self):
        self.requests = []
        self.state = "absent"      # absent | deployed | foreign
        self.error_mode = False    # every call answers success:false, echoing the token
        self.metadata = None
        self.content = b""
        self.domains = []
        self.settings_override = {}
        self.uploaded = []         # each upload's metadata, as sent

    def settings(self):
        bindings = []
        for b in self.metadata["bindings"]:
            b = dict(b)
            if b["type"] in ("secret_text", "inherit"):
                b = {"name": b["name"], "type": "secret_text"}
            bindings.append(b)
        result = {"bindings": bindings, "tags": list(self.metadata.get("tags", [])),
                  "logpush": self.metadata.get("logpush", False),
                  "tail_consumers": self.metadata.get("tail_consumers", []),
                  "observability": self.metadata.get("observability"),
                  "compatibility_date": self.metadata.get("compatibility_date"),
                  "compatibility_flags": [], "usage_model": "standard"}
        result.update(copy.deepcopy(self.settings_override))
        return result

    def handle(self, method, path, query, headers, body):
        self.requests.append({"method": method, "path": path, "query": query, "headers": headers,
                              "body": body})
        token = headers.get("authorization", "")
        if self.error_mode:
            return 400, {"success": False, "errors": [{"code": 9109, "message": f"Invalid token {token}"}],
                         "messages": [token], "result": None}
        base = f"/client/v4/accounts/{ACCOUNT}/workers"
        if method == "GET" and path == f"{base}/scripts/{SCRIPT}/settings":
            if self.state == "absent":
                return 404, {"success": False, "errors": [{"code": 10007, "message":
                                                           "workers.api.error.script_not_found"}], "result": None}
            if self.state == "foreign":
                return 200, {"success": True, "errors": [], "result": {"bindings": [], "tags": ["other-team"]}}
            return 200, {"success": True, "errors": [], "result": self.settings()}
        if method == "PUT" and path == f"{base}/scripts/{SCRIPT}":
            ctype = headers.get("content-type", "")
            msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                f"Content-Type: {ctype}\r\n\r\n".encode() + body)
            parts = {p.get_param("name", header="content-disposition"): p for p in msg.iter_parts()}
            meta = json.loads(parts["metadata"].get_payload(decode=True))
            module = parts[meta["main_module"]]
            self.uploaded.append(copy.deepcopy(meta))
            if self.metadata is not None:
                for b in meta["bindings"]:
                    if b["type"] == "inherit":
                        old = next(o for o in self.metadata["bindings"] if o["name"] == b["name"])
                        b.update(old)
            self.metadata = meta
            self.module_type = module.get_content_type()
            self.content = module.get_payload(decode=True)
            self.state = "deployed"
            return 200, {"success": True, "errors": [], "result": {"id": SCRIPT}}
        if method == "GET" and path == f"{base}/scripts/{SCRIPT}/content/v2":
            return 200, self.content
        if method == "PUT" and path == f"{base}/domains":
            d = json.loads(body)
            self.domains = [x for x in self.domains if x["hostname"] != d["hostname"]] + [
                {"hostname": d["hostname"], "service": d["service"], "zone_id": d["zone_id"],
                 "environment": d.get("environment")}]
            return 200, {"success": True, "errors": [], "result": self.domains[-1]}
        if method == "GET" and path == f"{base}/domains":
            want = query.get("hostname", [None])[0]
            return 200, {"success": True, "errors": [],
                         "result": [d for d in self.domains if want is None or d["hostname"] == want]}
        return 404, {"success": False, "errors": [{"code": 7003, "message": "no route"}], "result": None}


class StubServer:
    def __init__(self):
        self.stub = Stub()
        stub = self.stub

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _any(self):
                split = urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                status, payload = stub.handle(self.command, split.path, parse_qs(split.query),
                                              {k.lower(): v for k, v in self.headers.items()}, body)
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream" if isinstance(payload, bytes)
                                 else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_PUT = do_POST = do_DELETE = do_PATCH = _any

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}/client/v4"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=intake-test",
                           "-c", "user.email=intake-test@example.com", "-c", "commit.gpgsign=false", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


class ToolCase(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="intake-tool-")
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        for rel in COPIED:
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, self.repo / rel)
        bare = base / "site.git"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "init")
        git(self.repo, "remote", "add", "site", str(bare))
        git(self.repo, "push", "-q", "site", "main")
        git(self.repo, "fetch", "-q", "site")
        self.server = StubServer()
        self.stub = self.server.stub
        self.sc = load("sitecheck_copy", self.repo / "tools" / "sitecheck.py")

    def tearDown(self):
        self.server.close()
        self.tmp.cleanup()

    def run_tool(self, *args, stdin=None, env=None, base=None):
        e = {k: v for k, v in os.environ.items() if k not in ("CI", "GITHUB_ACTIONS")}
        e.update({"CLOUDFLARE_API_TOKEN": SENTINEL, "INTAKE_API_BASE": base or self.server.base})
        e.update(env or {})
        if stdin is None:
            stdin = f"{ACCOUNT}\n{ZONE}\n{DEST}\n" if args[:1] == ("deploy",) else f"{ACCOUNT}\n{DEST}\n"
        proc = subprocess.run([sys.executable, "-I", "-B", str(self.repo / "tools" / "intake.py"), *args],
                              input=stdin, capture_output=True, text=True, env=e, timeout=120)
        output = proc.stdout + proc.stderr
        self.assertNotIn(SENTINEL, output, "the token was printed")
        return proc.returncode, output

    def commit_and_push(self, message):
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", message)
        git(self.repo, "push", "-q", "site", "main")
        git(self.repo, "fetch", "-q", "site")

    def expected_metadata(self, first):
        pins = dict(line.split("=", 1) for line in (self.repo / "tools/pins.env").read_text().splitlines()
                    if line and not line.startswith("#"))
        bindings = [
            {"type": "send_email", "name": "EMAIL", "destination_address": DEST},
            {"type": "durable_object_namespace", "name": "LIMITER", "class_name": "IntakeLimiter"},
            {"type": "ratelimit", "name": "RATE_LIMITER", "namespace_id": str(self.sc.INTAKE_RATELIMIT_NAMESPACE_ID),
             "simple": {"limit": self.sc.INTAKE_BURST_LIMIT, "period": self.sc.INTAKE_BURST_PERIOD_S}},
            {"type": "secret_text", "name": "LIMITER_KEY", "text": "<64 hex>"} if first
            else {"type": "inherit", "name": "LIMITER_KEY"},
        ]
        meta = {"main_module": "intake.js", "compatibility_date": pins["WORKERD_COMPAT_DATE"],
                "bindings": bindings, "tags": [SCRIPT], "logpush": False, "tail_consumers": [],
                "observability": {"enabled": True, "logs": {"enabled": True, "invocation_logs": False}}}
        if first:
            meta["migrations"] = {"new_tag": "v1", "new_sqlite_classes": ["IntakeLimiter"]}
        return meta

    def uploads(self):
        return [r for r in self.stub.requests if r["method"] == "PUT" and "/scripts/" in r["path"]]


class Tool(ToolCase):
    def test_refuses_ci(self):
        for cmd in ("deploy", "verify"):
            for var in ("CI", "GITHUB_ACTIONS"):
                with self.subTest(cmd=cmd, var=var):
                    rc, out = self.run_tool(cmd, env={var: "true"})
                    self.assertEqual(rc, 2, out)
                    self.assertIn("refuses to run under", out)
        self.assertEqual(self.stub.requests, [])

    def test_refuses_tree_state(self):
        (self.repo / "tools" / "pins.env").write_text((self.repo / "tools/pins.env").read_text() + "\n")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertIn("uncommitted", out)
        git(self.repo, "checkout", "-q", "--", "tools/pins.env")
        (self.repo / "stray.txt").write_text("x")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertIn("uncommitted", out)
        (self.repo / "stray.txt").unlink()
        (self.repo / "README.md").write_text("local\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "unpushed")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertIn("site/main", out)
        git(self.repo, "push", "-q", "site", "main")
        git(self.repo, "fetch", "-q", "site")
        git(self.repo, "checkout", "-q", "HEAD~1")
        rc, out = self.run_tool("verify")
        self.assertEqual(rc, 2, out)
        self.assertIn("site/main", out)
        git(self.repo, "checkout", "-q", "main")
        git(self.repo, "remote", "remove", "site")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.stub.requests, [])

    def test_refuses_symlink_and_drift(self):
        worker = self.repo / "worker" / "intake.js"
        data = worker.read_bytes()
        worker.write_bytes(data[:-1] + (b"\n" if data[-1:] != b"\n" else b" "))
        self.commit_and_push("drift")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertIn("INTAKE_WORKER_SHA256", out)
        (self.repo / "elsewhere.js").write_bytes(data)
        worker.unlink()
        worker.symlink_to("../elsewhere.js")
        self.commit_and_push("symlink")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertIn("symlink", out)
        worker.unlink()
        self.commit_and_push("missing")
        rc, out = self.run_tool("verify")
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.stub.requests, [])

    def test_metadata_exact(self):
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 0, out)
        (upload,) = self.uploads()
        meta = copy.deepcopy(self.stub.metadata)
        secret = next(b for b in meta["bindings"] if b["name"] == "LIMITER_KEY")
        self.assertRegex(secret["text"], r"^[0-9a-f]{64}$")
        secret["text"] = "<64 hex>"
        self.assertEqual(meta, self.expected_metadata(first=True))
        self.assertEqual(self.stub.content, (self.repo / "worker/intake.js").read_bytes())
        self.assertEqual(self.stub.module_type, "application/javascript+module")
        self.assertEqual(self.stub.domains, [{"hostname": "intake.interviewscam.com", "service": SCRIPT,
                                              "zone_id": ZONE, "environment": "production"}])
        self.assertIn("revoke", out.lower())
        first_secret = next(b for b in self.stub.metadata["bindings"] if b["name"] == "LIMITER_KEY")["text"]
        self.assertNotIn(first_secret, out, "the limiter key was printed")
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.stub.uploaded[1], self.expected_metadata(first=False))

    def test_token_never_printed(self):
        self.stub.error_mode = True
        for cmd in ("deploy", "verify"):
            rc, out = self.run_tool(cmd)
            self.assertEqual(rc, 1, out)
            self.assertIn("[token]", out)
        self.stub.error_mode = False
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 0, out)
        rc, out = self.run_tool("verify")
        self.assertEqual(rc, 0, out)
        for req in self.stub.requests:
            self.assertEqual(req["headers"].get("authorization"), f"Bearer {SENTINEL}")
            self.assertNotIn(SENTINEL.encode(), req["body"])
            self.assertNotIn(SENTINEL, req["path"])

    def test_api_error_exit(self):
        self.stub.error_mode = True
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 1, out)
        self.assertIn("9109", out)

    def test_verify_detects_drift(self):
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 0, out)
        rc, out = self.run_tool("verify")
        self.assertEqual(rc, 0, out)
        good = (copy.deepcopy(self.stub.metadata), self.stub.content, copy.deepcopy(self.stub.domains))
        drifts = {
            "content": lambda: setattr(self.stub, "content", self.stub.content + b"\n"),
            "destination": lambda: self.stub.settings_override.update(
                bindings=[dict(b, destination_address="other@example.com") if b["type"] == "send_email" else b
                          for b in self.stub.settings()["bindings"]]),
            "extra binding": lambda: self.stub.settings_override.update(
                bindings=self.stub.settings()["bindings"] + [{"type": "plain_text", "name": "X", "text": "y"}]),
            "missing binding": lambda: self.stub.settings_override.update(
                bindings=self.stub.settings()["bindings"][1:]),
            "tail consumer": lambda: self.stub.settings_override.update(
                tail_consumers=[{"service": "other-worker"}]),
            "logpush": lambda: self.stub.settings_override.update(logpush=True),
            "invocation logs": lambda: self.stub.settings_override.update(
                observability={"enabled": True, "logs": {"enabled": True, "invocation_logs": True}}),
            "log destination": lambda: self.stub.settings_override.update(
                observability={"enabled": True, "logs": {"enabled": True, "invocation_logs": False,
                                                         "destinations": ["elsewhere"]}}),
            "tags": lambda: self.stub.settings_override.update(tags=[]),
            "compat date": lambda: self.stub.settings_override.update(compatibility_date="2020-01-01"),
            "domain service": lambda: setattr(self.stub, "domains", [dict(self.stub.domains[0], service="other")]),
            "domain twice": lambda: setattr(self.stub, "domains", self.stub.domains * 2),
            "domain missing": lambda: setattr(self.stub, "domains", []),
        }
        for name, drift in drifts.items():
            with self.subTest(drift=name):
                self.stub.metadata, self.stub.content, self.stub.domains = copy.deepcopy(good[0]), good[1], \
                    copy.deepcopy(good[2])
                self.stub.settings_override = {}
                drift()
                rc, out = self.run_tool("verify")
                self.assertEqual(rc, 1, out)
                self.assertIn("MISMATCH", out)

    def test_refuses_foreign_script(self):
        self.stub.state = "foreign"
        rc, out = self.run_tool("deploy")
        self.assertEqual(rc, 2, out)
        self.assertIn("tag", out)
        self.assertEqual(self.uploads(), [])
        self.assertEqual([r for r in self.stub.requests if r["method"] != "GET"], [])

    def test_single_script_name(self):
        self.run_tool("deploy")
        self.run_tool("deploy")
        self.run_tool("verify")
        self.assertGreater(len(self.stub.requests), 6)
        for req in self.stub.requests:
            names = re.findall(r"/workers/scripts/([^/]+)", req["path"])
            self.assertIn(names, ([SCRIPT], []), req["path"])
            if req["path"].endswith("/workers/domains") and req["method"] == "PUT":
                self.assertEqual(json.loads(req["body"])["service"], SCRIPT)

    def test_api_base_loopback_only(self):
        for base in ("https://evil.example/client/v4", "http://127.0.0.1.evil.example:1/client/v4",
                     "http://localhost:1/client/v4", "http://127.0.0.1:1/other"):
            with self.subTest(base=base):
                rc, out = self.run_tool("deploy", base=base)
                self.assertEqual(rc, 2, out)
                self.assertIn("INTAKE_API_BASE", out)

    def test_prompts_validated(self):
        for stdin in (f"not-an-id\n{ZONE}\n{DEST}\n", f"{ACCOUNT}\nzone\n{DEST}\n", f"{ACCOUNT}\n{ZONE}\nnope\n",
                      ""):
            with self.subTest(stdin=stdin):
                rc, out = self.run_tool("deploy", stdin=stdin)
                self.assertEqual(rc, 2, out)
        self.assertEqual(self.stub.requests, [])

    def test_live_target_closed(self):
        for target in ("https://evil.example", "http://intake.interviewscam.com",
                       "https://intake.interviewscam.com/submit", "http://127.0.0.2:1"):
            with self.subTest(target=target):
                rc, out = self.run_tool("live-test", "--target", target, stdin="")
                self.assertEqual(rc, 2, out)


if __name__ == "__main__":
    unittest.main()
