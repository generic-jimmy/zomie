#!/usr/bin/env python3
"""
SessionScope Lab — PHP session misconfiguration scope checker.

Detection-only. This module sends INERT probes and reports whether the
target's PHP session configuration exposes the conditions commonly discussed
in PHP session-injection research (upload_progress filename storage,
handler mismatch, strict-mode disabled).

Design guarantees:
  * No code-execution payloads. Filenames contain inert markers or an
    empty stdClass object (stdClass has NO destructor -> nothing executes).
  * Every request is logged to scan.log so the operator can audit traffic.
  * Scope guard: private/loopback targets by default; public targets need
    explicit operator confirmation; cloud metadata endpoints are blocked.

For use against lab systems you own or are authorized to test.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import time
from urllib.parse import urlsplit

import requests

USER_AGENT = "SessionScopeLab/1.0 (authorized-lab scanner)"
BODY_CAP = 200_000          # cap stored response body size (bytes)
DEFAULT_TIMEOUT = 10        # seconds per request

# statuses: vulnerable | hardened | inconclusive | info | error
STATUS_ORDER = {"error": 0, "vulnerable": 1, "inconclusive": 2, "info": 3, "hardened": 4}

BLOCKED_IPS = {
    "169.254.169.254",   # cloud instance metadata
    "fd00:ec2::254",
}


# --------------------------------------------------------------------------
# Scope guard
# --------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )


def classify_target(url: str) -> dict:
    """Decide whether a target is lab-safe by default.

    Returns dict with:
      ok            -> bool, scan may proceed
      needs_confirm -> bool, public target: requires operator confirmation
      reason        -> human-readable explanation
      ips           -> resolved IPs
    """
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return {"ok": False, "needs_confirm": False, "ips": [],
                "reason": "Could not parse a hostname from the URL."}

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return {"ok": False, "needs_confirm": False, "ips": [],
                "reason": f"DNS resolution failed for '{host}': {exc}"}

    ips = sorted({i[4][0] for i in infos})

    for ip in ips:
        if ip in BLOCKED_IPS:
            return {"ok": False, "needs_confirm": False, "ips": ips,
                    "reason": f"Blocked: {ip} is a cloud metadata endpoint. Never in scope."}

    if all(_is_private(ip) for ip in ips):
        return {"ok": True, "needs_confirm": False, "ips": ips,
                "reason": "Private/loopback target (lab-safe by default)."}

    return {"ok": True, "needs_confirm": True, "ips": ips,
            "reason": "Public IP target — requires the authorization confirmation."}


# --------------------------------------------------------------------------
# HTTP plumbing with full request logging
# --------------------------------------------------------------------------

class ScannedSession:
    """requests.Session wrapper that records every exchange for the report."""

    def __init__(self) -> None:
        self.sess = requests.Session()
        self.sess.headers.update({"User-Agent": USER_AGENT})
        self.log: list[dict] = []

    def request(self, method: str, url: str, **kw) -> requests.Response:
        kw.setdefault("timeout", DEFAULT_TIMEOUT)
        kw.setdefault("allow_redirects", False)
        started = time.time()
        try:
            resp = self.sess.request(method, url, **kw)
        except requests.RequestException as exc:
            self.log.append({
                "method": method, "url": url, "status": None,
                "ms": int((time.time() - started) * 1000),
                "note": f"transport error: {exc.__class__.__name__}: {exc}",
            })
            raise
        self.log.append({
            "method": method, "url": url, "status": resp.status_code,
            "ms": int((time.time() - started) * 1000),
            "note": f"{len(resp.content)} bytes",
        })
        return resp

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)


def _body(resp: requests.Response) -> str:
    return resp.text[:BODY_CAP]


def _mk_result(cid: str, title: str, status: str, summary: str,
               evidence: list[str], remediation: list[str] | None = None) -> dict:
    return {
        "id": cid, "title": title, "status": status, "summary": summary,
        "evidence": evidence,
        "remediation": remediation or [],
    }


# --------------------------------------------------------------------------
# Check 1 — fingerprint
# --------------------------------------------------------------------------

def check_fingerprint(sc: ScannedSession, base: str) -> dict:
    try:
        resp = sc.get(base)
    except requests.RequestException:
        return _mk_result(
            "fingerprint", "Target reachability & PHP fingerprint", "error",
            "Target did not answer a plain GET request.",
            ["No HTTP response — verify the URL, port, and that the lab site is running."],
        )

    evidence = [f"GET {base} -> HTTP {resp.status_code}"]
    powered = resp.headers.get("X-Powered-By", "")
    server = resp.headers.get("Server", "")
    if powered:
        evidence.append(f"X-Powered-By: {powered}")
    if server:
        evidence.append(f"Server: {server}")

    if re.search(r"PHP[/ ][\d.]+", powered, re.I):
        return _mk_result(
            "fingerprint", "Target reachability & PHP fingerprint", "info",
            f"PHP confirmed ({powered}). Continue with configuration checks.",
            evidence,
        )
    if "php" in _body(resp).lower()[:2000] or "php" in server.lower():
        return _mk_result(
            "fingerprint", "Target reachability & PHP fingerprint", "info",
            "PHP not exposed in headers but PHP hints found in body/server header.",
            evidence,
        )
    return _mk_result(
        "fingerprint", "Target reachability & PHP fingerprint", "inconclusive",
        "Target reachable but does not advertise PHP. Checks will still run.",
        evidence,
    )


# --------------------------------------------------------------------------
# Check 2 — phpinfo configuration disclosure
# --------------------------------------------------------------------------

SESSION_SETTINGS_OF_INTEREST = [
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "session.serialize_handler",
    "session.use_strict_mode",
    "session.use_only_cookies",
    "session.save_path",
]

PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/test.php"]

_TDS_RE = re.compile(r"<td[^>]*>\s*(session\.[a-z_.]+)\s*</td>\s*<td[^>]*>\s*(.*?)\s*</td>",
                     re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def check_phpinfo(sc: ScannedSession, base: str) -> dict:
    found_settings: dict[str, str] = {}
    evidence: list[str] = []

    for path in PHPINFO_PATHS:
        url = base.rstrip("/") + path
        try:
            resp = sc.get(url)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        body = _body(resp)
        if "PHP Version" not in body:
            continue
        evidence.append(f"phpinfo page reachable at {url} (HTTP {resp.status_code})")

        for name, raw_val in _TDS_RE.findall(body):
            val = _TAG_RE.sub("", raw_val).strip()
            if name not in found_settings and val:
                found_settings[name] = val

        if found_settings:
            break

    if not found_settings:
        return _mk_result(
            "phpinfo", "phpinfo() configuration disclosure", "inconclusive",
            "No phpinfo page found. Remote config verdict unavailable — "
            "host-side verification commands in the other checks remain valid.",
            ["Tried: " + ", ".join(PHPINFO_PATHS)],
        )

    for name in SESSION_SETTINGS_OF_INTEREST:
        if name in found_settings:
            evidence.append(f"{name} = {found_settings[name]}")

    up_enabled = found_settings.get("session.upload_progress.enabled", "").lower() == "on"
    strict = found_settings.get("session.use_strict_mode", "").lower()
    handler = found_settings.get("session.serialize_handler", "").lower()

    problems = []
    if up_enabled:
        problems.append("session.upload_progress.enabled=On allows session data to be "
                        "populated from multipart request content")
    if strict in ("off", "0", ""):
        problems.append("session.use_strict_mode=Off allows arbitrary/attacker-chosen session IDs")
    if handler == "php":
        problems.append("serialize_handler 'php' splits values at '|', the classic "
                        "handler-mismatch precondition")

    if problems:
        return _mk_result(
            "phpinfo", "phpinfo() configuration disclosure", "vulnerable",
            "Configuration conditions present: " + " | ".join(problems),
            evidence,
            remediation=[
                "Set session.upload_progress.enabled=0 in php.ini",
                "Set session.use_strict_mode=1",
                "Pin a single session.serialize_handler globally (never mix per-directory)",
                "Remove phpinfo pages from reachable paths",
            ],
        )

    return _mk_result(
        "phpinfo", "phpinfo() configuration disclosure", "hardened",
        "phpinfo reachable but no risky session defaults observed.",
        evidence,
    )


# --------------------------------------------------------------------------
# Check 3 — upload_progress acceptance (benign marker)
# --------------------------------------------------------------------------

def check_upload_progress(sc: ScannedSession, base: str, path: str) -> dict:
    url = base.rstrip("/") + path
    marker = "scopecheck-" + secrets.token_hex(6)
    sid = "scopesid" + secrets.token_hex(10)

    # Probe A: multipart POST carrying PHP_SESSION_UPLOAD_PROGRESS + a body-SID
    try:
        resp_a = sc.post(
            url,
            data={
                "PHPSESSID": sid,  # SID via POST body (fixation precondition)
                "PHP_SESSION_UPLOAD_PROGRESS": marker,
            },
            files={"f": (f"{marker}.txt", b"lab-scope-check", "application/octet-stream")},
            cookies={"PHPSESSID": sid},
        )
    except requests.RequestException as exc:
        return _mk_result(
            "upload_progress", "session.upload_progress acceptance", "error",
            "Request failed during probe.", [f"{url} -> {exc.__class__.__name__}"],
        )

    # Probe B: control request WITHOUT the upload-progress field
    try:
        resp_b = sc.post(
            url,
            data={"PHPSESSID": sid + "c"},
            files={"f": (f"{marker}-ctrl.txt", b"control", "application/octet-stream")},
            cookies={"PHPSESSID": sid + "c"},
        )
    except requests.RequestException as exc:
        return _mk_result(
            "upload_progress", "session.upload_progress acceptance", "error",
            "Control request failed during probe.", [f"{url} -> {exc.__class__.__name__}"],
        )

    evidence = [
        f"Probe A (with PHP_SESSION_UPLOAD_PROGRESS, SID={sid}): "
        f"HTTP {resp_a.status_code}, {len(resp_a.content)} bytes",
        f"Probe B (control, no upload-progress field): HTTP {resp_b.status_code}, "
        f"{len(resp_b.content)} bytes",
    ]

    warnings = re.findall(r"(?:Warning|Notice)\b[^\n<]{0,200}", _body(resp_a))
    if warnings:
        evidence.append("Server-side messages in probe A response: "
                        + " || ".join(w.strip() for w in warnings[:3]))

    status_differs = resp_a.status_code != resp_b.status_code
    if status_differs:
        evidence.append("Status codes differ between probe and control — "
                        "the endpoint treats upload-progress requests specially.")

    if "PHP Version" in _body(resp_a) or warnings:
        return _mk_result(
            "upload_progress", "session.upload_progress acceptance", "inconclusive",
            "Endpoint processed the multipart probe; inspect the response evidence. "
            "Definitive condition verdict needs the host-side file check below.",
            evidence,
            remediation=[
                "Host-side ground truth (run on the lab host): "
                f"ls -la /tmp/sessions/ | grep {sid}",
                "If sess_<SID> exists with the marker filename stored, the "
                "upload_progress injection condition is confirmed.",
                "Disable with session.upload_progress.enabled=0",
            ],
        )

    return _mk_result(
        "upload_progress", "session.upload_progress acceptance", "inconclusive",
        "No server-side disclosure observed. Remote probing alone cannot prove or "
        "disprove session-file creation — run the host-side check below for ground truth.",
        evidence,
        remediation=[
            f"Host-side check: ls -la /tmp/sessions/ | grep {sid}",
            "sess_<SID> present => upload_progress created the session file "
            "from an attacker-chosen SID (condition present).",
            "Hardening: session.upload_progress.enabled=0, session.use_strict_mode=1",
        ],
    )


# --------------------------------------------------------------------------
# Check 4 — serialize-handler mismatch (inert stdClass probe)
# --------------------------------------------------------------------------

def check_handler_mismatch(sc: ScannedSession, base: str,
                           write_path: str, read_path: str) -> dict:
    if not write_path or not read_path:
        return _mk_result(
            "handler_mismatch", "serialize_handler mismatch", "info",
            "Skipped — provide the php_serialize write path and php read path "
            "to enable this check.",
            ["This check needs two endpoints under different .user.ini handler configs."],
        )

    write_url = base.rstrip("/") + write_path
    read_url = base.rstrip("/") + read_path
    sid = "mismatch" + secrets.token_hex(9)

    # Inert object: stdClass with NO properties and NO destructor. Nothing executes.
    inert = 'a|O:8:"stdClass":0:{}' + secrets.token_hex(4)

    try:
        resp_w = sc.post(
            write_url,
            data={"PHP_SESSION_UPLOAD_PROGRESS": "scopecheck-mismatch"},
            files={"f": (inert, b"x", "application/octet-stream")},
            cookies={"PHPSESSID": sid},
        )
        resp_r = sc.post(
            read_url,
            data={"PHP_SESSION_UPLOAD_PROGRESS": "scopecheck-read"},
            files={"f": ("read-probe.txt", b"x", "application/octet-stream")},
            cookies={"PHPSESSID": sid},
        )
    except requests.RequestException as exc:
        return _mk_result(
            "handler_mismatch", "serialize_handler mismatch", "error",
            "Request failed during probe.", [f"{write_url} or {read_url} -> {exc.__class__.__name__}"],
        )

    evidence = [
        f"Write probe ({write_url}): HTTP {resp_w.status_code}, "
        f"filename marker stored under SID {sid}",
        f"Read probe ({read_url}): HTTP {resp_r.status_code}",
    ]

    combined = _body(resp_w) + "\n" + _body(resp_r)
    decode_fail = "failed to decode session object" in combined.lower()
    destruct_fail = "session object destruction failed" in combined.lower()

    if decode_fail:
        evidence.append("Matched: 'Failed to decode session object' — the php handler "
                        "tripped over php_serialize-formatted data. Mismatch confirmed.")
    if destruct_fail:
        evidence.append("Matched: 'Session object destruction failed' — "
                        "destruction path fired on decoded data.")

    if decode_fail or destruct_fail:
        return _mk_result(
            "handler_mismatch", "serialize_handler mismatch", "vulnerable",
            "Handler mismatch observed: session written under one serialize format "
            "is decoded under another. This is the precondition for object "
            "injection IF the app also defines classes with exploitable magic "
            "methods — this probe's stdClass is inert, so nothing executed.",
            evidence,
            remediation=[
                "Use ONE session.serialize_handler value globally (php_serialize recommended)",
                "Remove per-directory .user.ini handler overrides",
                "Audit app classes for dangerous __destruct/__wakeup gadgets",
            ],
        )

    return _mk_result(
        "handler_mismatch", "serialize_handler mismatch", "inconclusive",
        "No decode warnings surfaced. With display_errors=Off this is expected even "
        "when a mismatch exists — check the host-side session file for the '|' marker.",
        evidence,
        remediation=[
            f"Host-side check: cat /tmp/sessions/sess_{sid}  (expect the php_serialize "
            "format with a literal '|' if the write endpoint accepted the marker)",
            "Hardening: single global serialize_handler, display_errors=Off in production",
        ],
    )


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def run_scan(target: str, options: dict) -> dict:
    """Run all applicable checks. options keys:
       path, phpinfo (bool), write_path, read_path
    Returns a JSON-serialisable report dict.
    """
    base = target.rstrip("/")
    options = options or {}
    path = options.get("path") or "/index.php"

    sc = ScannedSession()
    results: list[dict] = []

    results.append(check_fingerprint(sc, base))
    if options.get("phpinfo", True):
        results.append(check_phpinfo(sc, base))
    results.append(check_upload_progress(sc, base, path))
    results.append(check_handler_mismatch(
        sc, base, options.get("write_path", ""), options.get("read_path", "")))

    results.sort(key=lambda r: STATUS_ORDER.get(r["status"], 5))
    worst = results[0]["status"] if results else "error"

    return {
        "target": target,
        "scan_id": secrets.token_hex(6),
        "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "overall": worst,
        "overall_label": {
            "vulnerable": "CONDITIONS PRESENT",
            "hardened": "NO CONDITIONS FOUND",
            "inconclusive": "INCONCLUSIVE — host-side checks needed",
            "info": "COMPLETED (informational)",
            "error": "SCAN ERROR",
        }.get(worst, worst.upper()),
        "results": results,
        "request_log": sc.log,
    }
