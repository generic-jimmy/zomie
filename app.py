#!/usr/bin/env python3
"""
SessionScope Lab — web UI for the PHP session misconfiguration checker.

Routes:
  GET  /           scan form
  POST /scan       run scan, render report
  POST /api/scan   run scan, return JSON (handy for CLI / curl)

Scope policy:
  * Private / loopback targets scan without friction.
  * Public targets require the authorization checkbox (form field
    `authorized`) — without it the scan is refused.
  * Cloud metadata endpoints are always refused (see scanner.classify_target).

Run:  python app.py          (dev)
      gunicorn app:app ...   (if you prefer; lab default is fine with Flask)
"""
from __future__ import annotations

import json

from flask import Flask, jsonify, render_template, request

from scanner import classify_target, run_scan

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def _parse_options(form) -> dict:
    return {
        "path": (form.get("path") or "/index.php").strip() or "/index.php",
        "phpinfo": form.get("phpinfo") in ("on", "true", "1", True),
        "write_path": (form.get("write_path") or "").strip(),
        "read_path": (form.get("read_path") or "").strip(),
    }


def _authorize(target: str, form) -> tuple[bool, dict | None]:
    """Enforce the scope policy. Returns (allowed, error_response_data)."""
    verdict = classify_target(target)
    if not verdict["ok"]:
        return False, {
            "error": verdict["reason"],
            "scope": verdict,
        }
    if verdict["needs_confirm"] and form.get("authorized") not in ("on", "true", "1"):
        return False, {
            "error": ("Target resolves to a public IP. Confirm you own the system "
                      "or have written authorization by ticking the authorization box."),
            "scope": verdict,
        }
    return True, None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        return render_template("index.html", error="Provide a target URL."), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    allowed, err = _authorize(target, request.form)
    if not allowed:
        return render_template("index.html", error=err["error"],
                               scope=json.dumps(err["scope"], indent=2)), 403

    report = run_scan(target, _parse_options(request.form))
    return render_template("index.html", report=report)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API: {"target": "...", "path": "/index.php", "authorized": true, ...}"""
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    allowed, err = _authorize(target, payload)
    if not allowed:
        return jsonify(err), 403

    report = run_scan(target, {
        "path": payload.get("path", "/index.php"),
        "phpinfo": payload.get("phpinfo", True),
        "write_path": payload.get("write_path", ""),
        "read_path": payload.get("read_path", ""),
    })
    return jsonify(report)


if __name__ == "__main__":
    # Lab tool: bind all interfaces inside the container; published port is
    # controlled by the docker run -p flag on the operator side.
    app.run(host="0.0.0.0", port=5000, debug=False)
