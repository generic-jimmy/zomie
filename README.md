# SessionScope Lab — PHP Session Misconfig Scope Checker

A detection-only web tool for red team lab training. Give it a URL, it runs
inert probes against the target's PHP session configuration and reports:

- **CONDITIONS PRESENT** — configuration/behaviour matching known PHP
  session-injection preconditions was observed
- **NO CONDITIONS FOUND** — probes answered and nothing risky was observed
- **INCONCLUSIVE** — remote probing alone cannot decide; the report gives you
  the exact host-side commands for ground truth

It is a scope checker in the same category as a nuclei template or an Nmap
NSE script: it proves or disproves that a misconfiguration exists. It does
**not** exploit anything, attempt code execution, or produce shells.

## What it checks

| Check | Method | Verdict logic |
|-------|--------|---------------|
| PHP fingerprint | `GET /`, inspect headers | informational |
| phpinfo disclosure | probes `/phpinfo.php`, `/info.php`, `/test.php`, parses `session.*` settings | definitive config verdict when a phpinfo page is exposed |
| upload_progress acceptance | multipart POST with `PHP_SESSION_UPLOAD_PROGRESS`, benign marker filename, attacker-chosen SID (body + cookie) + control request | signals + host-side verification command |
| serialize_handler mismatch | writes an inert `a\|O:8:"stdClass":0:{}` marker via the write endpoint, reads via the read endpoint, matches decode warnings | confirmed on warning evidence, else host-side command provided |

## Payload guarantee (important)

Every payload this tool sends is inert:

- Filenames are random markers like `scopecheck-a1b2c3d4e5f6.txt`
- The handler-mismatch probe stores an **empty `stdClass`** — stdClass has no
  destructor and no magic methods, so deserializing it executes nothing
- No `<?php` strings, no webshells, no reverse connections, ever

The tool exists to confirm the *configuration condition* on your own lab
targets. Turning conditions into impact is out of scope by design.

## Scope policy

- Private / loopback / RFC1918 targets (your lab): scan freely
- Public IPs: scan is refused unless you tick the authorization checkbox
- Cloud metadata endpoints (`169.254.169.254` etc.): always refused
- Every request the tool makes is listed in the report's request log

## Build & run (one Dockerfile)

```bash
cd php-session-scope-checker
docker build -t sessionscope .
```

### Reaching lab sites on your host machine

The container cannot use `127.0.0.1` to mean *your* machine — inside the
container that is the container itself. Use one of these:

**Option A — host-gateway (Linux, explicit):**

```bash
docker run --rm -p 5000:5000 --add-host=host.docker.internal:host-gateway sessionscope
```

Then open `http://localhost:5000` and scan
`http://host.docker.internal:18080` (replace port with your lab site's).

**Option B — host network (Linux, simplest):**

```bash
docker run --rm --network host sessionscope
```

Then open `http://localhost:5000` and scan `http://127.0.0.1:18080` directly.

**Option C — macOS / Windows Desktop:** `host.docker.internal` works out of
the box; use Option A without the `--add-host` flag.

### JSON API (for scripts / curl)

```bash
curl -s -X POST http://localhost:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{
        "target": "http://127.0.0.1:18080",
        "path": "/index.php",
        "phpinfo": true,
        "write_path": "/app/upload.php",
        "read_path": "/api/endpoint.php",
        "authorized": true
      }'
```

`authorized` is only required for public-IP targets.

## Reading the results

- **phpinfo check says VULNERABLE** → strongest signal: the configuration
  itself exposes the conditions. Fix with the listed hardening lines.
- **upload_progress check says INCONCLUSIVE** → normal. Session-file creation
  is server-side state; run the printed `ls -la /tmp/sessions/ | grep <SID>`
  on the lab host to get ground truth. `sess_<SID>` present = condition
  confirmed.
- **handler mismatch says VULNERABLE** → the two directories really are using
  different serialize handlers; the php handler tripped on
  php_serialize-formatted data. This is the precondition for object injection
  *only if* the app also defines classes with dangerous magic methods.

## Hardening reference (blue-team half)

```ini
; php.ini — kills every condition this tool checks for
session.upload_progress.enabled = 0
session.use_strict_mode = 1
; pick ONE handler globally, never per-directory overrides
session.serialize_handler = php_serialize
display_errors = Off
```

Plus: remove reachable phpinfo pages, audit custom classes for `__destruct` /
`__wakeup` gadgets, and never let `.user.ini` change session settings
per-directory.

## Files

```
php-session-scope-checker/
├── Dockerfile
├── requirements.txt
├── app.py               # Flask UI + JSON API + scope enforcement
├── scanner.py           # detection logic (pure, no shell delivery)
├── templates/index.html # form + verdict cards
├── static/style.css
└── README.md
```

## Note on the referenced CVE

The operator-supplied research this tool was built around references
CVE-2026-109618 / CVE-2026-109619. These IDs could not be independently
verified; the tool therefore checks the underlying, well-documented PHP
session misconfiguration *conditions* (upload_progress handling, strict mode,
serialize handler mismatch) rather than asserting any specific CVE match.
