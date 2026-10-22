# php2shell C2 — CVE-2026-109618 / CVE-2026-109619 Lab Console

A one-click exploit + interactive shell console for the **php2shell** PHP
session upload-progress heap UAF (CVSS v4.0 9.2), purpose-built for
**authorized lab targets** such as your TryHackMe room or a local
`php:8.4.26-apache` docker container.

> **Authorized use only.** Use this exclusively against systems you are
> explicitly permitted to attack (your own lab instances). Fixed PHP versions:
> 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

```
┌──────────────────────────────── browser ────────────────────────────────┐
│  Target config │ pipeline stages + live log │ xterm.js interactive shell │
└───────────────△──────────────────────────────△──────────────────────────┘
                │ SSE events / REST            │
┌───────────────┴──────────────────────────────┴──────────────────────────┐
│  Next.js server (thin proxy, port 3000)                                 │
│    /api/session /api/action /api/shell /api/events /api/raw             │
└───────────────△──────────────────────────────△──────────────────────────┘
                │ TCP 127.0.0.1:47017 (JSON lines)
┌───────────────┴──────────────────────────────┴──────────────────────────┐
│  engine/agent.py daemon  — owns all exploit state:                      │
│    exploit.py primitives → stage1 heap leak → stage2 libphp leak →      │
│    stage3 fake HashTable → zif_system(cmd ≤ 14 bytes)                   │
│    + shell channels: resp / fetch / tail / tmpdrop(revshell listener)   │
└─────────────────────────────────────────────────────────────────────────┘
```

The exploit engine is the author's `exploit.py` (repo:
`eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC`), kept **verbatim**.
`agent.py` imports it and adds leak caching + four shell channels.

---

## Why leaks get cached

The original PoC re-runs stage 1 + 2 for every command (~2-4 min each).
Apache prefork children share the same mmap layout, and the leaked Zend MM
chunk base / libphp base are identical across workers, so the console leaks
**once** and every following command costs a single stage-3 run (~10-40 s).

## Shell channels (auto-probed after PWN)

| mode | how it works | command budget | latency |
|------|--------------|----------------|---------|
| `resp` | command output is captured from the stage-3 HTTP response body | ≤ 14 bytes | ~10-30 s / cmd |
| `fetch` | `CMD>o` writes to the webroot (CWD of `system()` is the script dir), console GETs `/o` | ≤ 12 bytes | ~15-45 s / cmd |
| `tail` | one-time `tail -F c|sh` kept running in a worker; commands are appended to `c` in short printf/echo chunks; output streams over the held-open response | any length, but no <code>&#124;;&<>()\`'"</code> and spaces written as `$IFS` | ~10-30 s per 4-6 char chunk |
| `tmpdrop` | drops a reverse-shell script via a multipart file part that survives the worker abort in `/tmp/phpXXXXXX`, then fires `sh</tmp/p*` until it runs; console auto-detects the callback IP | full interactive terminal | bootstrap ~1-5 min, then instant |

The probe order is `resp` → `fetch`; `tail` and `tmpdrop` are validated when
opened. Everything degrades gracefully: if `resp` output never flushes, the
console falls back to `fetch`; if the webroot is read-only, use `tail` or
`tmpdrop`.

**TryHackMe tip:** run the console in docker with `network_mode: host` on the
machine connected to the TryHackMe OpenVPN, so (a) the console can reach
`http://10.x.x.x/...` and (b) the target can reach your callback port
(default `4444/tcp`) for `tmpdrop` reverse shells.

---

## Quickstart (docker, recommended)

```bash
docker compose up -d --build
# open http://localhost:3000
```

1. **Target** panel: paste the lab URL (e.g. `http://10.10.x.x:8080/index.php`),
   keep profile `bookworm` for the official `php:8.4.26-apache` image (or pick
   `lab` for the custom Apache 2.4.68 build), press **Connect**.
2. Press **PWN** — the pipeline (rotate → stage 1 heap leak → stage 2 libphp
   leak → auto-probe) streams into the log. Expect 1-4 minutes on the first
   run; retries are automatic.
3. Press **open shell** — `auto` uses the probed mode. Type commands in the
   terminal (Enter sends, ↑/↓ history, quick-command buttons included).
4. Want a *real* terminal? Select **tmpdrop** and press **open shell** — the
   console drops the reverse-shell script and waits for the callback. Once
   `reverse shell connected` appears, the terminal goes raw (instant
   keystrokes, full bash).

Offsets: `bookworm` defaults are built in. Different build? Expand
**advanced** and set `zif_system` / `zval_ptr_dtor` / `htdata` manually
(for local docker targets the original `exploit.py --no-auto-offsets=false`
flow also works through the **Raw PoC runner**).

## Local development (no docker)

```bash
bun install
python3 --version   # needs python3 on PATH
bun run dev         # http://localhost:3000
```

No lab at hand? Flip **Mock mode** in the advanced panel — the agent
simulates the full pipeline (leaks, probe, shell, flags) so you can exercise
the entire console safely.

## API (for scripting)

| route | purpose |
|-------|---------|
| `GET /api/session` | snapshot: state, mode, leaks, stages, logs |
| `POST /api/session` | configure target `{url, profile, hugeMb, timeout, retries, zifOffset, dtorOffset, htdataOffset, callbackIp, callbackPort, mock}` |
| `POST /api/action` | `{op: "pwn" \| "probe" \| "open_shell" \| "kill_shell", params}` (fire-and-forget; progress via SSE) |
| `POST /api/shell` | `{cmd, mode}` one-shot command, or `{input}` raw keystrokes for revshell |
| `GET /api/events` | SSE event stream (`?logs=1` replays the log) |
| `POST /api/raw` | run the author's `exploit.py` CLI verbatim with `-u/-c/--profile/--fetch` |

## Files that matter

```
engine/exploit.py    author's PoC (verbatim) — all heap grooming
engine/agent.py      daemon: leak caching + resp/fetch/tail/tmpdrop channels
src/lib/agent-manager.ts   node side: daemon proxy, SSE bus
src/app/api/*        REST + SSE routes
src/components/p2s/* console UI (target / pipeline / xterm terminal)
Dockerfile           bun build + python3 runtime
docker-compose.yml   host networking for VPN + callback
```

## Reliability & retries (read before blaming the exploit)

Stage 1/2 leaks are **probabilistic heap grooming**, not deterministic: each
attempt rotates a fresh prefork worker, sends the OOM + grooming requests, and
scores the `Set-Cookie` bytes (stage 1 needs **≥ 8** 2MB-aligned pointers in a
cookie of ≥ 1000 bytes). The author's CLI default is `--retries 3`; this console
defaults to **25 attempts per stage** (tunable in `advanced`, cap 100) and
rotates the worker between attempts.

The agent is also **adaptive**: after 3 consecutive stage-1 misses it switches
to the other build profile (the two calibrated builds use different grooming
field counts), and it cycles `huge_mb` (12 → 8 → 7 → 2 on "no cookie",
12 → 7 → 24 on weak patterns) when the diagnostics point at body-size or
`memory_limit` blockers. Every failed attempt logs a one-line reason so you
can see *why* it missed.

### Preflight is a hard GO/NO-GO gate (research-backed)

The php2shell chain only works if the POST actually reaches PHP's rfc1867
upload-progress handler — that is where the OOM corruption and the
`PHPSESSID` memory disclosure both live (see the Wiz / Datadog writeups,
October 2026). Before **any** exploit attempt is spent, the agent now:

1. **Follows redirects** (up to 4 GET hops) and retargets the exploit POST
   path to the final destination — a POST to `http://host/index.php` that
   nginx 301-redirects to `/index.php/` would otherwise bounce off the
   redirect and *never reach PHP* (the classic "no Set-Cookie at all on every
   attempt" signature).
2. **Sends a minimal upload probe** (1KB multipart with
   `PHP_SESSION_UPLOAD_PROGRESS`, no session cookie). PHP must answer with a
   fresh `Set-Cookie: PHPSESSID` or the run is refused with the exact reason:
   wrong page, `session.upload_progress.enabled=0`, `session.use_cookies=0`,
   or a custom `session.name`. A control POST without the upload field
   distinguishes "upload progress disabled" from "page has no session at all".
3. **Calibrates the body size**: a 12MB probe verifies the request is not
   swallowed by `client_max_body_size` (nginx defaults to **1M** → HTTP 413)
   or `post_max_size` (PHP default 8M silently drops oversized bodies — no
   413, just no session). If 12MB is rejected the agent retries 8 → 7 → 2MB
   and lowers `huge_mb` to the largest size the target still accepts.
4. **Fails fast instead of burning retries**: "no Set-Cookie at all" is a
   routing/config problem, not grooming luck — after 4 consecutive such
   stage-1 attempts (3 in stage 2) the run aborts with an explicit `[!]`
   message. Retries continue only for probabilistic signatures (short/weak
   leak cookies).

Retries only help when the target actually meets the exploit requirements —
if attempts keep failing, read the diagnostic the agent logs after each
attempt:

| diagnostic | meaning | fix |
|------------|---------|-----|
| `upload probe: no Set-Cookie PHPSESSID` (preflight fatal) | the exploit POST never reaches PHP's session handler | point the URL at the app's PHP entry page (e.g. its login page); check `session.upload_progress.enabled=1` and `session.use_cookies=1` |
| `a plain POST gets a session cookie but the PHP_SESSION_UPLOAD_PROGRESS one does not` (preflight fatal) | upload progress disabled | enable `session.upload_progress.enabled=1` (default On) |
| `body probe: the server rejects NMB POSTs (HTTP 413)` (preflight fatal) | proxy/WAF body limit below the exploit's multi-MB OOM field | raise `client_max_body_size` (nginx default 1M) / lower `huge_mb` — but it must still exceed the target `memory_limit` |
| `body probe: even a 2MB upload POST gets no Set-Cookie` (preflight fatal) | `post_max_size` under 2MB (PHP default is 8M) | fix server config; unexploitable as-is |
| `exploit POST path retargeted to ...` | a redirect was followed; POSTs now go to the final page | informational — the retargeted page must be the PHP app |
| `no Set-Cookie leak at all` (per attempt) | request-specific: body limit or a different backend worker answered | the run auto-aborts after 4; check the preflight probe lines above |
| `no PHPSESSID Set-Cookie leak observed` | page/session config wrong or PHP ≠ 8.4.26 mod_php prefork | enable `session.upload_progress.enabled=1`, `session.use_strict_mode=0`, `session.use_cookies=1`; confirm PHP 8.4.26 + Apache prefork |
| `leak cookie only NB (<1000)` | grooming did not reach the leak window | just retry / more retries; agent auto-cycles `huge_mb` |
| `leak cookie ... best 2MB group N (need >=8)` | pattern too weak: OOM did not trigger or input caps interfere | raise `huge_mb` above the target `memory_limit` (agent cycles 12→24 automatically); target needs `max_input_vars=1000` |
| `[manager] agent daemon exited ...` + `[engine] ...` lines | the python engine process died | the crash output is streamed into the console (no file access needed on PaaS) |

Target requirements (from the PoC README): `display_errors=1`, `memory_limit`
below `--huge-mb` (default 12M), `max_input_vars=1000`, `session.use_cookies=1`,
`session.use_strict_mode=0`, `session.upload_progress.enabled=1`, mod_php under
Apache **prefork**.

## Deploying on Render (or any PaaS)

The Dockerfile binds to `$PORT`, so Render's injected port (10000) is picked up
automatically — no config needed. The python engine daemon runs inside the same
container on 127.0.0.1 and needs no open port.

**Target reachability is the #1 failure mode on PaaS.** The console exploits
from wherever it runs — a cloud container can only reach targets that are
routable from it:

- TryHackMe VPN IPs (`10.10.x.x`) are **not** reachable from Render.
- Render private-service IPs (`10.x.x.x`) work only if the console service is
  in the same account/region.
- Anything else must be publicly reachable, or run the console locally with
  `docker compose up --build` (host networking keeps VPN routes + callback).

The preflight stage fails fast with a clear message when the target is
unreachable instead of a generic error.

## Troubleshooting

| symptom | fix |
|---------|-----|
| `cannot reach host:port` at preflight | target not routable from the console host — see "Deploying on Render" above. |
| `HEAP_LEAK_FAILED` | target `memory_limit` must be smaller than `--huge-mb` (default 12 MB). The page must trigger session handling with `session.upload_progress.enabled=1` and `session.use_strict_mode=0`. |
| leaks OK, every command fails | build ≠ bookworm profile → set custom offsets, or rotate more (`retries`); confirm the endpoint is actually served by mod_php. |
| `resp` probe finds nothing | normal on many setups; console auto-falls back to `fetch`. |
| `fetch` GET 404 | webroot not writable by www-data, or app not at the URL path you gave; use `tail`/`tmpdrop`. |
| `tmpdrop` no callback | callback IP must be reachable from the target (host-network docker + VPN). Check `callback IP` field, port 4444 not firewalled. |
| daemon port busy | set `P2S_AGENT_PORT` env for both server and compose. |

Engine daemon state (leaks + shell) lives in `engine/agent.py --serve`
(127.0.0.1:47017) — the web server can restart without losing a running shell.
