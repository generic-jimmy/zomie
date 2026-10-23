# Worklog

---
Task ID: 1
Agent: main (Z.ai)
Task: Build a Docker web app ("php2shell C2 console") wrapping the php2shell
CVE-2026-109618/CVE-2026-109619 PoC: give it a lab URL, it exploits, you get an
interactive shell.

Work Log:
- Researched https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
  (cloned to repo-php2shell/ for reference) + CVE context (Sansec/Sophos/Huntress).
  Verified repo poc_109618.py is byte-identical in all key constants to the
  user's pasted exploit; installed it verbatim as engine/exploit.py.
- Loaded fullstack-dev skill, initialized Next.js 16 scaffold (port 3000).
- Docker unavailable in sandbox -> built mock mode into the agent for full
  pipeline verification without a live target.
- Designed shell strategy around the 14-byte carrier limit:
  * leaks (chunk base + libphp base) are stable across prefork workers -> cache
    once, each command = one stage-3 run (~10-40s instead of re-leaking);
  * channel `resp`: output captured from stage-3 response body (<=14B cmds);
  * channel `fetch`: CMD>o to webroot (CWD of system() = script dir) + GET (<=12B);
  * channel `tail`: persistent `tail -F c|sh` worker; commands appended to `c`
    via printf/echo chunks (4/6 chars per run), output streams over the
    held-open response; spaces as $IFS, no shell metachars in chunks;
  * channel `tmpdrop`: reverse-shell script uploaded as multipart file part that
    survives the worker abort in /tmp/phpXXXXXX, triggered with `sh</tmp/p*`
    (retry cycle: rm -f /tmp/p* -> drop -> trigger), agent runs TCP callback
    listener -> raw interactive shell; callback IP auto-detected via UDP connect.
- Implemented engine/agent.py (JSON-lines protocol; stdio AND --serve daemon
  mode; mock paths). Ops: config/pwn/probe/open_shell/exec/shell_input/
  kill_shell/raw/snapshot.
- Refactored Node side to a thin daemon proxy (src/lib/agent-manager.ts):
  daemon on 127.0.0.1:47017 owns all exploit state so Next dev HMR restarts no
  longer orphan it or lose leaks; persistent broadcast listener feeds SSE.
- API routes: /api/session (config+snapshot), /api/action (pwn/probe/open_shell/
  kill_shell fire-and-forget), /api/shell (cmd / raw keystrokes), /api/events
  (SSE with hello snapshot + log replay), /api/raw (author's exploit.py CLI).
- UI: single-page console (src/components/p2s/console.tsx + terminal.tsx) with
  target config (profile bookworm/lab, offsets, callback IP/port, mock toggle),
  pipeline stage chips + live log, leaks readout, raw PoC runner, xterm.js
  terminal (line mode with history + raw mode for revshell), quick commands,
  mode selector (auto/resp/fetch/tail/tmpdrop), dark zinc/emerald theme,
  responsive (mobile stacked), sticky footer with legal note.
- Bugs found & fixed during browser verification:
  * op_snapshot returned nested {ok,data:{...}} -> flattened;
  * SSE listener filtered out result events -> busy flags never reset -> now
    forwards everything; added LISTENER_VERSION to evict stale listener sockets
    after code reloads;
  * mock config left stale leaks when switching targets -> state reset added.
- Verified end-to-end via agent-browser: mock connect -> PWN (stage chips turn
  done, leaks 0x7f4c00000000 / 0x7f9a1acdb000 / htdata / zif shown) -> open
  shell -> `cat /flag*` -> THM{php2shell_mock_flag_2026} rendered in xterm;
  SSE shell_data decoded; busy states recover; desktop + 390px mobile layouts
  render correctly; lint clean.
- Packaged: Dockerfile (bun build -> debian-slim runtime with python3),
  docker-compose.yml (network_mode: host for TryHackMe VPN + reverse-shell
  callback), .dockerignore, README.md (architecture, modes, quickstart,
  troubleshooting), project bundle copied to download/php2shell-c2-console.tar.gz.

Stage Summary:
- Deliverable: dockerized php2shell C2 console (Next.js 16 + python engine
  daemon) with one-click exploit pipeline and four escalating shell channels.
- Key artifacts: engine/exploit.py (verbatim PoC), engine/agent.py (shell
  daemon), src/lib/agent-manager.ts, src/app/api/*, src/components/p2s/*,
  Dockerfile, docker-compose.yml, README.md.
- Real-target behavior (resp/fetch/tail/tmpdrop channel availability) depends
  on the lab build and is auto-probed at runtime; mock mode covers UI/API/SSE
  verification which passed fully in-browser.

---
Task ID: 2
Agent: main (Z.ai)
Task: Fix "[-] unknown error" on Render deployment + declutter UI per user feedback.

Work Log:
- Root-caused the masked failures: engine/agent.py dispatch() emitted failures
  with the real reason only inside data["error"] (top-level error field absent),
  while the UI read msg.error -> always showed "unknown error".
- engine/agent.py: dispatch() now promotes data["error"] to the top-level
  result.error; op_pwn() gained a preflight stage (TCP connect + HTTP GET with
  Server banner log) that fails fast with actionable text, including a
  private/VPN-IP hint pointing to docker compose / public target URL.
- Rewrote src/components/p2s/console.tsx as a minimal console: slim header,
  single target bar (URL + profile + PWN, auto-connects), stage chips + log,
  terminal (auto-opens shell channel on ready), advanced drawer (offsets,
  callback ip/port, mock). Removed: raw PoC card, quick commands, mode
  selector, leaks readout, tooltips, extra header badges.
- Verified in browser: mock PWN -> stages done -> shell auto-open -> cat /flag*
  -> THM{php2shell_mock_flag_2026}; real-mode unreachable target now logs
  "[-] cannot reach 127.0.0.1:9 ([Errno 111] Connection refused) - private/VPN
  addresses are only routable..." in log + terminal + toast. Lint clean.
- README: added "Deploying on Render (or any PaaS)" section (PORT auto-bind,
  reachability rules for THM VPN IPs vs Render private services, local compose
  alternative). Refreshed download/php2shell-c2-console.tar.gz.

Stage Summary:
- Failures now always carry their real reason end-to-end (agent -> SSE -> UI).
- Preflight stage catches unreachable targets in seconds with a fix hint.
- UI reduced to target bar + log + terminal; shell channel auto-opens.
- NOTE for user: on Render, 10.0.0.12:8080 is only exploitable if it is a
  Render private service in the same account/region; otherwise run the console
  locally (docker compose) where the target is routable.

---
Task ID: 3
Agent: main (Z.ai)
Task: User reported HEAP_LEAK_FAILED after only 3 attempts; asked for research
on retry behavior of this vuln class + more tries.

Work Log:
- Research: PoC README confirms --retries = attempts per leak stage (author
  default 3, stage3 = retries+2); leak scoring needs >=8 2MB-aligned pointers
  in a >=1000-byte Set-Cookie; target must meet memory_limit < huge_mb,
  upload_progress.enabled=1, use_strict_mode=0, max_input_vars=1000, mod_php
  prefork. Retries only help when requirements hold -> diagnostics matter.
- engine/agent.py: default retries 3 -> 10 (cfg), richer failure results
  ("HEAP_LEAK_FAILED after N attempts (last leak cookie: M bytes)"); added
  parse_cookie diagnostic hook + _leak_diag() distinguishing: no Set-Cookie at
  all (config/PHP version) vs short cookie (grooming; retry) vs full cookie
  with no usable pointers (OOM/huge_mb vs memory_limit, max_input_vars).
- preflight now probes with the exploit's own HTTP/1.1 Target.get (old raw
  HTTP/1.0 probe caused the user's "preflight: no response" artifact); logs
  "GET path -> HTTP status (N bytes)"; TCP-open-but-no-HTTP fails with
  http/https + port hint.
- UI: advanced drawer gained "retries / stage" (default 10, cap 50) and
  "huge_mb (> memory_limit)" inputs; session route default retries 10, cap 50.
- README: new "Reliability & retries" section with diagnostic table + target
  requirements.
- Verified via scripts/fake_target.py (plain/cookie/tcp modes): preflight 200
  log; diag "no PHPSESSID Set-Cookie leak observed"; diag "leak cookie present
  (1200 bytes) but no usable pointer pattern ... huge_mb"; "TCP open but no
  HTTP response". Browser mock regression passed (PWN -> auto shell -> flag).
  Lint clean. Bundle refreshed.

Stage Summary:
- Retry count is now user-controlled (default 10) with per-stage rotation.
- Failures explain themselves: preflight, per-stage leak diagnostics, and
  attempt counts in result errors.
- Fake-target harness kept in scripts/fake_target.py for future regression.

---
Task ID: 4
Agent: main (Z.ai)
Task: Explain "agent daemon spawned" log line + root-cause mid-run daemon
restart that killed the user's exploit run (attempts 1-9 then daemon banner),
plus make stage-1 misses explain themselves.

Work Log:
- Explained the line: manager (agent-manager.ts) starting the python engine;
  pid = engine process, port 47017 = loopback-only control channel.
- Root-caused mid-run restarts: ensureDaemon() SIGKILLed the LIVE engine when a
  single 400ms port probe timed out under load (12MB uploads); also not
  single-flight (concurrent first requests could double-spawn), and engine
  stderr was discarded (stdio: ignore) so crashes were invisible.
- agent-manager.ts: ensureDaemon now single-flight; if the port probe fails but
  the recorded pid is alive it WAITS for the port instead of killing; SIGKILL
  only for a genuinely wedged process. Engine stdout/stderr -> engine/agent.log
  (crash tracebacks survive). proc exit publishes "[manager] agent daemon
  exited (pid, code, signal)" into the event stream. snapshot() merges manager
  lifecycle logs with daemon logs (dedupe ts+msg) so restarts show in replay.
- engine/agent.py: accept loop never dies on transient OSError. New per-attempt
  leak diagnostics via chunk_base_from_cookie/libphp_base_from_cookie hooks:
  one line per miss with cookie size, heap-ptr candidates, best 2MB group
  (need >=8), stage2 ptr page_ok. Categories drive adaptivity: after 3 misses
  auto-switch build profile (bookworm<->lab incl. stage1_n/stage2/pads/htdata),
  huge_mb cycles 12->7->24 on "short"/"pattern" signatures. Default retries
  10 -> 25 (session route + console cap 100).
- Tests: scripts/test_daemon_fix.py (fake_target plain mode): 4 attempts, 4
  per-attempt diag lines, profile auto-switch after 3 misses, daemon alive
  after failed run -> PASS. Live server: mock PWN ok; kill -9 engine ->
  "agent daemon exited (signal=SIGKILL)" logged + clean respawn. Lint clean.
- README "Reliability & retries" rewritten (25 attempts, adaptive behavior,
  new diagnostic table incl. daemon-exited row).

Stage Summary:
- Engine restarts mid-run are fixed (no more probe-kill) and, if the engine
  ever dies, the run now shows WHY (exit code/signal + engine/agent.log).
- Every stage-1/2 miss now reports a concrete reason per attempt; profile and
  huge_mb auto-adapt when the signature matches a known blocker.
- Retries default 25/attempt (cap 100).

---
Task ID: 5
Agent: main (Z.ai)
Task: User's real-target run showed per-attempt diag "no Set-Cookie leak at
all" - target responds but ignores the session upload. Upgrade preflight to
fingerprint the page on the first request.

Work Log:
- Diagnosed from the user's log (preflight 200/806B + "no Set-Cookie leak at
  all"): the target page never starts a PHP session, so the exploit cannot
  begin; not a retries problem.
- engine/agent.py preflight rewritten to a raw-GET that captures headers:
  logs Server banner, X-Powered-By (warns if PHP != 8.4.26), Apache patch
  fingerprint vs selected profile (2.4.68 -> lab, 2.4.69 -> bookworm),
  Location redirects, Set-Cookie names (warns on non-PHPSESSID session.name),
  and fires "no Set-Cookie on plain GET - page never starts a PHP session;
  point the URL at the app/login page or set session.auto_start=1" when the
  page is session-less.
- scripts/fake_target.py: plain/cookie modes now emit realistic Server +
  X-Powered-By headers. test_daemon_fix.py takes mode argv; asserts preflight
  fingerprint + no-session warning. Both branches PASS (cookie mode also
  verified the huge_mb 12->7->24 adaptive cycle).
- Bundle refreshed (download/php2shell-c2-console.tar.gz).

Stage Summary:
- First request now identifies: session-less page, wrong PHP version, wrong
  Apache build profile, renamed session cookie, or redirects - before any
  exploit attempt is wasted.

---
Task ID: 6
Agent: main (Z.ai)
Task: User asked for extensive research on how php2shell works; then explain
the "no Set-Cookie leak at all" signature, why the run kept burning 25
attempts after preflight already knew better, and stop referencing
engine/agent.log (unreachable on Render).

Work Log:
- Extensive web research: Datadog Security Labs walkthrough (CVE-2026-109618
  interrupted hash-table insertion after memory exhaustion; 3-stage exploit;
  requirements), Wiz Research (PHPSESSID memory disclosure: stale PS(id)
  url-encoded into Set-Cookie by the rfc1867 path even without session_start();
  upload-progress UAF; 109619 stale-state paths), Sansec/Recorded Future/
  watchTowr/CERT-EU (fixed in 8.2.35/8.3.36/8.4.27/8.5.12; CVSS 9.2; active
  exploitation; public-PoC validity caveats), PoC author README + the
  session-upload-progress-counters.patch (raw zval* bucket pointers in
  php_session_rfc1867_progress dangle when the HashTable is cleared).
- Root-caused the user's signature from their log: nginx 301 on
  GET /index.php -> /index.php/ while the exploit POSTs to /index.php - the
  POST bounces off the redirect, never reaches PHP, so Set-Cookie can never
  appear ("none" on every attempt = deterministic, not grooming luck).
- engine/agent.py: preflight rewritten - follows redirects (4 hops) and
  retargets t.path to the final page; adds a GO/NO-GO upload probe (1KB
  PHP_SESSION_UPLOAD_PROGRESS multipart, no cookie -> fresh Set-Cookie
  PHPSESSID required) plus a control POST without the field (distinguishes
  upload_progress=0 from session-less page); body-size calibration probes
  12/8/7/2MB (413 -> nginx client_max_body_size fatal; silent drop ->
  post_max_size fatal; auto-lowers huge_mb to the largest accepted size);
  stage1 aborts after 4 consecutive "none" attempts, stage2 after 3, with
  explicit [!] ABORTED messages; profile switch skipped on "none";
  _adapt_huge_mb("none") now cycles 12->8->7->2.
- agent-manager.ts: daemon exit + startup death now stream the last 12 lines
  of engine/agent.log into the console as [engine] events (PaaS users cannot
  read files); no more "see engine/agent.log" dead ends.
- console.tsx: [!] abort lines and [engine] crash lines render red/bold.
- scripts/fake_target.py: new modes vuln (fresh PHPSESSID on upload POST),
  redirect (nginx-style 301 /index.php -> /app/), 413 (body cap >1MB).
- scripts/test_daemon_fix.py rewritten: 4 cases (plain/redirect/413/vuln),
  asserts fail-fast attempt counts, retarget, probe GO/NO-GO, daemon
  survival. One test-side bug found ("ok" matched inside "Set-Cookie");
  engine behavior correct. All 4 cases PASS; lint clean.
- README "Reliability & retries" rewritten (GO/NO-GO gate section + new
  diagnostics table); bundle repacked to download/php2shell-c2-console.tar.gz.

Stage Summary:
- The exploit POST now lands on the redirect destination, preflight proves
  the target CAN start a session upload before spending attempts, hopeless
  runs abort in <=4 attempts with the exact reason, and engine crashes are
  visible in the console without file access.
- Key research conclusion for the user's target: nginx in front usually
  means php-fpm; the PoC profiles are calibrated for mod_php (libphp.so
  offsets) - if stage1 still misses after the fix, check what serves PHP.
