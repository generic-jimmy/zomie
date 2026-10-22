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
