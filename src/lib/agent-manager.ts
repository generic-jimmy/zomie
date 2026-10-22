import net from "net";
import { spawn } from "child_process";
import path from "path";
import fs from "fs";

export type AgentEvent =
  | { type: "log"; level: string; msg: string; ts: number }
  | { type: "stage"; stage: string; status: string; detail?: string; ts: number }
  | {
      type: "state";
      state: string;
      mode: string | null;
      modes?: Record<string, boolean>;
      leaks?: Record<string, string | null>;
      ts: number;
    }
  | { type: "shell_data"; data: string; ts: number } // base64
  | { type: "shell_status"; status: string; detail?: string; ts: number }
  | { type: "result"; id: string; ok: boolean; data?: unknown; error?: string; ts: number };

export interface SessionConfig {
  url: string;
  profile: string;
  hugeMb: number;
  timeout: number;
  retries: number;
  zifOffset: string | null;
  dtorOffset: string | null;
  htdataOffset: string | null;
  callbackIp: string;
  callbackPort: number;
  mock: boolean;
}

export interface LogLine {
  ts: number;
  level: string;
  msg: string;
}

interface DaemonSnapshot {
  state: string;
  mode: string | null;
  modes: Record<string, boolean>;
  leaks: Record<string, string | null>;
  stages: Record<string, { status: string; detail?: string }>;
  shell_status: { status: string; detail?: string } | null;
  logs: LogLine[];
  url: string | null;
  mock: boolean;
}

export interface Snapshot {
  config: SessionConfig | null;
  agentRunning: boolean;
  state: string;
  mode: string | null;
  modes: Record<string, boolean>;
  leaks: Record<string, string | null>;
  stages: Record<string, { status: string; detail?: string }>;
  shellStatus: { status: string; detail?: string } | null;
  logs: LogLine[];
  url: string | null;
  mock: boolean;
  lastResult: { id: string; ok: boolean; data?: unknown; error?: string; ts: number } | null;
}

const AGENT_PORT = Number(process.env.P2S_AGENT_PORT || 47017);
const MAX_LOGS = 1500;

interface ModState {
  listener: net.Socket | null;
  listenerStarting: Promise<void> | null;
  listenerVersion: number;
  subs: Set<(e: AgentEvent) => void>;
  logs: LogLine[];
  lastConfig: SessionConfig | null;
  lastResult: Snapshot["lastResult"];
  proc: ReturnType<typeof spawn> | null;
  starting: Promise<boolean> | null;
}

// bump when the listener wiring changes so stale sockets get evicted
const LISTENER_VERSION = 2;

const g = globalThis as unknown as { __p2sMod?: ModState };
const M: ModState = g.__p2sMod ?? {
  listener: null,
  listenerStarting: null,
  listenerVersion: 0,
  subs: new Set(),
  logs: [],
  lastConfig: null,
  lastResult: null,
  proc: null,
  starting: null,
};
g.__p2sMod = M;

function engineDir(): string {
  return process.env.ENGINE_DIR || path.join(process.cwd(), "engine");
}

/* ---------------- event bus ---------------- */

export function addSubscriber(fn: (e: AgentEvent) => void): () => void {
  M.subs.add(fn);
  return () => {
    M.subs.delete(fn);
  };
}

export function publish(e: AgentEvent): void {
  if (e.type === "log") {
    M.logs.push({ ts: e.ts, level: e.level, msg: e.msg });
    if (M.logs.length > MAX_LOGS) M.logs.splice(0, M.logs.length - MAX_LOGS);
  } else if (e.type === "result") {
    M.lastResult = { id: e.id, ok: e.ok, data: e.data, error: e.error, ts: e.ts };
  }
  for (const fn of M.subs) {
    try {
      fn(e);
    } catch {
      /* subscriber died */
    }
  }
}

function handleDaemonEvent(evt: Omit<AgentEvent, "ts">): void {
  publish({ ...evt, ts: Date.now() } as AgentEvent);
}

/* ---------------- daemon plumbing ---------------- */

function tryConnect(timeoutMs = 400): Promise<net.Socket | null> {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port: AGENT_PORT });
    const done = (v: net.Socket | null) => {
      sock.removeAllListeners();
      resolve(v);
    };
    const t = setTimeout(() => {
      sock.destroy();
      done(null);
    }, timeoutMs);
    sock.once("connect", () => {
      clearTimeout(t);
      done(sock);
    });
    sock.once("error", () => {
      clearTimeout(t);
      done(null);
    });
  });
}

export async function daemonAlive(): Promise<boolean> {
  const s = await tryConnect();
  if (s) s.destroy();
  return s !== null;
}

function pidAlive(pid: number | undefined): boolean {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Engine stdout/stderr go to engine/agent.log so crash tracebacks survive. */
function engineLogFds(): ("ignore" | number)[] {
  try {
    const fd = fs.openSync(path.join(engineDir(), "agent.log"), "a");
    return ["ignore", fd, fd];
  } catch {
    return ["ignore"];
  }
}

/**
 * Last lines of the engine log. Users on PaaS (Render etc.) cannot read
 * files inside the container, so crash output must be pushed into the
 * console event stream instead of referenced as "see engine/agent.log".
 */
function tailEngineLog(maxLines = 12): string[] {
  try {
    const raw = fs.readFileSync(path.join(engineDir(), "agent.log"), "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    return lines.slice(-maxLines);
  } catch {
    return [];
  }
}

function publishEngineLogTail(reason: string) {
  publish({
    type: "log",
    level: "warn",
    msg: `${reason} - engine output follows:`,
    ts: Date.now(),
  });
  const lines = tailEngineLog();
  if (!lines.length) {
    publish({
      type: "log",
      level: "warn",
      msg: "[engine] (agent.log empty or unreadable)",
      ts: Date.now(),
    });
    return;
  }
  for (const l of lines) {
    publish({
      type: "log",
      level: "warn",
      msg: `[engine] ${l.slice(0, 400)}`,
      ts: Date.now(),
    });
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Start the engine if (and only if) it is really down.
 *
 * - Single-flight: concurrent callers share one spawn attempt (no double bind).
 * - Never SIGKILLs a live engine just because one 400ms port probe failed:
 *   if the process exists we wait for the port instead. This used to restart
 *   the daemon mid-exploit whenever a probe timed out under load.
 */
export function ensureDaemon(): Promise<boolean> {
  if (!M.starting) {
    M.starting = (async () => {
      if (await daemonAlive()) return true;
      const dir = engineDir();
      const script = path.join(dir, "agent.py");
      if (!fs.existsSync(script)) {
        throw new Error(`engine script not found: ${script}`);
      }
      // Port probe failed but the engine process is alive: it may just be
      // busy/slow. Give it time instead of killing it.
      if (M.proc && pidAlive(M.proc.pid)) {
        const deadline = Date.now() + 8000;
        while (Date.now() < deadline) {
          if (await daemonAlive()) return true;
          if (!pidAlive(M.proc.pid)) break;
          await wait(250);
        }
        if (await daemonAlive()) return true;
        // genuinely wedged: only now do we put it down
        publish({
          type: "log",
          level: "warn",
          msg: "[manager] engine process alive but not serving; restarting it",
          ts: Date.now(),
        });
        try {
          M.proc.kill("SIGKILL");
        } catch {
          /* already dead */
        }
        M.proc = null;
      }
      const python = process.env.PYTHON_BIN || "python3";
      const proc = spawn(python, ["-u", script, "--serve"], {
        cwd: dir,
        stdio: engineLogFds(),
        detached: false,
      });
      M.proc = proc;
      proc.on("exit", (code, signal) => {
        if (M.proc === proc) M.proc = null;
        publishEngineLogTail(
          `[manager] agent daemon exited (pid ${proc.pid}, code=${code ?? "?"}, signal=${signal ?? "none"})`,
        );
      });
      try {
        fs.writeFileSync(path.join(dir, "agent.pid"), String(proc.pid ?? ""));
      } catch {
        /* best effort */
      }
      const deadline = Date.now() + 8000;
      while (Date.now() < deadline) {
        if (await daemonAlive()) {
          publish({
            type: "log",
            level: "info",
            msg: `[*] agent daemon spawned (pid ${proc.pid}, port ${AGENT_PORT})`,
            ts: Date.now(),
          });
          return true;
        }
        if (!pidAlive(proc.pid)) {
          const tail = tailEngineLog(6).map((l) => l.slice(0, 200)).join(" | ");
          throw new Error(
            `agent daemon died on startup${tail ? `: ${tail}` : `; port ${AGENT_PORT}`}`,
          );
        }
        await wait(250);
      }
      throw new Error("agent daemon did not come up on port " + AGENT_PORT);
    })().finally(() => {
      M.starting = null;
    });
  }
  return M.starting;
}

/** One request/response round-trip; broadcasts seen on the wire are published. */
function daemonRequest(
  req: Record<string, unknown>,
  timeoutMs = 60000,
): Promise<Extract<AgentEvent, { type: "result" }>> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: "127.0.0.1", port: AGENT_PORT });
    let buf = "";
    let settled = false;
    const id = String(req.id ?? "");
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      fn();
    };
    const timer = setTimeout(() => {
      finish(() => reject(new Error(`agent request timed out (${req.op})`)));
    }, timeoutMs);
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          const evt = JSON.parse(line);
          if (evt.type === "result" && String(evt.id) === id) {
            finish(() => resolve(evt));
          } else if (evt.type !== "result") {
            handleDaemonEvent(evt);
          }
        } catch {
          /* malformed line */
        }
      }
    });
    sock.on("error", (err) => finish(() => reject(err)));
    sock.on("connect", () => {
      sock.write(JSON.stringify(req) + "\n");
    });
  });
}

let reqSeq = 0;
export async function rpc(
  op: string,
  params?: Record<string, unknown>,
  timeoutMs = 120000,
): Promise<Extract<AgentEvent, { type: "result" }>> {
  await ensureDaemon();
  const id = `n${++reqSeq}`;
  return daemonRequest({ id, op, params: params ?? {} }, timeoutMs);
}

/** Queue an op without waiting for its result (progress arrives via events). */
export async function fireAndForget(
  op: string,
  params?: Record<string, unknown>,
): Promise<string> {
  await ensureDaemon();
  const id = `n${++reqSeq}`;
  const sock = await tryConnect();
  if (!sock) throw new Error("agent daemon unreachable");
  sock.end(JSON.stringify({ id, op, params: params ?? {} }) + "\n");
  return id;
}

/** Persistent broadcast listener feeding SSE subscribers. */
export async function startListener(): Promise<void> {
  if (M.listener && M.listenerVersion === LISTENER_VERSION && !M.listener.destroyed) {
    return;
  }
  if (M.listener) {
    try {
      M.listener.destroy();
    } catch {
      /* ignore */
    }
    M.listener = null;
  }
  if (M.listenerStarting) return M.listenerStarting;
  M.listenerStarting = (async () => {
    await ensureDaemon();
    const sock = await tryConnect(1500);
    if (!sock) {
      M.listenerStarting = null;
      throw new Error("could not attach to agent daemon");
    }
    let buf = "";
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          const evt = JSON.parse(line);
          // forward EVERYTHING (incl. results) - fire-and-forget results
          // only reach the UI through this listener
          handleDaemonEvent(evt);
        } catch {
          /* ignore */
        }
      }
    });
    sock.on("error", () => {
      if (M.listener === sock) M.listener = null;
    });
    sock.on("close", () => {
      if (M.listener === sock) M.listener = null;
    });
    M.listener = sock;
    M.listenerVersion = LISTENER_VERSION;
    M.listenerStarting = null;
  })();
  return M.listenerStarting;
}

/* ---------------- snapshots ---------------- */

/** Merge manager-side lifecycle logs with the daemon's own log, dedup by ts+msg. */
function mergeLogs(a: LogLine[], b: LogLine[]): LogLine[] {
  const seen = new Set<string>();
  const out: LogLine[] = [];
  for (const l of [...a, ...b]) {
    const key = `${l.ts}|${l.msg}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(l);
  }
  out.sort((x, y) => x.ts - y.ts);
  return out;
}

export async function snapshot(): Promise<Snapshot> {
  let snap: Snapshot = {
    config: M.lastConfig,
    agentRunning: false,
    state: "idle",
    mode: null,
    modes: {},
    leaks: {},
    stages: {},
    shellStatus: null,
    logs: M.logs,
    url: M.lastConfig?.url ?? null,
    mock: M.lastConfig?.mock ?? false,
    lastResult: M.lastResult,
  };
  try {
    const res = await rpc("snapshot", {}, 8000);
    if (res.ok && res.data && typeof res.data === "object") {
      const d = res.data as Record<string, unknown>;
      const daemon = d as unknown as DaemonSnapshot;
      snap = {
        config: M.lastConfig,
        agentRunning: true,
        state: daemon.state ?? "idle",
        mode: daemon.mode ?? null,
        modes: daemon.modes ?? {},
        leaks: daemon.leaks ?? {},
        stages: daemon.stages ?? {},
        shellStatus: daemon.shell_status ?? null,
        logs: mergeLogs(M.logs, daemon.logs ?? []),
        url: daemon.url ?? M.lastConfig?.url ?? null,
        mock: Boolean(daemon.mock),
        lastResult: M.lastResult,
      };
    }
  } catch {
    /* daemon down; return local view */
  }
  return snap;
}

export function setLastConfig(cfg: SessionConfig): void {
  M.lastConfig = cfg;
}

export function recentLogs(): LogLine[] {
  return M.logs;
}
