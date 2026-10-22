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

export function ensureDaemon(): Promise<boolean> {
  return (async () => {
    if (await daemonAlive()) return true;
    const dir = engineDir();
    const script = path.join(dir, "agent.py");
    if (!fs.existsSync(script)) {
      throw new Error(`engine script not found: ${script}`);
    }
    const python = process.env.PYTHON_BIN || "python3";
    if (M.proc) {
      try {
        M.proc.kill("SIGKILL");
      } catch {
        /* already dead */
      }
      M.proc = null;
    }
    const proc = spawn(python, ["-u", script, "--serve"], {
      cwd: dir,
      stdio: "ignore",
      detached: false,
    });
    M.proc = proc;
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
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error("agent daemon did not come up on port " + AGENT_PORT);
  })();
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
        logs: daemon.logs?.length ? daemon.logs : M.logs,
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
