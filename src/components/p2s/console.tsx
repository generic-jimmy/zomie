"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ChevronDown, TerminalSquare, Zap } from "lucide-react";
import P2sTerminal, { type TerminalHandle } from "./terminal";

/* ---------------- types ---------------- */

interface LogLine {
  ts: number;
  level: string;
  msg: string;
}

interface Snapshot {
  config: unknown;
  agentRunning: boolean;
  state: string;
  mode: string | null;
  modes: Record<string, boolean>;
  leaks: Record<string, string | null>;
  stages: Record<string, { status: string; detail?: string }>;
  shellStatus: { status: string; detail?: string } | null;
}

/* ---------------- helpers ---------------- */

function logColor(level: string): string {
  switch (level) {
    case "warn":
      return "text-amber-400";
    case "raw":
      return "text-emerald-300";
    default:
      return "text-zinc-400";
  }
}

function b64ToUtf8(b64: string): string {
  try {
    return decodeURIComponent(escape(atob(b64)));
  } catch {
    try {
      return atob(b64);
    } catch {
      return "";
    }
  }
}

function stageColor(status: string): string {
  switch (status) {
    case "done":
      return "bg-emerald-500/15 text-emerald-400 border-emerald-500/40";
    case "running":
      return "bg-amber-500/15 text-amber-400 border-amber-500/40 animate-pulse";
    case "failed":
      return "bg-red-500/15 text-red-400 border-red-500/40";
    default:
      return "bg-zinc-900 text-zinc-600 border-zinc-800";
  }
}

function stateColor(state: string): string {
  switch (state) {
    case "ready":
      return "bg-emerald-500/15 text-emerald-400 border-emerald-500/40";
    case "shell":
      return "bg-emerald-500/25 text-emerald-300 border-emerald-400/60 animate-pulse";
    case "error":
      return "bg-red-500/15 text-red-400 border-red-500/40";
    default:
      return "bg-zinc-900 text-zinc-400 border-zinc-800";
  }
}

/* ---------------- main component ---------------- */

export default function Console() {
  const [cfg, setCfg] = useState({
    url: "",
    profile: "bookworm",
    zifOffset: "",
    dtorOffset: "",
    htdataOffset: "",
    callbackIp: "",
    callbackPort: 4444,
    mock: false,
  });
  const [snap, setSnap] = useState<Snapshot>({
    config: null,
    agentRunning: false,
    state: "idle",
    mode: null,
    modes: {},
    leaks: {},
    stages: {},
    shellStatus: null,
  });
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [busy, setBusy] = useState({ pwn: false, shell: false });

  const termRef = useRef<TerminalHandle>(null);
  const logBoxRef = useRef<HTMLDivElement>(null);
  const snapRef = useRef(snap);
  snapRef.current = snap;
  const autoOpenedRef = useRef(false);

  const appendLog = useCallback((line: LogLine) => {
    setLogs((prev) => {
      const next = [...prev, line];
      return next.length > 1500 ? next.slice(next.length - 1500) : next;
    });
  }, []);

  /* ---------- SSE wiring ---------- */
  useEffect(() => {
    const es = new EventSource("/api/events?logs=1");
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        switch (msg.type) {
          case "hello":
            setSnap(msg.snapshot as Snapshot);
            break;
          case "log":
            appendLog({ ts: msg.ts, level: msg.level, msg: msg.msg });
            break;
          case "stage":
            setSnap((s) => ({
              ...s,
              stages: { ...s.stages, [msg.stage]: { status: msg.status, detail: msg.detail } },
            }));
            break;
          case "state":
            setSnap((s) => ({ ...s, state: msg.state, mode: msg.mode }));
            break;
          case "shell_status":
            setSnap((s) => ({
              ...s,
              shellStatus: { status: msg.status, detail: msg.detail },
            }));
            if (msg.status === "connected")
              termRef.current?.writeln("\x1b[1;32m[+] reverse shell connected - raw mode\x1b[0m");
            if (msg.status === "closed")
              termRef.current?.writeln("\x1b[31m[-] shell channel closed\x1b[0m");
            if (msg.status === "chunk")
              termRef.current?.writeln(`\x1b[90m[*] ${msg.detail}\x1b[0m`);
            break;
          case "shell_data":
            termRef.current?.write(b64ToUtf8(msg.data));
            break;
          case "result": {
            if (!msg.ok) {
              const err = msg.error ?? msg.data?.error ?? "failed";
              appendLog({ ts: Date.now(), level: "warn", msg: `[-] ${err}` });
              termRef.current?.writeln(`\x1b[31m[-] ${err}\x1b[0m`);
              toast({ title: "Failed", description: String(err), variant: "destructive" });
            }
            setBusy((b) => ({ ...b, pwn: false, shell: false }));
            break;
          }
        }
      } catch {
        /* malformed event */
      }
    };
    return () => {
      es.close();
    };
  }, [appendLog]);

  useEffect(() => {
    logBoxRef.current?.scrollTo({ top: logBoxRef.current.scrollHeight });
  }, [logs]);

  /* ---------- actions ---------- */

  const connect = useCallback(
    async (silent = false): Promise<boolean> => {
      try {
        const res = await fetch("/api/session", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cfg),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error ?? "connect failed");
        setSnap(data.snapshot as Snapshot);
        if (!silent) {
          appendLog({
            ts: Date.now(),
            level: "info",
            msg: `[+] target configured: ${cfg.mock ? "MOCK" : cfg.url} (profile: ${cfg.profile})`,
          });
        }
        termRef.current?.writeln(
          `\x1b[1;34m[*] target: ${cfg.mock ? "MOCK" : cfg.url} (profile: ${cfg.profile})\x1b[0m`,
        );
        return true;
      } catch (e) {
        toast({
          title: "Connect failed",
          description: e instanceof Error ? e.message : String(e),
          variant: "destructive",
        });
        return false;
      }
    },
    [cfg, appendLog],
  );

  const action = async (op: string, params?: Record<string, unknown>) => {
    const res = await fetch("/api/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ op, params }),
    });
    const data = await res.json();
    if (!res.ok) {
      toast({
        title: `Cannot ${op}`,
        description: data.error ?? "request failed",
        variant: "destructive",
      });
      setBusy((b) => ({ ...b, pwn: false, shell: false }));
    }
  };

  const pwn = async () => {
    if (!cfg.url.trim() && !cfg.mock) {
      toast({ title: "Enter a target URL first" });
      return;
    }
    setBusy((b) => ({ ...b, pwn: true }));
    autoOpenedRef.current = false;
    termRef.current?.writeln("\x1b[1;33m[*] exploit pipeline started\x1b[0m");
    if (await connect(true)) await action("pwn");
    else setBusy((b) => ({ ...b, pwn: false }));
  };

  const openShell = async (mode: string | null = null) => {
    setBusy((b) => ({ ...b, shell: true }));
    await action("open_shell", { mode, callback_port: cfg.callbackPort });
  };

  const killShell = async () => {
    await action("kill_shell");
    termRef.current?.writeln("\x1b[90m[*] shell channel torn down\x1b[0m");
  };

  const execCmd = useCallback(async (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;
    termRef.current?.writeln(`\x1b[90m> ${trimmed}\x1b[0m`);
    try {
      const res = await fetch("/api/shell", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cmd: trimmed }),
      });
      const data = await res.json();
      if (!res.ok) {
        termRef.current?.writeln(`\x1b[31m[-] ${data.error ?? "rejected"}\x1b[0m`);
      }
    } catch {
      termRef.current?.writeln("\x1b[31m[-] network error while sending command\x1b[0m");
    }
  }, []);

  const onTermData = useCallback((data: string) => {
    // raw keystrokes are only forwarded while the tmpdrop reverse shell is live
    const st = snapRef.current;
    if (!(st.mode === "tmpdrop" && st.shellStatus?.status === "connected")) return;
    fetch("/api/shell", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: data }),
    }).catch(() => undefined);
  }, []);

  const handleLine = useCallback(
    (line: string) => {
      if (line.trim()) void execCmd(line);
    },
    [execCmd],
  );

  // auto-open the shell channel as soon as leaks are ready
  useEffect(() => {
    if (snap.state === "ready" && !autoOpenedRef.current) {
      autoOpenedRef.current = true;
      void openShell(null);
    }
  }, [snap.state]);

  const ready = snap.state === "ready" || snap.state === "shell";
  const stageNames = ["preflight", "rotate", "stage1", "stage2", "probe"] as const;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-200 flex flex-col">
      {/* header */}
      <header className="border-b border-zinc-800 bg-zinc-900/60 sticky top-0 z-20">
        <div className="max-w-5xl mx-auto px-4 py-2.5 flex items-center gap-3">
          <TerminalSquare className="h-5 w-5 text-emerald-400" />
          <h1 className="text-base font-bold tracking-tight">
            php2shell<span className="text-emerald-400"> C2</span>
          </h1>
          <div className="ml-auto flex items-center gap-2">
            {snap.mode && (
              <Badge variant="outline" className="font-mono text-[10px] border-zinc-700 text-zinc-300">
                {snap.mode}
              </Badge>
            )}
            <Badge variant="outline" className={`font-mono text-[10px] border ${stateColor(snap.state)}`}>
              {snap.state}
            </Badge>
          </div>
        </div>
      </header>

      {/* main */}
      <main className="flex-1 w-full max-w-5xl mx-auto px-4 py-4 flex flex-col gap-4">
        {/* target bar */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 flex flex-col gap-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <Input
              placeholder="http://target:8080/index.php"
              value={cfg.url}
              onChange={(e) => setCfg({ ...cfg, url: e.target.value })}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !busy.pwn) void pwn();
              }}
              className="bg-zinc-950 border-zinc-800 font-mono text-xs flex-1"
            />
            <Select value={cfg.profile} onValueChange={(v) => setCfg({ ...cfg, profile: v })}>
              <SelectTrigger className="bg-zinc-950 border-zinc-800 text-xs sm:w-[170px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-950 border-zinc-800">
                <SelectItem value="bookworm">bookworm</SelectItem>
                <SelectItem value="lab">lab</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={pwn}
              disabled={busy.pwn}
              className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold sm:w-32"
            >
              <Zap className="h-4 w-4 mr-1" />
              {busy.pwn ? "exploiting..." : "PWN"}
            </Button>
          </div>

          <Collapsible>
            <CollapsibleTrigger className="flex items-center gap-1 text-[11px] text-zinc-600 hover:text-zinc-400">
              <ChevronDown className="h-3 w-3" /> advanced (offsets, callback, mock)
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-3 grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="grid gap-1">
                <Label className="text-[10px] text-zinc-600">zif_system</Label>
                <Input
                  placeholder="auto"
                  value={cfg.zifOffset}
                  onChange={(e) => setCfg({ ...cfg, zifOffset: e.target.value })}
                  className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                />
              </div>
              <div className="grid gap-1">
                <Label className="text-[10px] text-zinc-600">zval_ptr_dtor</Label>
                <Input
                  placeholder="auto"
                  value={cfg.dtorOffset}
                  onChange={(e) => setCfg({ ...cfg, dtorOffset: e.target.value })}
                  className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                />
              </div>
              <div className="grid gap-1">
                <Label className="text-[10px] text-zinc-600">callback IP</Label>
                <Input
                  placeholder="auto"
                  value={cfg.callbackIp}
                  onChange={(e) => setCfg({ ...cfg, callbackIp: e.target.value })}
                  className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                />
              </div>
              <div className="grid gap-1">
                <Label className="text-[10px] text-zinc-600">callback port</Label>
                <Input
                  type="number"
                  value={cfg.callbackPort}
                  onChange={(e) =>
                    setCfg({ ...cfg, callbackPort: Number(e.target.value) || 4444 })
                  }
                  className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                />
              </div>
              <div className="col-span-2 sm:col-span-4 flex items-center gap-2">
                <Switch
                  id="mock"
                  checked={cfg.mock}
                  onCheckedChange={(v) => setCfg({ ...cfg, mock: v })}
                />
                <Label htmlFor="mock" className="text-[11px] text-zinc-500">
                  mock mode (demo pipeline, no real target)
                </Label>
              </div>
            </CollapsibleContent>
          </Collapsible>
        </div>

        {/* log */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
          <div className="flex flex-wrap items-center gap-1.5 mb-2">
            {stageNames.map((st) => {
              const info = snap.stages[st];
              return (
                <Badge
                  key={st}
                  variant="outline"
                  className={`font-mono text-[10px] border ${stageColor(info?.status ?? "")}`}
                  title={info?.detail ?? ""}
                >
                  {st}
                </Badge>
              );
            })}
          </div>
          <div
            ref={logBoxRef}
            className="h-52 overflow-y-auto rounded-md border border-zinc-800 bg-zinc-950 p-2 font-mono text-[10.5px] leading-relaxed"
          >
            {logs.length === 0 && (
              <div className="text-zinc-600">agent log appears here...</div>
            )}
            {logs.map((l, i) => (
              <div key={`${l.ts}-${i}`} className={logColor(l.level)}>
                {l.msg}
              </div>
            ))}
          </div>
        </div>

        {/* shell */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
              <TerminalSquare className="h-4 w-4 text-emerald-400" /> shell
            </span>
            <span className="text-[10px] font-mono text-zinc-600 truncate">
              {ready ? "channel open - type a command" : "opens automatically after PWN"}
              {snap.shellStatus?.detail ? ` | ${snap.shellStatus.detail}` : ""}
            </span>
            <div className="ml-auto flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => openShell(null)}
                disabled={!ready || busy.shell}
                className="h-7 text-[11px] border-emerald-600/50 text-emerald-400 hover:bg-emerald-500/10"
              >
                reopen
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={killShell}
                disabled={!snap.mode}
                className="h-7 text-[11px] border-zinc-700 text-zinc-400 hover:bg-zinc-800"
              >
                close
              </Button>
            </div>
          </div>
          <div className="rounded-md border border-zinc-800 overflow-hidden">
            <P2sTerminal
              ref={termRef}
              onData={onTermData}
              onLine={handleLine}
              rawMode={Boolean(snap.mode === "tmpdrop" && snap.shellStatus?.status === "connected")}
              className="h-[380px] w-full"
            />
          </div>
        </div>
      </main>

      {/* footer */}
      <footer className="border-t border-zinc-800 bg-zinc-900/60 mt-auto">
        <div className="max-w-5xl mx-auto px-4 py-2 text-[10px] text-zinc-600 flex flex-wrap gap-x-4 justify-between">
          <span>
            authorized lab use only - CVE-2026-109618/109619 - resp/fetch/tail commands
            run ~10-40s each (14-byte carrier limit); tmpdrop gives a true terminal
          </span>
          <span className="font-mono">{snap.agentRunning ? "agent running" : "agent idle"}</span>
        </div>
      </footer>
    </div>
  );
}
