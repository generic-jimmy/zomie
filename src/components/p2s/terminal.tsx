"use client";

import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import "@xterm/xterm/css/xterm.css";

export interface TerminalHandle {
  write: (s: string) => void;
  writeln: (s: string) => void;
  clear: () => void;
  focus: () => void;
}

interface TerminalProps {
  /** raw keystrokes (tmpdrop reverse-shell mode) */
  onData?: (data: string) => void;
  /** completed lines (Enter) in line mode */
  onLine?: (line: string) => void;
  rawMode: boolean;
  className?: string;
}

const THEME = {
  background: "#09090b",
  foreground: "#d4d4d8",
  cursor: "#34d399",
  cursorAccent: "#09090b",
  selectionBackground: "#064e3b",
  black: "#18181b",
  red: "#f87171",
  green: "#34d399",
  yellow: "#fbbf24",
  blue: "#60a5fa",
  magenta: "#c084fc",
  cyan: "#22d3ee",
  white: "#e4e4e7",
  brightBlack: "#52525b",
};

/**
 * xterm.js wrapper. In raw mode every keystroke is forwarded immediately
 * (reverse-shell channel). In line mode the component does local echo,
 * keeps its own command history (Up/Down) and submits whole lines.
 */
const P2sTerminal = forwardRef<TerminalHandle, TerminalProps>(function P2sTerminal(
  { onData, onLine, rawMode, className },
  ref,
) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<import("@xterm/xterm").Terminal | null>(null);
  const rawRef = useRef(rawMode);
  rawRef.current = rawMode;
  const onDataRef = useRef(onData);
  onDataRef.current = onData;
  const onLineRef = useRef(onLine);
  onLineRef.current = onLine;

  useEffect(() => {
    if (!hostRef.current || termRef.current) return;
    let disposed = false;
    (async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
      ]);
      if (disposed || !hostRef.current) return;
      const term = new Terminal({
        fontFamily: "'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
        fontSize: 13,
        lineHeight: 1.25,
        cursorBlink: true,
        convertEol: true,
        scrollback: 5000,
        theme: THEME,
        allowProposedApi: true,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(hostRef.current);
      try {
        fit.fit();
      } catch {
        /* container not laid out yet */
      }

      let lineBuf = "";
      const history: string[] = [];
      let histIdx = -1;

      const repaint = (text: string) => {
        term.write(`\x1b[90m>\x1b[0m ${text}`);
      };

      term.onData((data) => {
        if (rawRef.current) {
          onDataRef.current?.(data);
          return;
        }
        if (data === "\r") {
          const line = lineBuf;
          term.write("\r\n");
          lineBuf = "";
          histIdx = -1;
          if (line.trim()) {
            history.push(line);
            if (history.length > 50) history.shift();
            onLineRef.current?.(line);
          }
        } else if (data === "\x7f") {
          if (lineBuf.length > 0) {
            lineBuf = lineBuf.slice(0, -1);
            term.write("\b \b");
          }
        } else if (data === "\x03") {
          term.write("^C\r\n");
          lineBuf = "";
          histIdx = -1;
        } else if (data === "\x1b[A" || data === "\x1b[B") {
          // history navigation
          if (history.length === 0) return;
          const dir = data === "\x1b[A" ? 1 : -1;
          const next = Math.min(Math.max(histIdx + dir, -1), history.length - 1);
          if (next === histIdx) return;
          histIdx = next;
          for (let i = 0; i < lineBuf.length; i++) term.write("\b \b");
          lineBuf = next === -1 ? "" : history[history.length - 1 - next];
          repaint(lineBuf);
        } else if (data >= " " || data === "\t") {
          lineBuf += data;
          term.write(data);
        }
      });
      termRef.current = term;

      const ro = new ResizeObserver(() => {
        try {
          fit.fit();
        } catch {
          /* ignore */
        }
      });
      ro.observe(hostRef.current);
      term.writeln(
        "\x1b[1;32m  php2shell console\x1b[0m \x1b[90m- CVE-2026-109618 / CVE-2026-109619\x1b[0m",
      );
      term.writeln("\x1b[90m  authorized lab use only\x1b[0m");
      term.writeln("");
    })();
    return () => {
      disposed = true;
      termRef.current?.dispose();
      termRef.current = null;
    };
  }, []);

  useImperativeHandle(ref, () => ({
    write: (s) => termRef.current?.write(s),
    writeln: (s) => termRef.current?.writeln(s),
    clear: () => termRef.current?.clear(),
    focus: () => termRef.current?.focus(),
  }));

  return <div ref={hostRef} className={className} style={{ minHeight: 320 }} />;
});

export default P2sTerminal;
