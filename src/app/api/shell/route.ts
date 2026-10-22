import { NextResponse } from "next/server";
import { fireAndForget } from "@/lib/agent-manager";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  if (typeof body.input === "string" && body.input.length > 0) {
    // raw keystrokes for the interactive (tmpdrop/revshell) channel
    try {
      const id = await fireAndForget("shell_input", {
        data: Buffer.from(body.input, "utf8").toString("base64"),
      });
      return NextResponse.json({ ok: true, queued: id });
    } catch (e) {
      return NextResponse.json(
        { error: e instanceof Error ? e.message : "failed" },
        { status: 502 },
      );
    }
  }

  const cmd = typeof body.cmd === "string" ? body.cmd : "";
  if (!cmd.trim()) {
    return NextResponse.json({ error: "empty command" }, { status: 400 });
  }
  if (cmd.length > 4000) {
    return NextResponse.json({ error: "command too long" }, { status: 400 });
  }
  const mode = typeof body.mode === "string" ? body.mode : undefined;
  try {
    const id = await fireAndForget("exec", { cmd, mode });
    return NextResponse.json({ ok: true, queued: id });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "failed" },
      { status: 502 },
    );
  }
}
