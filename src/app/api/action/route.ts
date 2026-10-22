import { NextResponse } from "next/server";
import { fireAndForget } from "@/lib/agent-manager";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const OPS = new Set(["pwn", "probe", "open_shell", "kill_shell"]);

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  const op = typeof body.op === "string" ? body.op : "";
  if (!OPS.has(op)) {
    return NextResponse.json({ error: `unsupported op "${op}"` }, { status: 400 });
  }
  try {
    const params = (body.params ?? {}) as Record<string, unknown>;
    const id = await fireAndForget(op, params);
    return NextResponse.json({ ok: true, queued: id });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "failed to queue op" },
      { status: 502 },
    );
  }
}
