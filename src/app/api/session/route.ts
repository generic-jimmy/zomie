import { NextResponse } from "next/server";
import { rpc, snapshot, setLastConfig, type SessionConfig } from "@/lib/agent-manager";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function parseHex(v: unknown): string | null {
  if (typeof v !== "string" || !v.trim()) return null;
  const t = v.trim().replace(/^0x/i, "");
  return /^[0-9a-fA-F]+$/.test(t) ? `0x${t.toLowerCase()}` : null;
}

export async function GET() {
  return NextResponse.json(await snapshot());
}

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  const url = typeof body.url === "string" ? body.url.trim() : "";
  if (!body.mock) {
    if (!/^https?:\/\//i.test(url)) {
      return NextResponse.json(
        { error: "URL must start with http:// or https://" },
        { status: 400 },
      );
    }
  }

  const cfg: SessionConfig = {
    url: url || "http://mock.target/index.php",
    profile: body.profile === "lab" ? "lab" : "bookworm",
    hugeMb: Number(body.hugeMb) > 0 ? Number(body.hugeMb) : 12,
    timeout: Number(body.timeout) > 0 ? Number(body.timeout) : 30,
    retries: Number(body.retries) > 0 ? Math.min(50, Number(body.retries)) : 10,
    zifOffset: parseHex(body.zifOffset),
    dtorOffset: parseHex(body.dtorOffset),
    htdataOffset: parseHex(body.htdataOffset),
    callbackIp: typeof body.callbackIp === "string" ? body.callbackIp.trim() : "",
    callbackPort: Number(body.callbackPort) > 0 ? Number(body.callbackPort) : 4444,
    mock: Boolean(body.mock),
  };

  try {
    setLastConfig(cfg);
    const res = await rpc("config", {
      url: cfg.url,
      profile: cfg.profile,
      huge_mb: cfg.hugeMb,
      timeout: cfg.timeout,
      retries: cfg.retries,
      zif_offset: cfg.zifOffset ? Number(cfg.zifOffset) : null,
      dtor_offset: cfg.dtorOffset ? Number(cfg.dtorOffset) : null,
      htdata_offset: cfg.htdataOffset ? Number(cfg.htdataOffset) : null,
      callback_ip: cfg.callbackIp,
      callback_port: cfg.callbackPort,
      mock: cfg.mock,
    });
    if (!res.ok) {
      return NextResponse.json(
        { error: res.error ?? "agent rejected config" },
        { status: 400 },
      );
    }
    return NextResponse.json({ ok: true, snapshot: await snapshot() });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "config rpc failed" },
      { status: 500 },
    );
  }
}
