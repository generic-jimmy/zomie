import {
  addSubscriber,
  snapshot,
  startListener,
  type AgentEvent,
} from "@/lib/agent-manager";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const withLogs = url.searchParams.get("logs") === "1";

  const encoder = new TextEncoder();
  let unsub: (() => void) | null = null;
  let heartbeat: ReturnType<typeof setInterval> | null = null;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (evt: AgentEvent | Record<string, unknown>) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(evt)}\n\n`));
        } catch {
          /* stream closed */
        }
      };

      // attach to the daemon first so no events are missed after hello
      try {
        await startListener();
      } catch {
        /* daemon may come up later; events route still streams local events */
      }
      const snap = await snapshot();
      send({ type: "hello", snapshot: snap, ts: Date.now() });
      if (withLogs) {
        for (const line of snap.logs ?? []) {
          send({ type: "log", ...line });
        }
      }

      unsub = addSubscriber(send as (e: AgentEvent) => void);
      heartbeat = setInterval(() => {
        try {
          controller.enqueue(encoder.encode(`: ping\n\n`));
        } catch {
          /* closed */
        }
      }, 15000);

      req.signal.addEventListener("abort", () => {
        unsub?.();
        if (heartbeat) clearInterval(heartbeat);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      });
    },
    cancel() {
      unsub?.();
      if (heartbeat) clearInterval(heartbeat);
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
