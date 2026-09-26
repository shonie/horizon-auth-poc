import type { IncomingMessage, ServerResponse } from "node:http";

const MAX_BODY_BYTES = 1_000_000;

export async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) {
      throw new Error("request body too large");
    }
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) {
    return undefined;
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
}

export function bearerToken(req: IncomingMessage): string | undefined {
  const header = req.headers["authorization"];
  if (typeof header !== "string") {
    return undefined;
  }
  const match = /^Bearer (.+)$/.exec(header);
  return match ? match[1] : undefined;
}
