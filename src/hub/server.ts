import { createServer } from "node:http";
import type { Server, IncomingMessage, ServerResponse } from "node:http";

import { readJson, sendJson } from "../http.ts";
import { importPrivateKey } from "../core/keys.ts";
import { issueSession } from "../core/session.ts";
import type { Store } from "./store.ts";

// The hub runs on the farm. It issues sessions offline: it has NO network
// dependency and does not import an HTTP client or receive a cloud URL.
// Authenticating the user (password, etc.) is out of scope for this PoC — the
// caller supplies the userId to put in the session.

export type HubConfig = {
  port: number;
  store: Store;
};

export type HubServer = {
  server: Server;
  close: () => Promise<void>;
  port: () => number;
};

type SessionRequest = {
  userId?: unknown;
};

export async function createHubServer(config: HubConfig): Promise<HubServer> {
  const loaded = await config.store.loadDeviceIdentity();
  if (!loaded) {
    throw new Error("hub is not provisioned: run provision first");
  }
  const identity = loaded;
  const devicePrivateKey = await importPrivateKey(identity.privateJwk);

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "POST" && url.pathname === "/session") {
        await handleSession(req, res);
        return;
      }
      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 400, { error: "bad request", detail: String((err as Error).message) });
    }
  });

  async function handleSession(req: IncomingMessage, res: ServerResponse) {
    const body = ((await readJson(req)) ?? {}) as SessionRequest;
    const { userId } = body;

    if (typeof userId !== "string" || userId.length === 0) {
      sendJson(res, 400, { error: "missing userId" });
      return;
    }

    // Issue the session offline, signed with the device key.
    const token = await issueSession({
      devicePrivateKey,
      deviceCert: identity.deviceCert,
      deviceId: identity.deviceId,
      userId,
    });

    sendJson(res, 200, { token });
  }

  await new Promise<void>((resolve) => server.listen(config.port, "127.0.0.1", resolve));

  return {
    server,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
    port: () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        return addr.port;
      }
      throw new Error("server has no port");
    },
  };
}
