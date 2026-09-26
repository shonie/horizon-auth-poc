import { createServer } from "node:http";
import type { Server, IncomingMessage, ServerResponse } from "node:http";

import { readJson, sendJson, bearerToken } from "../http.ts";
import { importPrivateKey, importPublicKey } from "../core/keys.ts";
import { verifyPassword } from "../core/passwords.ts";
import { issueSession, verifySession, AUDIENCE_LOCAL } from "../core/session.ts";
import type { Store } from "./store.ts";

// The hub runs on the farm. Its login and local-access paths have NO network
// dependency: it does not import an HTTP client and does not receive a cloud URL.

export type HubConfig = {
  port: number;
  store: Store;
};

export type HubServer = {
  server: Server;
  close: () => Promise<void>;
  port: () => number;
};

type LoginRequest = {
  username?: unknown;
  password?: unknown;
};

// A well-formed but unmatchable hash, so unknown users cost the same scrypt work.
const DUMMY_HASH = `scrypt$${"00".repeat(16)}$${"00".repeat(64)}`;

export async function createHubServer(config: HubConfig): Promise<HubServer> {
  const loaded = await config.store.loadDeviceIdentity();
  if (!loaded) {
    throw new Error("hub is not provisioned: run provision first");
  }
  const identity = loaded;

  const devicePrivateKey = await importPrivateKey(identity.privateJwk);
  const rootKey = await importPublicKey(identity.rootJwk);

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;

      if (req.method === "POST" && path === "/login") {
        await handleLogin(req, res);
        return;
      }
      if (req.method === "GET" && path === "/local/cows") {
        await handleLocalCows(req, res);
        return;
      }

      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 400, { error: "bad request", detail: String((err as Error).message) });
    }
  });

  async function handleLogin(req: IncomingMessage, res: ServerResponse) {
    const body = ((await readJson(req)) ?? {}) as LoginRequest;
    const { username, password } = body;

    if (typeof username !== "string" || typeof password !== "string") {
      sendJson(res, 400, { error: "missing username or password" });
      return;
    }

    const user = await config.store.getUser(username);
    // Verify against a hash even when the user is unknown, to avoid leaking
    // which usernames exist through timing. Reject on the boolean either way.
    const hash = user?.passwordHash ?? DUMMY_HASH;
    const ok = await verifyPassword(password, hash);

    if (!user || !ok) {
      sendJson(res, 401, { error: "invalid credentials" });
      return;
    }

    // Issue the session offline, signed with the device key.
    const token = await issueSession({
      devicePrivateKey,
      deviceCert: identity.deviceCert,
      deviceId: identity.deviceId,
      farmId: identity.farmId,
      userId: username,
    });

    sendJson(res, 200, { token });
  }

  async function handleLocalCows(req: IncomingMessage, res: ServerResponse) {
    const token = bearerToken(req);
    if (!token) {
      sendJson(res, 401, { error: "missing bearer token" });
      return;
    }

    let session;
    try {
      // Hub policy: do not enforce cert expiry, and never treat a device as
      // revoked (revocation is a cloud concern in this PoC).
      session = await verifySession(token, {
        rootKey,
        audience: AUDIENCE_LOCAL,
        enforceCertExpiry: false,
        isRevoked: () => false,
      });
    } catch {
      sendJson(res, 401, { error: "invalid session" });
      return;
    }

    if (session.farmId !== identity.farmId) {
      sendJson(res, 403, { error: "token farm does not match this hub" });
      return;
    }

    sendJson(res, 200, {
      farmId: session.farmId,
      cows: [
        { id: "cow-001", name: "Bessie", lastMilking: "2026-09-26T04:30:00Z" },
        { id: "cow-002", name: "Clarabelle", lastMilking: "2026-09-26T05:10:00Z" },
      ],
      verifiedFor: { userId: session.userId, deviceId: session.deviceId },
    });
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
