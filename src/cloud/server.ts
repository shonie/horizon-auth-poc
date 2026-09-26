import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { generateKeyPair, exportJWK } from "jose";
import type { Server, IncomingMessage, ServerResponse } from "node:http";
import type { JWK, KeyLike } from "jose";

import { readJson, sendJson, bearerToken } from "../http.ts";
import { issueDeviceCert } from "../core/device-cert.ts";
import { verifySession } from "../core/session.ts";

export type CloudRootKeyPair = {
  publicKey: KeyLike;
  privateKey: KeyLike;
  kid: string;
};

export type CloudConfig = {
  port: number;
  enrollmentCode: string;
  // The root key is the trust anchor and must persist across restarts:
  // regenerating it would invalidate every device cert ever issued. In
  // production it is loaded from a secret store / KMS and injected here.
  // When omitted, a fresh key is generated (dev/demo convenience).
  rootKeyPair?: CloudRootKeyPair;
};

export type CloudServer = {
  server: Server;
  close: () => Promise<void>;
  rootKeyPair: CloudRootKeyPair;
  port: () => number;
};

async function makeRootKeyPair(): Promise<CloudRootKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  return { publicKey, privateKey, kid: `root-${randomUUID()}` };
}

type ProvisionRequest = {
  enrollmentCode?: unknown;
  publicJwk?: unknown;
};

export async function createCloudServer(config: CloudConfig): Promise<CloudServer> {
  const rootKeyPair = config.rootKeyPair ?? (await makeRootKeyPair());
  const rootJwk: JWK = { ...(await exportJWK(rootKeyPair.publicKey)), kid: rootKeyPair.kid };

  // In-memory state: enrollment codes that have already been spent.
  const usedEnrollmentCodes = new Set<string>();

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;

      if (req.method === "POST" && path === "/provision") {
        await handleProvision(req, res);
        return;
      }
      if (req.method === "GET" && path === "/.well-known/jwks.json") {
        sendJson(res, 200, { keys: [rootJwk] });
        return;
      }
      if (req.method === "GET" && path === "/whoami") {
        await handleWhoami(req, res);
        return;
      }

      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 400, { error: "bad request", detail: String((err as Error).message) });
    }
  });

  async function handleProvision(req: IncomingMessage, res: ServerResponse) {
    const body = ((await readJson(req)) ?? {}) as ProvisionRequest;
    const { enrollmentCode, publicJwk } = body;

    if (typeof enrollmentCode !== "string" || typeof publicJwk !== "object" || publicJwk === null) {
      sendJson(res, 400, { error: "missing enrollmentCode or publicJwk" });
      return;
    }
    // One-time use: a wrong or already-spent code is rejected.
    if (enrollmentCode !== config.enrollmentCode || usedEnrollmentCodes.has(enrollmentCode)) {
      sendJson(res, 401, { error: "invalid or already-used enrollment code" });
      return;
    }
    usedEnrollmentCodes.add(enrollmentCode);

    const deviceId = `dev-${randomUUID()}`;
    const deviceCert = await issueDeviceCert({
      rootPrivateKey: rootKeyPair.privateKey,
      rootKid: rootKeyPair.kid,
      deviceId,
      devicePublicJwk: publicJwk as JWK,
    });

    sendJson(res, 200, { deviceId, deviceCert, rootJwk });
  }

  // Verify a presented session against the pinned root key and return the
  // principal. This is the "cloud verifies an offline-issued token" step.
  async function handleWhoami(req: IncomingMessage, res: ServerResponse) {
    const token = bearerToken(req);
    if (!token) {
      sendJson(res, 401, { error: "missing bearer token" });
      return;
    }

    try {
      const session = await verifySession(token, { rootKey: rootKeyPair.publicKey });
      sendJson(res, 200, session);
    } catch {
      sendJson(res, 401, { error: "invalid session" });
    }
  }

  await new Promise<void>((resolve) => server.listen(config.port, "127.0.0.1", resolve));

  return {
    server,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
    rootKeyPair,
    port: () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        return addr.port;
      }
      throw new Error("server has no port");
    },
  };
}
