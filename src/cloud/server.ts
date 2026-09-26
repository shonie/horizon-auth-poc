import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { generateKeyPair, exportJWK } from "jose";
import type { Server, IncomingMessage, ServerResponse } from "node:http";
import type { JWK, KeyLike } from "jose";

import { readJson, sendJson, bearerToken } from "../http.ts";
import { issueDeviceCert } from "../core/device-cert.ts";
import { verifySession, AUDIENCE_CLOUD } from "../core/session.ts";

export type CloudRootKeyPair = {
  publicKey: KeyLike;
  privateKey: KeyLike;
  kid: string;
};

export type CloudConfig = {
  port: number;
  enrollmentCode: string;
  // Optional, so a test can restart the cloud with the same root key.
  rootKeyPair?: CloudRootKeyPair;
};

export type CloudServer = {
  server: Server;
  close: () => Promise<void>;
  revokeDevice: (deviceId: string) => void;
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
  farmId?: unknown;
  publicJwk?: unknown;
};

export async function createCloudServer(config: CloudConfig): Promise<CloudServer> {
  const rootKeyPair = config.rootKeyPair ?? (await makeRootKeyPair());
  const rootJwk: JWK = { ...(await exportJWK(rootKeyPair.publicKey)), kid: rootKeyPair.kid };

  // In-memory state: one-time enrollment codes and revoked device IDs.
  const usedEnrollmentCodes = new Set<string>();
  const revoked = new Set<string>();

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
      const reportsMatch = /^\/farms\/([^/]+)\/reports$/.exec(path);
      if (req.method === "GET" && reportsMatch) {
        await handleReports(req, res, decodeURIComponent(reportsMatch[1]));
        return;
      }

      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 400, { error: "bad request", detail: String((err as Error).message) });
    }
  });

  async function handleProvision(req: IncomingMessage, res: ServerResponse) {
    const body = ((await readJson(req)) ?? {}) as ProvisionRequest;
    const { enrollmentCode, farmId, publicJwk } = body;

    if (typeof enrollmentCode !== "string" || typeof farmId !== "string" || typeof publicJwk !== "object" || publicJwk === null) {
      sendJson(res, 400, { error: "missing enrollmentCode, farmId, or publicJwk" });
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
      farmId,
      devicePublicJwk: publicJwk as JWK,
    });

    sendJson(res, 200, { deviceId, deviceCert, rootJwk });
  }

  async function handleReports(req: IncomingMessage, res: ServerResponse, farmId: string) {
    const token = bearerToken(req);
    if (!token) {
      sendJson(res, 401, { error: "missing bearer token" });
      return;
    }

    let session;
    try {
      session = await verifySession(token, {
        rootKey: rootKeyPair.publicKey,
        audience: AUDIENCE_CLOUD,
        enforceCertExpiry: true,
        isRevoked: (id) => revoked.has(id),
      });
    } catch {
      sendJson(res, 401, { error: "invalid session" });
      return;
    }

    if (session.farmId !== farmId) {
      sendJson(res, 403, { error: "token farm does not match route farm" });
      return;
    }

    sendJson(res, 200, {
      farmId,
      reports: [
        { id: "milk-yield", period: "2026-09", litres: 18450 },
        { id: "avg-yield-per-cow", period: "2026-09", litres: 29.1 },
      ],
      verifiedFor: { userId: session.userId, deviceId: session.deviceId },
    });
  }

  await new Promise<void>((resolve) => server.listen(config.port, "127.0.0.1", resolve));

  return {
    server,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
    revokeDevice: (deviceId: string) => {
      revoked.add(deviceId);
    },
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
