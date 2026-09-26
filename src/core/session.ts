import { SignJWT, jwtVerify, decodeProtectedHeader } from "jose";
import { randomUUID } from "node:crypto";
import type { KeyLike } from "jose";
import { verifyDeviceCert } from "./device-cert.ts";
import { importPublicKey } from "./keys.ts";

export const AUDIENCE_LOCAL = "horizon-local";
export const AUDIENCE_CLOUD = "horizon-cloud";
export const SESSION_AUDIENCE = [AUDIENCE_LOCAL, AUDIENCE_CLOUD];

// One farm shift.
export const SESSION_LIFETIME_S = 12 * 60 * 60;
// Tolerance for farm clock drift while offline.
export const CLOCK_TOLERANCE_S = 300;

export type IssueSessionInput = {
  devicePrivateKey: KeyLike;
  deviceCert: string;
  deviceId: string;
  farmId: string;
  userId: string;
  now?: Date;
  lifetimeSeconds?: number;
};

// Hub-side, offline. Signs the session with the device private key and embeds
// the device cert in the header so the cloud can verify statelessly.
export async function issueSession(input: IssueSessionInput): Promise<string> {
  const now = input.now ?? new Date();
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + (input.lifetimeSeconds ?? SESSION_LIFETIME_S);

  return new SignJWT({ farm_id: input.farmId })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", dcert: input.deviceCert })
    .setIssuer(`device:${input.deviceId}`)
    .setSubject(input.userId)
    .setAudience(SESSION_AUDIENCE)
    .setJti(randomUUID())
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(input.devicePrivateKey);
}

export type VerifySessionOptions = {
  rootKey: KeyLike;
  audience: string;
  enforceCertExpiry: boolean;
  isRevoked: (deviceId: string) => boolean;
  currentDate?: Date;
};

export type SessionResult = {
  userId: string;
  farmId: string;
  deviceId: string;
};

// Verifies a session under either policy. Steps run in order and stop at the
// first failure (see docs/adr.md section 5).
export async function verifySession(
  token: string,
  options: VerifySessionOptions,
): Promise<SessionResult> {
  // 1. Read dcert from the protected header.
  const header = decodeProtectedHeader(token);
  const dcert = header.dcert;
  if (typeof dcert !== "string" || dcert.length === 0) {
    throw new Error("session has no device cert in header");
  }

  // 2. Verify the device cert with the pinned root key.
  const cert = await verifyDeviceCert(dcert, {
    rootKey: options.rootKey,
    enforceExpiry: options.enforceCertExpiry,
    currentDate: options.currentDate,
  });

  // 3. Import the device key from the cert.
  const deviceKey = await importPublicKey(cert.cnf.jwk);

  // 4. Verify the session with the device key.
  const { payload } = await jwtVerify(token, deviceKey, {
    audience: options.audience,
    clockTolerance: CLOCK_TOLERANCE_S,
    currentDate: options.currentDate,
    issuer: `device:${cert.sub}`,
  });

  const farmId = payload.farm_id;
  if (typeof farmId !== "string") {
    throw new Error("session has no farm_id");
  }
  if (typeof payload.sub !== "string") {
    throw new Error("session has no subject");
  }

  // 5. The session and the cert must agree on the farm.
  if (farmId !== cert.farm_id) {
    throw new Error("session farm_id does not match cert farm_id");
  }

  // 6. Revocation.
  if (options.isRevoked(cert.sub)) {
    throw new Error(`device is revoked: ${cert.sub}`);
  }

  // 7.
  return { userId: payload.sub, farmId, deviceId: cert.sub };
}
