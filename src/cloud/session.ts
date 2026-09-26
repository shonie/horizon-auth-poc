import { jwtVerify, decodeProtectedHeader, importJWK } from "jose";
import type { KeyLike } from "jose";
import { verifyDeviceCert } from "./device-cert.ts";

// Tolerance for device clock drift while offline.
export const CLOCK_TOLERANCE_S = 300;

export type VerifySessionOptions = {
  rootKey: KeyLike;
  currentDate?: Date;
};

export type SessionResult = {
  userId: string;
  deviceId: string;
};

// Verifies a session against the pinned root key. The root verifies the embedded
// device cert; the key inside the cert verifies the session. No IdP call needed.
export async function verifySession(
  token: string,
  options: VerifySessionOptions,
): Promise<SessionResult> {
  // 1. Read the device cert from the protected header.
  const header = decodeProtectedHeader(token);
  const dcert = header.dcert;
  if (typeof dcert !== "string" || dcert.length === 0) {
    throw new Error("session has no device cert in header");
  }

  // 2. Verify the device cert with the pinned root key.
  const cert = await verifyDeviceCert(dcert, {
    rootKey: options.rootKey,
    currentDate: options.currentDate,
  });

  // 3. Import the device key from the cert and verify the session with it.
  const deviceKey = (await importJWK(cert.cnf.jwk, "EdDSA")) as KeyLike;
  const { payload } = await jwtVerify(token, deviceKey, {
    clockTolerance: CLOCK_TOLERANCE_S,
    currentDate: options.currentDate,
    issuer: `device:${cert.sub}`,
  });

  if (typeof payload.sub !== "string") {
    throw new Error("session has no subject");
  }

  return { userId: payload.sub, deviceId: cert.sub };
}
