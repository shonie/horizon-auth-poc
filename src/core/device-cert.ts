import { SignJWT, compactVerify, decodeJwt } from "jose";
import type { JWK, KeyLike } from "jose";

export const DEVICE_CERT_TYP = "device-cert+jwt";
export const CERT_ISSUER = "lely-cloud";

// One year, matching the durability window in the design memo.
export const DEVICE_CERT_LIFETIME_S = 365 * 24 * 60 * 60;

export type DeviceCertClaims = {
  iss: string;
  sub: string;
  farm_id: string;
  cnf: { jwk: JWK };
  iat: number;
  exp: number;
};

export type IssueDeviceCertInput = {
  rootPrivateKey: KeyLike;
  rootKid: string;
  deviceId: string;
  farmId: string;
  devicePublicJwk: JWK;
  now?: Date;
  lifetimeSeconds?: number;
};

// Cloud-side. Binds deviceId + farmId + device public key, signed by the root key.
export async function issueDeviceCert(input: IssueDeviceCertInput): Promise<string> {
  const now = input.now ?? new Date();
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + (input.lifetimeSeconds ?? DEVICE_CERT_LIFETIME_S);

  return new SignJWT({
    farm_id: input.farmId,
    cnf: { jwk: input.devicePublicJwk },
  })
    .setProtectedHeader({ alg: "EdDSA", typ: DEVICE_CERT_TYP, kid: input.rootKid })
    .setIssuer(CERT_ISSUER)
    .setSubject(input.deviceId)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(input.rootPrivateKey);
}

export type VerifyDeviceCertOptions = {
  rootKey: KeyLike;
  enforceExpiry: boolean;
  currentDate?: Date;
};

// Verifies the cert signature against the pinned root key and checks its claims.
// Expiry is enforced only when enforceExpiry is true (cloud), so a long-offline
// farm is not locked out (hub).
export async function verifyDeviceCert(
  token: string,
  options: VerifyDeviceCertOptions,
): Promise<DeviceCertClaims> {
  const { protectedHeader } = await compactVerify(token, options.rootKey);

  if (protectedHeader.typ !== DEVICE_CERT_TYP) {
    throw new Error(`unexpected device cert typ: ${String(protectedHeader.typ)}`);
  }

  const claims = decodeJwt(token) as unknown as DeviceCertClaims;

  if (claims.iss !== CERT_ISSUER) {
    throw new Error(`unexpected device cert issuer: ${String(claims.iss)}`);
  }
  if (!claims.sub) {
    throw new Error("device cert has no subject");
  }
  if (!claims.cnf?.jwk) {
    throw new Error("device cert has no confirmation key");
  }

  if (options.enforceExpiry) {
    const nowS = Math.floor((options.currentDate ?? new Date()).getTime() / 1000);
    if (typeof claims.exp !== "number" || claims.exp <= nowS) {
      throw new Error("device cert is expired");
    }
  }

  return claims;
}
