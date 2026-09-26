import { SignJWT } from "jose";
import { randomUUID } from "node:crypto";
import type { KeyLike } from "jose";

// One farm shift.
export const SESSION_LIFETIME_S = 12 * 60 * 60;

export type IssueSessionInput = {
  devicePrivateKey: KeyLike;
  deviceCert: string;
  deviceId: string;
  userId: string;
  now?: Date;
  lifetimeSeconds?: number;
};

// Hub-side, offline. Signs the session with the device private key and embeds
// the device cert in the header so the cloud can verify statelessly. The hub
// treats the cert as an opaque blob — only the cloud parses it.
export async function issueSession(input: IssueSessionInput): Promise<string> {
  const now = input.now ?? new Date();
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + (input.lifetimeSeconds ?? SESSION_LIFETIME_S);

  return new SignJWT({})
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", dcert: input.deviceCert })
    .setIssuer(`device:${input.deviceId}`)
    .setSubject(input.userId)
    .setJti(randomUUID())
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(input.devicePrivateKey);
}
