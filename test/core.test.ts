import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "jose";
import type { JWK, KeyLike } from "jose";

import { generateDeviceKeys } from "../src/core/keys.ts";
import { issueDeviceCert } from "../src/core/device-cert.ts";
import {
  issueSession,
  verifySession,
  AUDIENCE_LOCAL,
  AUDIENCE_CLOUD,
  SESSION_LIFETIME_S,
  CLOCK_TOLERANCE_S,
} from "../src/core/session.ts";
import { hashPassword, verifyPassword } from "../src/core/passwords.ts";

const ROOT_KID = "root-1";
const DEVICE_ID = "dev-123";
const FARM_ID = "farm-42";
const USER_ID = "user-7";

async function makeRoot() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  return { rootPublicKey: publicKey, rootPrivateKey: privateKey };
}

type Fixture = {
  rootPublicKey: KeyLike;
  rootPrivateKey: KeyLike;
  devicePrivateKey: KeyLike;
  devicePublicJwk: JWK;
  deviceCert: string;
};

async function makeFixture(overrides?: { farmId?: string; certNow?: Date; certLifetime?: number }): Promise<Fixture> {
  const { rootPublicKey, rootPrivateKey } = await makeRoot();
  const device = await generateDeviceKeys();
  const deviceCert = await issueDeviceCert({
    rootPrivateKey,
    rootKid: ROOT_KID,
    deviceId: DEVICE_ID,
    farmId: overrides?.farmId ?? FARM_ID,
    devicePublicJwk: device.publicJwk,
    now: overrides?.certNow,
    lifetimeSeconds: overrides?.certLifetime,
  });
  return {
    rootPublicKey,
    rootPrivateKey,
    devicePrivateKey: device.privateKey,
    devicePublicJwk: device.publicJwk,
    deviceCert,
  };
}

const neverRevoked = () => false;

test("a valid session verifies under both policies", async () => {
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    userId: USER_ID,
  });

  const hub = await verifySession(token, {
    rootKey: f.rootPublicKey,
    audience: AUDIENCE_LOCAL,
    enforceCertExpiry: false,
    isRevoked: neverRevoked,
  });
  assert.deepEqual(hub, { userId: USER_ID, farmId: FARM_ID, deviceId: DEVICE_ID });

  const cloud = await verifySession(token, {
    rootKey: f.rootPublicKey,
    audience: AUDIENCE_CLOUD,
    enforceCertExpiry: true,
    isRevoked: neverRevoked,
  });
  assert.deepEqual(cloud, { userId: USER_ID, farmId: FARM_ID, deviceId: DEVICE_ID });
});

test("a tampered payload is rejected", async () => {
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    userId: USER_ID,
  });

  const [h, p, s] = token.split(".");
  const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  claims.sub = "attacker";
  const tamperedPayload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const tampered = `${h}.${tamperedPayload}.${s}`;

  await assert.rejects(
    verifySession(tampered, {
      rootKey: f.rootPublicKey,
      audience: AUDIENCE_LOCAL,
      enforceCertExpiry: false,
      isRevoked: neverRevoked,
    }),
  );
});

test("a self-signed cert is rejected because the root key does not match", async () => {
  // Attacker generates their own "root" and signs a cert with it.
  const attackerRoot = await makeRoot();
  const device = await generateDeviceKeys();
  const forgedCert = await issueDeviceCert({
    rootPrivateKey: attackerRoot.rootPrivateKey,
    rootKid: ROOT_KID,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    devicePublicJwk: device.publicJwk,
  });
  const token = await issueSession({
    devicePrivateKey: device.privateKey,
    deviceCert: forgedCert,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    userId: USER_ID,
  });

  // The real root does not match the attacker's signature.
  const realRoot = await makeRoot();
  await assert.rejects(
    verifySession(token, {
      rootKey: realRoot.rootPublicKey,
      audience: AUDIENCE_LOCAL,
      enforceCertExpiry: false,
      isRevoked: neverRevoked,
    }),
  );
});

test("an expired session is rejected", async () => {
  const f = await makeFixture();
  mock.timers.enable({ apis: ["Date"], now: 0 });
  try {
    const token = await issueSession({
      devicePrivateKey: f.devicePrivateKey,
      deviceCert: f.deviceCert,
      deviceId: DEVICE_ID,
      farmId: FARM_ID,
      userId: USER_ID,
    });
    // Advance past the session lifetime plus the clock tolerance.
    mock.timers.setTime((SESSION_LIFETIME_S + CLOCK_TOLERANCE_S + 60) * 1000);
    await assert.rejects(
      verifySession(token, {
        rootKey: f.rootPublicKey,
        audience: AUDIENCE_LOCAL,
        enforceCertExpiry: false,
        isRevoked: neverRevoked,
      }),
    );
  } finally {
    mock.timers.reset();
  }
});

test("an expired device cert is rejected by the cloud policy and accepted by the hub policy", async () => {
  // Cert issued in the past with a short lifetime, so it is already expired.
  const f = await makeFixture({ certNow: new Date(Date.now() - 60_000), certLifetime: 10 });
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    userId: USER_ID,
  });

  // Hub does not enforce cert expiry.
  const hub = await verifySession(token, {
    rootKey: f.rootPublicKey,
    audience: AUDIENCE_LOCAL,
    enforceCertExpiry: false,
    isRevoked: neverRevoked,
  });
  assert.equal(hub.deviceId, DEVICE_ID);

  // Cloud does.
  await assert.rejects(
    verifySession(token, {
      rootKey: f.rootPublicKey,
      audience: AUDIENCE_CLOUD,
      enforceCertExpiry: true,
      isRevoked: neverRevoked,
    }),
  );
});

test("a session farm_id that does not match the cert farm_id is rejected", async () => {
  // Cert says farm-42, but we issue a session claiming farm-99.
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    farmId: "farm-99",
    userId: USER_ID,
  });
  await assert.rejects(
    verifySession(token, {
      rootKey: f.rootPublicKey,
      audience: AUDIENCE_LOCAL,
      enforceCertExpiry: false,
      isRevoked: neverRevoked,
    }),
  );
});

test("a revoked device is rejected by the cloud policy", async () => {
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    userId: USER_ID,
  });
  await assert.rejects(
    verifySession(token, {
      rootKey: f.rootPublicKey,
      audience: AUDIENCE_CLOUD,
      enforceCertExpiry: true,
      isRevoked: (id) => id === DEVICE_ID,
    }),
  );
});

test("a token with no dcert header is rejected", async () => {
  const f = await makeFixture();
  // Sign a session-shaped JWT with no dcert in the header.
  const { SignJWT } = await import("jose");
  const token = await new SignJWT({ farm_id: FARM_ID })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setIssuer(`device:${DEVICE_ID}`)
    .setSubject(USER_ID)
    .setAudience([AUDIENCE_LOCAL, AUDIENCE_CLOUD])
    .setIssuedAt()
    .setExpirationTime("12h")
    .sign(f.devicePrivateKey);

  await assert.rejects(
    verifySession(token, {
      rootKey: f.rootPublicKey,
      audience: AUDIENCE_LOCAL,
      enforceCertExpiry: false,
      isRevoked: neverRevoked,
    }),
  );
});

test("a wrong audience is rejected", async () => {
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    farmId: FARM_ID,
    userId: USER_ID,
  });
  await assert.rejects(
    verifySession(token, {
      rootKey: f.rootPublicKey,
      audience: "some-other-service",
      enforceCertExpiry: false,
      isRevoked: neverRevoked,
    }),
  );
});

test("password hash verifies the correct password and rejects a wrong one", async () => {
  const hash = await hashPassword("correct horse battery staple");
  assert.equal(await verifyPassword("correct horse battery staple", hash), true);
  assert.equal(await verifyPassword("Tr0ub4dour", hash), false);
});
