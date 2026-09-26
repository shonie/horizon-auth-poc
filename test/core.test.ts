import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "jose";
import type { KeyLike } from "jose";

import { generateDeviceKeys } from "../src/core/keys.ts";
import { issueDeviceCert } from "../src/core/device-cert.ts";
import { issueSession, verifySession } from "../src/core/session.ts";

const ROOT_KID = "root-1";
const DEVICE_ID = "dev-123";
const USER_ID = "user-7";

type RootKeyPair = {
  rootPublicKey: KeyLike;
  rootPrivateKey: KeyLike;
};

async function makeRoot(): Promise<RootKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  return { rootPublicKey: publicKey, rootPrivateKey: privateKey };
}

type Fixture = {
  rootPublicKey: KeyLike;
  devicePrivateKey: KeyLike;
  deviceCert: string;
};

async function makeFixture(): Promise<Fixture> {
  const { rootPublicKey, rootPrivateKey } = await makeRoot();
  const device = await generateDeviceKeys();
  const deviceCert = await issueDeviceCert({
    rootPrivateKey,
    rootKid: ROOT_KID,
    deviceId: DEVICE_ID,
    devicePublicJwk: device.publicJwk,
  });
  return { rootPublicKey, devicePrivateKey: device.privateKey, deviceCert };
}

test("a valid session verifies against the pinned root key", async () => {
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    userId: USER_ID,
  });

  const result = await verifySession(token, { rootKey: f.rootPublicKey });
  assert.deepEqual(result, { userId: USER_ID, deviceId: DEVICE_ID });
});

test("a session whose cert was signed by a different root is rejected", async () => {
  // The core security property: without the real root key you cannot forge a
  // cert, so a self-signed chain does not verify.
  const attackerRoot = await makeRoot();
  const device = await generateDeviceKeys();
  const forgedCert = await issueDeviceCert({
    rootPrivateKey: attackerRoot.rootPrivateKey,
    rootKid: ROOT_KID,
    deviceId: DEVICE_ID,
    devicePublicJwk: device.publicJwk,
  });
  const token = await issueSession({
    devicePrivateKey: device.privateKey,
    deviceCert: forgedCert,
    deviceId: DEVICE_ID,
    userId: USER_ID,
  });

  const realRoot = await makeRoot();
  await assert.rejects(verifySession(token, { rootKey: realRoot.rootPublicKey }));
});

test("a tampered session payload is rejected", async () => {
  const f = await makeFixture();
  const token = await issueSession({
    devicePrivateKey: f.devicePrivateKey,
    deviceCert: f.deviceCert,
    deviceId: DEVICE_ID,
    userId: USER_ID,
  });

  const [h, p, s] = token.split(".");
  const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  claims.sub = "attacker";
  const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;

  await assert.rejects(verifySession(tampered, { rootKey: f.rootPublicKey }));
});
