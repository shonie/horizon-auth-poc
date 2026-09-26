import { test } from "node:test";
import assert from "node:assert/strict";

// Black-box integration tests. They know nothing about connectivity: they just
// talk to a hub and a cloud over HTTP at the URLs given in the environment. The
// SAME suite runs against the online and offline compose setups; the setup —
// including enrollment — is provided by the environment, not by the tests.
const HUB_URL = process.env.HUB_URL ?? "http://127.0.0.1:8080";
const CLOUD_URL = process.env.CLOUD_URL ?? "http://127.0.0.1:8081";
const USER_ID = "user-7";

// Issues a session at the local hub URL.
async function issueSession(): Promise<string> {
  const res = await fetch(`${HUB_URL}/session`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userId: USER_ID }),
  });
  assert.equal(res.status, 200);
  const { token } = (await res.json()) as { token: string };
  return token;
}

// Verify a session by calling /whoami on the cloud.
function whoami(token?: string): Promise<Response> {
  return fetch(`${CLOUD_URL}/whoami`, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

test("the hub issues a session and the cloud verifies it", async () => {
  const token = await issueSession();

  const res = await whoami(token);
  assert.equal(res.status, 200);
  const principal = (await res.json()) as { userId: string; deviceId: string };
  assert.equal(principal.userId, USER_ID);
  assert.ok(principal.deviceId);
});

test("the cloud rejects a missing or tampered token", async () => {
  assert.equal((await whoami()).status, 401);

  const token = await issueSession();
  const [h, p, s] = token.split(".");
  const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  claims.sub = "attacker";
  const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;

  assert.equal((await whoami(tampered)).status, 401);
});
