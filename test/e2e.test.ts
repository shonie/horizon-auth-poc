import { test, mock } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";

import { createCloudServer } from "../src/cloud/server.ts";
import { createHubServer } from "../src/hub/server.ts";
import { createStore } from "../src/hub/store.ts";
import { provisionDevice } from "../src/hub/provision.ts";
import { hashPassword } from "../src/core/passwords.ts";

const ENROLLMENT_CODE = "enroll-test-code";
const FARM_ID = "farm-42";
const USERNAME = "farmer-joe";
const PASSWORD = "green-pastures-42";

type Response = { status: number; json: any };

// Test HTTP client built on node:http, so it never touches globalThis.fetch
// (the offline test stubs fetch and asserts zero calls).
function request(
  port: number,
  method: string,
  reqPath: string,
  opts: { token?: string; body?: unknown } = {},
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const data = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    const headers: Record<string, string> = {};
    if (data) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(Buffer.byteLength(data));
    }
    if (opts.token) {
      headers["authorization"] = `Bearer ${opts.token}`;
    }
    const req = http.request({ host: "127.0.0.1", port, path: reqPath, method, headers }, (res) => {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (raw += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, json: raw ? JSON.parse(raw) : undefined }));
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function makeDataDir(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), "horizon-e2e-"));
}

// Bring up a cloud, provision a hub against it, and seed one user.
async function setup() {
  const dataDir = await makeDataDir();
  const store = createStore(dataDir);
  await store.upsertUser({ username: USERNAME, passwordHash: await hashPassword(PASSWORD) });

  const cloud = await createCloudServer({ port: 0, enrollmentCode: ENROLLMENT_CODE });
  await provisionDevice({
    cloudUrl: `http://127.0.0.1:${cloud.port()}`,
    enrollmentCode: ENROLLMENT_CODE,
    farmId: FARM_ID,
    store,
  });

  return { dataDir, store, cloud };
}

async function cleanup(dataDir: string, servers: Array<{ close: () => Promise<void> }>) {
  for (const s of servers) {
    await s.close().catch(() => {});
  }
  await rm(dataDir, { recursive: true, force: true });
}

test("offline login and local access make zero network calls", async () => {
  const { dataDir, store, cloud } = await setup();
  const hub = await createHubServer({ port: 0, store });

  try {
    // Stop the cloud so a real request would get ECONNREFUSED.
    await cloud.close();

    // Stub fetch so any network attempt throws — and count the calls.
    const fetchMock = mock.method(globalThis, "fetch", () => {
      throw new Error("network is down");
    });

    try {
      const login = await request(hub.port(), "POST", "/login", {
        body: { username: USERNAME, password: PASSWORD },
      });
      assert.equal(login.status, 200);
      const token = login.json.token as string;
      assert.ok(token);

      const cows = await request(hub.port(), "GET", "/local/cows", { token });
      assert.equal(cows.status, 200);
      assert.equal(cows.json.farmId, FARM_ID);

      // The proof: the hub made no network calls.
      assert.equal(fetchMock.mock.callCount(), 0);
    } finally {
      fetchMock.mock.restore();
    }
  } finally {
    await cleanup(dataDir, [hub]);
  }
});

test("the cloud verifies a token issued while it was offline", async () => {
  const { dataDir, store, cloud } = await setup();
  const hub = await createHubServer({ port: 0, store });
  const rootKeyPair = cloud.rootKeyPair;

  try {
    // Issue the token while the cloud is down.
    await cloud.close();
    const login = await request(hub.port(), "POST", "/login", {
      body: { username: USERNAME, password: PASSWORD },
    });
    assert.equal(login.status, 200);
    const token = login.json.token as string;

    // Restart the cloud with the SAME root key.
    const cloud2 = await createCloudServer({ port: 0, enrollmentCode: ENROLLMENT_CODE, rootKeyPair });
    try {
      const reports = await request(cloud2.port(), "GET", `/farms/${FARM_ID}/reports`, { token });
      assert.equal(reports.status, 200);
      assert.equal(reports.json.farmId, FARM_ID);
    } finally {
      await cloud2.close();
    }
  } finally {
    await cleanup(dataDir, [hub]);
  }
});

test("negative cases: bad credentials, missing/tampered token, wrong farm, revocation, reused code", async () => {
  const { dataDir, store, cloud } = await setup();
  const hub = await createHubServer({ port: 0, store });

  try {
    // A wrong password returns 401.
    const badLogin = await request(hub.port(), "POST", "/login", {
      body: { username: USERNAME, password: "wrong" },
    });
    assert.equal(badLogin.status, 401);

    // No token returns 401 on both services.
    assert.equal((await request(hub.port(), "GET", "/local/cows", {})).status, 401);
    assert.equal((await request(cloud.port(), "GET", `/farms/${FARM_ID}/reports`, {})).status, 401);

    // A good token to work from.
    const login = await request(hub.port(), "POST", "/login", {
      body: { username: USERNAME, password: PASSWORD },
    });
    assert.equal(login.status, 200);
    const token = login.json.token as string;

    // A tampered token returns 401 on the hub and in the cloud.
    const [h, p, s] = token.split(".");
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    claims.sub = "attacker";
    const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
    assert.equal((await request(hub.port(), "GET", "/local/cows", { token: tampered })).status, 401);
    assert.equal((await request(cloud.port(), "GET", `/farms/${FARM_ID}/reports`, { token: tampered })).status, 401);

    // A farm-42 token on /farms/farm-99/reports returns 403.
    const wrongFarm = await request(cloud.port(), "GET", "/farms/farm-99/reports", { token });
    assert.equal(wrongFarm.status, 403);

    // A revoked device returns 401 in the cloud and still 200 on the hub.
    const identity = await store.loadDeviceIdentity();
    assert.ok(identity);
    cloud.revokeDevice(identity.deviceId);
    assert.equal((await request(cloud.port(), "GET", `/farms/${FARM_ID}/reports`, { token })).status, 401);
    assert.equal((await request(hub.port(), "GET", "/local/cows", { token })).status, 200);

    // A reused enrollment code returns 401.
    const reuse = await request(cloud.port(), "POST", "/provision", {
      body: { enrollmentCode: ENROLLMENT_CODE, farmId: FARM_ID, publicJwk: identity.rootJwk },
    });
    assert.equal(reuse.status, 401);
  } finally {
    await cleanup(dataDir, [hub, cloud]);
  }
});
