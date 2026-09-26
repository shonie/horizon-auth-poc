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

const ENROLLMENT_CODE = "enroll-test-code";
const USER_ID = "user-7";

type HttpResponse = {
  status: number;
  json: any;
};

type RequestOptions = {
  token?: string;
  body?: unknown;
};

// Test HTTP client built on node:http, so it never touches globalThis.fetch
// (the offline test stubs fetch and asserts zero calls).
function request(
  port: number,
  method: string,
  reqPath: string,
  opts: RequestOptions = {},
): Promise<HttpResponse> {
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

type Closable = {
  close: () => Promise<void>;
};

// Bring up a cloud and provision a hub against it.
async function setup() {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "horizon-e2e-"));
  const store = createStore(dataDir);

  const cloud = await createCloudServer({ port: 0, enrollmentCode: ENROLLMENT_CODE });
  await provisionDevice({
    cloudUrl: `http://127.0.0.1:${cloud.port()}`,
    enrollmentCode: ENROLLMENT_CODE,
    store,
  });

  return { dataDir, store, cloud };
}

async function cleanup(dataDir: string, servers: Closable[]) {
  for (const s of servers) {
    await s.close().catch(() => {});
  }
  await rm(dataDir, { recursive: true, force: true });
}

test("a session issued offline is verified later by the cloud", async () => {
  const { dataDir, store, cloud } = await setup();
  const hub = await createHubServer({ port: 0, store });
  const rootKeyPair = cloud.rootKeyPair;

  try {
    // Stop the cloud so a real request would get ECONNREFUSED, and stub fetch
    // so any network attempt throws — and is counted.
    await cloud.close();
    const fetchMock = mock.method(globalThis, "fetch", () => {
      throw new Error("network is down");
    });

    let token: string;
    try {
      const issued = await request(hub.port(), "POST", "/session", { body: { userId: USER_ID } });
      assert.equal(issued.status, 200);
      token = issued.json.token as string;
      assert.ok(token);

      // The proof: issuing the session made no network calls.
      assert.equal(fetchMock.mock.callCount(), 0);
    } finally {
      fetchMock.mock.restore();
    }

    // Restart the cloud with the SAME root key, then verify the offline token.
    const cloud2 = await createCloudServer({ port: 0, enrollmentCode: ENROLLMENT_CODE, rootKeyPair });
    try {
      const who = await request(cloud2.port(), "GET", "/whoami", { token });
      assert.equal(who.status, 200);
      assert.deepEqual(who.json, { userId: USER_ID, deviceId: (await store.loadDeviceIdentity())?.deviceId });
    } finally {
      await cloud2.close();
    }
  } finally {
    await cleanup(dataDir, [hub]);
  }
});

test("negative cases: no token, tampered token, reused enrollment code", async () => {
  const { dataDir, store, cloud } = await setup();
  const hub = await createHubServer({ port: 0, store });

  try {
    // No token returns 401.
    assert.equal((await request(cloud.port(), "GET", "/whoami", {})).status, 401);

    // A tampered token returns 401.
    const issued = await request(hub.port(), "POST", "/session", { body: { userId: USER_ID } });
    const token = issued.json.token as string;
    const [h, p, s] = token.split(".");
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    claims.sub = "attacker";
    const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
    assert.equal((await request(cloud.port(), "GET", "/whoami", { token: tampered })).status, 401);

    // A reused enrollment code returns 401.
    const identity = await store.loadDeviceIdentity();
    assert.ok(identity);
    const reuse = await request(cloud.port(), "POST", "/provision", {
      body: { enrollmentCode: ENROLLMENT_CODE, publicJwk: identity.rootJwk },
    });
    assert.equal(reuse.status, 401);
  } finally {
    await cleanup(dataDir, [hub, cloud]);
  }
});
