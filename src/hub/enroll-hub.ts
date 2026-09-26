import { pathToFileURL } from "node:url";
import type { JWK } from "jose";

import { generateDeviceKeys, exportPrivateJwk } from "../core/keys.ts";
import { createStore, resolveDataDir } from "./store.ts";
import type { Store } from "./store.ts";

// The ONLY hub code that touches the network. It runs once, at install time,
// while the device is online. Everything after this — issuing sessions — works
// offline.

export type EnrollHubConfig = {
  cloudUrl: string;
  enrollmentCode: string;
  store: Store;
};

export type EnrollHubResult = {
  deviceId: string;
};

type EnrollHubResponse = {
  deviceId: string;
  deviceCert: string;
  rootJwk: JWK;
};

export async function enrollHub(config: EnrollHubConfig): Promise<EnrollHubResult> {
  // 1. Generate the device key pair. The private key never leaves the device.
  const keys = await generateDeviceKeys();

  // 2. Send the public key and the one-time enrollment code to the cloud.
  const res = await fetch(new URL("/enroll-hub", config.cloudUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      enrollmentCode: config.enrollmentCode,
      publicJwk: keys.publicJwk,
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`enroll-hub failed: ${res.status} ${detail}`);
  }

  const body = (await res.json()) as EnrollHubResponse;

  // 3. Persist the identity: private key, cert, and pinned root key.
  const privateJwk = await exportPrivateJwk(keys.privateKey);
  await config.store.saveDeviceIdentity({
    deviceId: body.deviceId,
    privateJwk,
    deviceCert: body.deviceCert,
    rootJwk: body.rootJwk,
  });

  return { deviceId: body.deviceId };
}

// CLI entry: node src/hub/enroll-hub.ts
async function main() {
  const cloudUrl = process.env.HORIZON_CLOUD_URL ?? "http://127.0.0.1:8081";
  const enrollmentCode = process.env.HORIZON_ENROLLMENT_CODE ?? "enroll-dev-code";

  const store = createStore(resolveDataDir());
  const result = await enrollHub({ cloudUrl, enrollmentCode, store });

  console.log(`[enroll-hub] device enrolled: ${result.deviceId}`);
  console.log(`[enroll-hub] identity stored in ${store.dataDir}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`[enroll-hub] error: ${(err as Error).message}`);
    process.exit(1);
  });
}
