import { pathToFileURL } from "node:url";
import type { JWK } from "jose";

import { generateDeviceKeys, exportPrivateJwk } from "../core/keys.ts";
import { createStore, resolveDataDir } from "./store.ts";
import type { Store } from "./store.ts";

// The ONLY hub code that touches the network. It runs once, at install time,
// while the device is online. Everything after this — login, local access —
// works offline.

export type ProvisionConfig = {
  cloudUrl: string;
  enrollmentCode: string;
  farmId: string;
  store: Store;
};

export type ProvisionResult = {
  deviceId: string;
  farmId: string;
};

type ProvisionResponse = {
  deviceId: string;
  deviceCert: string;
  rootJwk: JWK;
};

export async function provisionDevice(config: ProvisionConfig): Promise<ProvisionResult> {
  // 1. Generate the device key pair. The private key never leaves the device.
  const keys = await generateDeviceKeys();

  // 2. Send the public key and the one-time enrollment code to the cloud.
  const res = await fetch(new URL("/provision", config.cloudUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      enrollmentCode: config.enrollmentCode,
      farmId: config.farmId,
      publicJwk: keys.publicJwk,
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`provision failed: ${res.status} ${detail}`);
  }

  const body = (await res.json()) as ProvisionResponse;

  // 3. Persist the identity: private key, cert, and pinned root key.
  const privateJwk = await exportPrivateJwk(keys.privateKey);
  await config.store.saveDeviceIdentity({
    deviceId: body.deviceId,
    farmId: config.farmId,
    privateJwk,
    deviceCert: body.deviceCert,
    rootJwk: body.rootJwk,
  });

  return { deviceId: body.deviceId, farmId: config.farmId };
}

// CLI entry: node src/hub/provision.ts
async function main() {
  const cloudUrl = process.env.HORIZON_CLOUD_URL ?? "http://127.0.0.1:8081";
  const enrollmentCode = process.env.HORIZON_ENROLLMENT_CODE ?? "enroll-dev-code";
  const farmId = process.env.HORIZON_FARM_ID ?? "farm-42";

  const store = createStore(resolveDataDir());
  const result = await provisionDevice({ cloudUrl, enrollmentCode, farmId, store });

  console.log(`[provision] device provisioned: ${result.deviceId} for ${result.farmId}`);
  console.log(`[provision] identity stored in ${store.dataDir}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`[provision] error: ${(err as Error).message}`);
    process.exit(1);
  });
}
