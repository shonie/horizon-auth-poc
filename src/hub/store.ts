import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import type { JWK } from "jose";

// The hub persists its device identity as a JSON file in the data dir. In
// production these files would sit behind hardware key protection (see the open
// questions); the PoC stores them as plain files.

export type DeviceIdentity = {
  deviceId: string;
  privateJwk: JWK;
  deviceCert: string;
  rootJwk: JWK;
};

export type Store = {
  dataDir: string;
  saveDeviceIdentity: (identity: DeviceIdentity) => Promise<void>;
  loadDeviceIdentity: () => Promise<DeviceIdentity | null>;
};

async function readJsonFile<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }
}

async function writeJsonFile(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(value, null, 2), "utf8");
}

export function createStore(dataDir: string): Store {
  const deviceFile = path.join(dataDir, "device.json");

  return {
    dataDir,

    async saveDeviceIdentity(identity) {
      await writeJsonFile(deviceFile, identity);
    },

    async loadDeviceIdentity() {
      return readJsonFile<DeviceIdentity>(deviceFile);
    },
  };
}

// Resolves the data dir from the environment. main.ts and provision use this;
// tests pass a temp dir straight to createStore.
export function resolveDataDir(): string {
  const fromEnv = process.env.HORIZON_DATA_DIR;
  if (fromEnv && fromEnv.length > 0) {
    return fromEnv;
  }
  return path.join(process.cwd(), "data");
}
