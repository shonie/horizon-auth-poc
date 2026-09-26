import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import type { JWK } from "jose";

// The hub persists its identity and its users as two JSON files in the data dir.
// In production these files would sit behind hardware key protection (see the
// open questions); the PoC stores them as plain files.

export type DeviceIdentity = {
  deviceId: string;
  farmId: string;
  privateJwk: JWK;
  deviceCert: string;
  rootJwk: JWK;
};

export type StoredUser = {
  username: string;
  passwordHash: string;
};

export type Store = {
  dataDir: string;
  saveDeviceIdentity: (identity: DeviceIdentity) => Promise<void>;
  loadDeviceIdentity: () => Promise<DeviceIdentity | null>;
  upsertUser: (user: StoredUser) => Promise<void>;
  getUser: (username: string) => Promise<StoredUser | null>;
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
  const usersFile = path.join(dataDir, "users.json");

  return {
    dataDir,

    async saveDeviceIdentity(identity) {
      await writeJsonFile(deviceFile, identity);
    },

    async loadDeviceIdentity() {
      return readJsonFile<DeviceIdentity>(deviceFile);
    },

    async upsertUser(user) {
      const users = (await readJsonFile<Record<string, StoredUser>>(usersFile)) ?? {};
      users[user.username] = user;
      await writeJsonFile(usersFile, users);
    },

    async getUser(username) {
      const users = (await readJsonFile<Record<string, StoredUser>>(usersFile)) ?? {};
      return users[username] ?? null;
    },
  };
}

// Resolves the data dir from the environment. main.ts and the CLIs use this;
// tests pass a temp dir straight to createStore.
export function resolveDataDir(): string {
  const fromEnv = process.env.HORIZON_DATA_DIR;
  if (fromEnv && fromEnv.length > 0) {
    return fromEnv;
  }
  return path.join(process.cwd(), "data");
}
