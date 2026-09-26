import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { generateKeyPair, exportJWK, importJWK } from "jose";
import type { JWK, KeyLike } from "jose";
import type { CloudRootKeyPair } from "./server.ts";

// The root key is the trust anchor. It must persist across restarts, so a cloud
// that comes back up still verifies certs it signed earlier. In production this
// would be a secret store / KMS; here it is a JWK file on disk.

type StoredRootKey = {
  kid: string;
  privateJwk: JWK;
};

export async function loadOrCreateRootKey(file: string): Promise<CloudRootKeyPair> {
  const existing = await readStored(file);
  if (existing) {
    const privateKey = (await importJWK(existing.privateJwk, "EdDSA")) as KeyLike;
    const publicJwk: JWK = { ...existing.privateJwk };
    delete publicJwk.d;
    const publicKey = (await importJWK(publicJwk, "EdDSA")) as KeyLike;
    return { publicKey, privateKey, kid: existing.kid };
  }

  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const kid = `root-${randomUUID()}`;
  await writeStored(file, { kid, privateJwk: await exportJWK(privateKey) });
  return { publicKey, privateKey, kid };
}

async function readStored(file: string): Promise<StoredRootKey | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as StoredRootKey;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }
}

async function writeStored(file: string, value: StoredRootKey): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(value, null, 2), "utf8");
}
