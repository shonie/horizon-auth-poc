import { generateKeyPair, exportJWK, importJWK } from "jose";
import type { JWK, KeyLike } from "jose";

// Ed25519 key pair. The private key never leaves the device that generated it.
export type KeyPair = {
  publicKey: KeyLike;
  privateKey: KeyLike;
  publicJwk: JWK;
};

export async function generateDeviceKeys(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  return { publicKey, privateKey, publicJwk };
}

export async function exportPrivateJwk(privateKey: KeyLike): Promise<JWK> {
  return exportJWK(privateKey);
}

export async function importPrivateKey(jwk: JWK): Promise<KeyLike> {
  return (await importJWK(jwk, "EdDSA")) as KeyLike;
}

export async function importPublicKey(jwk: JWK): Promise<KeyLike> {
  return (await importJWK(jwk, "EdDSA")) as KeyLike;
}
