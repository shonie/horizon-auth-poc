import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);

const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

// Stored format: scrypt$<saltHex>$<hashHex>
const PREFIX = "scrypt";

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_LENGTH);
  const derived = (await scryptAsync(password, salt, KEY_LENGTH)) as Buffer;
  return `${PREFIX}$${salt.toString("hex")}$${derived.toString("hex")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== PREFIX) {
    return false;
  }
  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");
  const derived = (await scryptAsync(password, salt, expected.length)) as Buffer;
  if (derived.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(derived, expected);
}
