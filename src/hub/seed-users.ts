import { pathToFileURL } from "node:url";

import { hashPassword } from "../core/passwords.ts";
import { createStore, resolveDataDir } from "./store.ts";

// CLI: add (or update) a user with a scrypt password hash.
//   node src/hub/seed-users.ts <username> <password>
async function main() {
  const [username, password] = process.argv.slice(2);
  if (!username || !password) {
    console.error("usage: node src/hub/seed-users.ts <username> <password>");
    process.exit(2);
  }

  const store = createStore(resolveDataDir());
  const passwordHash = await hashPassword(password);
  await store.upsertUser({ username, passwordHash });

  console.log(`[seed-user] stored user "${username}" in ${store.dataDir}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`[seed-user] error: ${(err as Error).message}`);
    process.exit(1);
  });
}
