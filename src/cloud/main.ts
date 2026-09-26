import { createCloudServer } from "./server.ts";
import { loadOrCreateRootKey } from "./root-key.ts";

const port = Number(process.env.HORIZON_CLOUD_PORT ?? 8081);
const enrollmentCode = process.env.HORIZON_ENROLLMENT_CODE ?? "enroll-dev-code";
// When set, the root key persists to this file so it survives restarts.
const rootKeyFile = process.env.HORIZON_ROOT_KEY_FILE;
const rootKeyPair = rootKeyFile ? await loadOrCreateRootKey(rootKeyFile) : undefined;
const host = process.env.HORIZON_BIND_HOST;

const cloud = await createCloudServer({ port, enrollmentCode, rootKeyPair, host });

console.log(`[cloud] listening on http://127.0.0.1:${cloud.port()}`);
console.log(`[cloud] root kid: ${cloud.rootKeyPair.kid}`);
console.log(`[cloud] enrollment code: ${enrollmentCode}`);
console.log("[cloud] endpoints: POST /enroll-hub, GET /.well-known/jwks.json, GET /whoami");

const shutdown = () => {
  cloud.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
