import { createCloudServer } from "./server.ts";

const port = Number(process.env.HORIZON_CLOUD_PORT ?? 8081);
const enrollmentCode = process.env.HORIZON_ENROLLMENT_CODE ?? "enroll-dev-code";

const cloud = await createCloudServer({ port, enrollmentCode });

console.log(`[cloud] listening on http://127.0.0.1:${cloud.port()}`);
console.log(`[cloud] root kid: ${cloud.rootKeyPair.kid}`);
console.log(`[cloud] enrollment code: ${enrollmentCode}`);
console.log("[cloud] endpoints: POST /provision, GET /.well-known/jwks.json, GET /farms/:farmId/reports");

const shutdown = () => {
  cloud.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
