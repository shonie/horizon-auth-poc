import { createHubServer } from "./server.ts";
import { createStore, resolveDataDir } from "./store.ts";

const port = Number(process.env.HORIZON_HUB_PORT ?? 8080);
const store = createStore(resolveDataDir());

const hub = await createHubServer({ port, store });

console.log(`[hub] listening on http://127.0.0.1:${hub.port()}`);
console.log(`[hub] data dir: ${store.dataDir}`);
console.log("[hub] endpoints: POST /login, GET /local/cows");

const shutdown = () => {
  hub.close().then(() => process.exit(0));
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
