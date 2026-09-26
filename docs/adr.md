# PLAN: Horizon offline-capable authentication (PoC)

Part 2 of the Lely Software Architect take-home. Build a small, self-contained proof of concept of session issuance and verification that:

- works when the farm device (Hub or legacy Windows desktop) has no connectivity;
- produces a session that Lely's cloud can verify later, without a live round trip to an IdP.

Keep it small. We evaluate the soundness of the mechanism and the clarity of the code, not infrastructure. Do not over-engineer.

## 1. Mechanism: delegated signing

Do not derive or copy a private key from the cloud IdP. If every farm holds a key that comes from the IdP secret, one compromised farm can forge sessions for all farms.

Use a trust chain instead:

1. **Installation (online, once):** The device generates its own Ed25519 key pair. The private key never leaves the device.
2. The device sends its public key and a one-time enrollment code to the cloud (`POST /provision`).
3. The cloud signs a **device certificate**: a JWT that binds `deviceId + farmId + device public key`. The cloud root key signs it. The device stores the certificate and pins the cloud root public key.
4. **Login (offline):** The device verifies the password locally and signs a session JWT with the device private key. It embeds the device certificate in the JWT header.
5. **Verification (anywhere):** The pinned root key verifies the device certificate. The public key in the certificate verifies the session. No IdP call is necessary.

The blast radius of a compromised device is one farm. The cloud can revoke a device by device ID.

```
cloud root key ──signs──▶ device cert {farm_id, cnf.jwk} ──key in cert verifies──▶ session token
```

## 2. Stack

- **Runtime:** Node 24 LTS. Run `.ts` files directly (type stripping, no build step).
  - tsconfig: `"erasableSyntaxOnly": true`, `"allowImportingTsExtensions": true`, `"noEmit": true`, `"module": "nodenext"`, `"strict": true`.
  - Do not use enums or parameter properties. Use the `.ts` extension in imports.
  - Typecheck with `tsc --noEmit`, which is a dev dependency only.
- **Runtime dependency:** `jose` only, for JWS/JWT with EdDSA. Do not hand-roll JWT.
- **Built-ins:** `node:http` (no framework), `node:crypto` (scrypt, randomUUID), `node:fs/promises`, `node:path`.
- **Tests:** `node:test` and `node:assert/strict`. Use `mock.method` and `mock.timers`.
- **Style:** Functional. Use pure functions in `core/` and factories for the servers. Use classes only if a library requires them.
- **Cross-platform:** It must run on Windows and Linux.
  - Use `node:path` for all paths.
  - Do not use shell-specific npm scripts.
  - Take the data directory from the `HORIZON_DATA_DIR` env var, with `os.tmpdir()`-based defaults in tests.

## 3. Structure

One package. Do not use workspaces.

```
horizon-auth-poc/
  package.json          # "type": "module"
  tsconfig.json
  .github/workflows/ci.yml   # matrix: ubuntu-latest, windows-latest; npm ci, typecheck, test
  src/
    core/               # pure functions, no I/O, shared by both services
      keys.ts           # generateDeviceKeys, export/import JWK
      device-cert.ts    # issueDeviceCert (cloud), verifyDeviceCert
      session.ts        # issueSession (hub), verifySession (both)
      passwords.ts      # hashPassword, verifyPassword (scrypt, timingSafeEqual)
    hub/
      server.ts         # createHubServer(config): POST /login, GET /local/cows
      provision.ts      # install-time step; the ONLY hub code that uses the network
      store.ts          # read/write: device private key, device cert, root JWK, users
      seed-users.ts     # CLI: add a user with a scrypt hash
      main.ts           # reads env, calls listen
    cloud/
      server.ts         # createCloudServer(config): POST /provision,
                        # GET /.well-known/jwks.json, GET /farms/:farmId/reports
      main.ts
  test/
    core.test.ts
    e2e.test.ts
  README.md
```

Rules:

- The server factories return `{ server, close }` and accept `port: 0` in tests. Only `main.ts` calls `listen` with a fixed port.
- `createCloudServer` accepts an optional root key pair, so a test can restart the cloud with the same key. It also exposes `revokeDevice(deviceId)` for tests. Keep the revocation list in memory.
- The enrollment code comes from config or env. It is one-time use, so a second use returns 401.
- `hub/server.ts` must not import any HTTP client and must not receive a cloud URL.

## 4. Token formats

**Device certificate.** Protected header: `{ alg: "EdDSA", typ: "device-cert+jwt", kid: <root kid> }`.

```json
{
  "iss": "lely-cloud",
  "sub": "dev-123",
  "farm_id": "farm-42",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } },
  "iat": 0,
  "exp": 0
}
```

**Session token.** Protected header: `{ alg: "EdDSA", typ: "JWT", dcert: "<device cert JWT>" }`.

```json
{
  "iss": "device:dev-123",
  "sub": "user-7",
  "farm_id": "farm-42",
  "aud": ["horizon-local", "horizon-cloud"],
  "jti": "<uuid>",
  "iat": 0,
  "exp": 0
}
```

## 5. Verification: one function, two policies

```ts
verifySession(token, {
  rootKey,            // pinned cloud root public key
  audience,           // "horizon-local" | "horizon-cloud"
  enforceCertExpiry,  // hub: false, cloud: true
  isRevoked,          // (deviceId) => boolean; hub: () => false
  currentDate?,       // for tests
})
```

`verifySession` runs these steps in order and stops at the first failure:

1. Read `dcert` from the protected header. If it is absent, reject.
2. Verify `dcert` with `rootKey`. Require `iss === "lely-cloud"` and `typ === "device-cert+jwt"`. Check `exp` only if `enforceCertExpiry` is true.
3. Import the device key from `cnf.jwk`.
4. Verify the session with the device key. Check the signature, `exp`, and `aud`, with a clock tolerance of 300 s. Require `iss === "device:" + cert.sub`.
5. Require `session.farm_id === cert.farm_id`.
6. If `isRevoked(cert.sub)` returns true, reject.
7. Return `{ userId, farmId, deviceId }`.

Resource handlers also require `farmId === route farmId`. If it does not match, return 403. Failed verification returns 401.

## 6. Flows

- **Provision (hub, online):**
  1. Generate the key pair.
  2. `POST /provision { enrollmentCode, farmId, publicJwk }`. The response is `{ deviceId, deviceCert, rootJwk }`.
  3. Persist the key pair, `deviceCert`, and `rootJwk` to the store.
- **Login (hub, offline):**
  1. `POST /login { username, password }`.
  2. Verify the password against the scrypt hash in the store.
  3. Issue a session with a 12 h lifetime.
  4. Return `{ token }`.
- **Local resource:** `GET /local/cows` with `Authorization: Bearer <token>`. The hub verifies with the hub policy.
- **Cloud resource:** `GET /farms/:farmId/reports` with `Authorization: Bearer <token>`. The cloud verifies with the cloud policy.

## 7. Emulating network absence

- **By design:** The hub login path has no network dependency. `provision.ts` is the only network caller.
- **In tests:**
  1. Provision while the cloud runs, then `await cloud.close()`. Now a real request gets `ECONNREFUSED`.
  2. Replace `globalThis.fetch` with `mock.method` so it throws. Assert `fetch.mock.callCount() === 0` after login and local access. This zero-call assertion is the proof.
- **Optional manual demo (Linux only, not in CI):** `docker run --network none`. Document it in the README only.

## 8. Tests

### `test/core.test.ts`

Test the pure functions with no HTTP:

- A valid session verifies under both policies.
- A tampered payload is rejected.
- A self-generated key pair with a self-signed "cert" is rejected, because the root key does not match.
- An expired session is rejected. Use `mock.timers.enable({ apis: ["Date"] })`.
- An expired device cert is rejected by the cloud policy and accepted by the hub policy.
- A session `farm_id` that does not match the cert `farm_id` is rejected.
- A revoked device is rejected by the cloud policy.
- A token with no `dcert` header is rejected.
- A wrong audience is rejected.
- Password hash and verify: the correct password passes and a wrong password fails.

### `test/e2e.test.ts`

Test the full flow over HTTP on `127.0.0.1` with port 0:

1. **Offline login and local access:**
   1. Start the cloud and provision the hub.
   2. Stop the cloud and stub fetch.
   3. Log in and expect 200.
   4. Call `GET /local/cows` and expect 200.
   5. Assert 0 fetch calls.
2. **Cloud verification of an offline-issued token:**
   1. Issue the token while the cloud is down.
   2. Restart the cloud with the same root key.
   3. Call `GET /farms/farm-42/reports` and expect 200.
3. **Negative cases:**
   - A wrong password returns 401.
   - No token returns 401.
   - A tampered token returns 401 on the hub and 401 in the cloud.
   - A `farm-42` token on `/farms/farm-99/reports` returns 403.
   - A revoked device returns 401 in the cloud and still returns 200 on the hub.
   - A reused enrollment code returns 401.

Use a temporary data dir per test and remove it afterward.

## 9. Milestones

Work in this order. Finish each milestone with green tests before you start the next.

1. **Scaffold:** `package.json`, tsconfig, and the scripts:
   - `"test": "node --test \"test/**/*.test.ts\""`
   - `"typecheck": "tsc --noEmit"`
   - `"cloud": "node src/cloud/main.ts"`
   - `"hub": "node src/hub/main.ts"`
   - `"provision": "node src/hub/provision.ts"`
   - `"seed-user": "node src/hub/seed-users.ts"`

   Also add the CI workflow.

2. `core/` and `core.test.ts`.
3. The cloud server.
4. The hub store, provisioning, and the seed-user CLI.
5. The hub server and `e2e.test.ts`.
6. `README.md`, with these sections:
   - Run steps: install, start the cloud, provision, seed a user, start the hub, run curl examples, run the tests.
   - A short mechanism explanation with the diagram from section 1.
   - Trade-offs (section 10).
   - Open questions (section 11).
   - AI-use note (section 12).

**Definition of done:** `npm run typecheck` and `npm test` pass on Ubuntu and Windows in CI.

## 10. Decisions and trade-offs

| Decision                                                    | Choice                                                                   | Reason                                                                            |
| ----------------------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| Key type                                                    | Ed25519 (EdDSA)                                                          | Small keys, fast, deterministic signatures, supported by `jose` and `node:crypto` |
| Session lifetime                                            | 12 h                                                                     | One farm shift                                                                    |
| Device cert lifetime                                        | 1 year, renew when online and < 30 days remain (renewal not implemented) | Matches the 1-year durability window in the design memo                           |
| Cert expiry on hub                                          | Not enforced                                                             | A farm that is offline for a long time must not lock the farmer out               |
| Cert format                                                 | JWT, not X.509                                                           | Smaller PoC. Same trust model as an intermediate CA                               |
| Cert transport                                              | Embedded in the session header (`dcert`)                                 | Cloud verification stays stateless, apart from revocation                         |
| **Rejected:** a cloud registry of device public keys        | —                                                                        | Works, but needs a DB lookup on every verification                                |
| **Rejected:** a shared secret or a key derived from the IdP | —                                                                        | One compromised farm could forge sessions for all farms                           |
| **Rejected:** OS-level network isolation in tests           | —                                                                        | Not cross-platform, and needs root                                                |

## 11. Out of scope (list as open questions in Part 3)

- **Hardware key protection:** TPM on the Hub, TPM or DPAPI on Windows. The PoC stores keys as files in the data dir.
- **Credential distribution:** How user credentials reach the farm, for example synced from the cloud or created locally.
- **Session refresh:** Silent refresh and re-issue of sessions.
- **Farm clock drift:** Drift while offline, and the tolerance the cloud accepts.
- **Revocation delivery:** How revocation reaches the hub. The PoC checks revocation only in the cloud.
- **Roles and scopes:** Roles, scopes, and RBAC. The design memo assumes one role.
- **Cert renewal:** The certificate renewal endpoint.

## 12. AI-use note (for README)

- The plan was drafted with Claude from the design memo and refined by the author.
- The implementation was done with Claude Code, milestone by milestone.
- The author steered and verified the output as follows: Oleksandr Starnikov.
