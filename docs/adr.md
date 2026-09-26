# PLAN: Horizon offline-capable authentication (PoC)

Part 2 of the Lely Software Architect take-home. Build a small, self-contained proof of concept of session issuance and verification that:

- works when the farm device (Hub or legacy Windows desktop) has no connectivity;
- produces a session that Lely's cloud can verify later, without a live round trip to an IdP.

Keep it small. We evaluate the soundness of the mechanism and the clarity of the code, not infrastructure. Do not over-engineer.

## 1. Mechanism: delegated signing

Do not derive or copy a private key from the cloud IdP. If every device holds a key that comes from the IdP secret, one compromised device can forge sessions for all devices.

Use a trust chain instead:

1. **Installation (online, once):** The device generates its own Ed25519 key pair. The private key never leaves the device.
2. The device sends its public key and a one-time enrollment code to the cloud (`POST /provision`).
3. The cloud signs a **device certificate**: a JWT that binds `deviceId + device public key`. The cloud root key signs it. The device stores the certificate and pins the cloud root public key.
4. **Issue a session (offline):** The device signs a session JWT with the device private key and embeds the device certificate in the JWT header. Authenticating the user is out of scope; the caller supplies the `userId`.
5. **Verification (anywhere):** The pinned root key verifies the device certificate. The public key in the certificate verifies the session. No IdP call is necessary.

The blast radius of a compromised device is that device alone: it cannot forge sessions for any other device, because it does not hold the root key.

```
cloud root key ──signs──▶ device cert {sub: deviceId, cnf.jwk} ──key in cert verifies──▶ session token
```

## 2. Stack

- **Runtime:** Node 24 LTS. Run `.ts` files directly (type stripping, no build step).
  - tsconfig: `"erasableSyntaxOnly": true`, `"allowImportingTsExtensions": true`, `"noEmit": true`, `"module": "nodenext"`, `"strict": true`.
  - Do not use enums or parameter properties. Use the `.ts` extension in imports.
  - Typecheck with `tsc --noEmit`, which is a dev dependency only.
- **Runtime dependency:** `jose` only, for JWS/JWT with EdDSA. Do not hand-roll JWT.
- **Built-ins:** `node:http` (no framework), `node:crypto` (randomUUID), `node:fs/promises`, `node:path`.
- **Tests:** `node:test` and `node:assert/strict`. Use `mock.method`.
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
    hub/
      server.ts         # createHubServer(config): POST /session
      provision.ts      # install-time step; the ONLY hub code that uses the network
      store.ts          # read/write: device private key, device cert, root JWK
      main.ts           # reads env, calls listen
    cloud/
      server.ts         # createCloudServer(config): POST /provision,
                        # GET /.well-known/jwks.json, GET /whoami
      main.ts
  test/
    core.test.ts
    e2e.test.ts
  README.md
```

Rules:

- The server factories return `{ server, close }` and accept `port: 0` in tests. Only `main.ts` calls `listen` with a fixed port.
- `createCloudServer` accepts an optional root key pair so the trust anchor can persist across restarts (loaded from a secret store in production; a fresh key is generated when omitted).
- The enrollment code comes from config or env. It is one-time use, so a second use returns 401.
- `hub/server.ts` must not import any HTTP client and must not receive a cloud URL.

## 4. Token formats

**Device certificate.** Protected header: `{ alg: "EdDSA", typ: "device-cert+jwt", kid: <root kid> }`.

```json
{
  "iss": "lely-cloud",
  "sub": "dev-123",
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
  "jti": "<uuid>",
  "iat": 0,
  "exp": 0
}
```

## 5. Verification

```ts
verifySession(token, {
  rootKey,       // pinned cloud root public key
  currentDate?,  // for tests
})
```

`verifySession` runs these steps in order and stops at the first failure:

1. Read `dcert` from the protected header. If it is absent, reject.
2. Verify `dcert` with `rootKey`. Require `iss === "lely-cloud"`, `typ === "device-cert+jwt"`, and `exp` in the future.
3. Import the device key from `cnf.jwk`.
4. Verify the session with the device key. Check the signature and `exp`, with a clock tolerance of 300 s. Require `iss === "device:" + cert.sub`.
5. Return `{ userId, deviceId }`.

Failed verification returns 401.

## 6. Flows

- **Provision (hub, online):**
  1. Generate the key pair.
  2. `POST /provision { enrollmentCode, publicJwk }`. The response is `{ deviceId, deviceCert, rootJwk }`.
  3. Persist the key pair, `deviceCert`, and `rootJwk` to the store.
- **Issue a session (hub, offline):**
  1. `POST /session { userId }`. Authenticating the user is out of scope.
  2. Issue a session with a 12 h lifetime, signed by the device key.
  3. Return `{ token }`.
- **Verify (cloud):** `GET /whoami` with `Authorization: Bearer <token>`. The cloud verifies against the pinned root key and returns `{ userId, deviceId }`.

## 7. Emulating network absence

- **By design:** The hub session-issuance path has no network dependency. `provision.ts` is the only network caller.
- **In tests:**
  1. Provision while the cloud runs, then `await cloud.close()`. Now a real request gets `ECONNREFUSED`.
  2. Replace `globalThis.fetch` with `mock.method` so it throws. Assert `fetch.mock.callCount() === 0` after issuing a session. This zero-call assertion is the proof.
- **Optional manual demo (Linux only, not in CI):** `docker run --network none`. Document it in the README only.

## 8. Tests

### `test/core.test.ts`

Test the pure functions with no HTTP:

- A valid session verifies against the pinned root key.
- A session whose cert was signed by a different root is rejected (you cannot forge a chain without the real root key).
- A tampered session payload is rejected.

### `test/e2e.test.ts`

Test the full flow over HTTP on `127.0.0.1` with port 0:

1. **A session issued offline is verified later by the cloud:**
   1. Start the cloud and provision the hub.
   2. Stop the cloud and stub fetch.
   3. Issue a session and expect 200; assert 0 fetch calls.
   4. Restart the cloud with the same root key.
   5. Call `GET /whoami` on the cloud and expect 200.
2. **Negative cases:**
   - No token returns 401.
   - A tampered token returns 401.
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

   Also add the CI workflow.

2. `core/` and `core.test.ts`.
3. The cloud server.
4. The hub store and provisioning.
5. The hub server and `e2e.test.ts`.
6. `README.md`, with these sections:
   - Run steps: install, start the cloud, provision, start the hub, run curl examples, run the tests.
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
| Cert format                                                 | JWT, not X.509                                                           | Smaller PoC. Same trust model as an intermediate CA                               |
| Cert transport                                              | Embedded in the session header (`dcert`)                                 | Cloud verification stays fully stateless                                          |
| **Rejected:** a cloud registry of device public keys        | —                                                                        | Works, but needs a DB lookup on every verification                                |
| **Rejected:** a shared secret or a key derived from the IdP | —                                                                        | One compromised device could forge sessions for every device                      |
| **Rejected:** OS-level network isolation in tests           | —                                                                        | Not cross-platform, and needs root                                                |

## 11. Out of scope (list as open questions in Part 3)

- **Hardware key protection:** TPM on the Hub, TPM or DPAPI on Windows. The PoC stores keys as files in the data dir.
- **User authentication:** How the user is authenticated before a session is issued (password, PIN, credential sync from the cloud). The PoC takes the `userId` as given.
- **Session refresh:** Silent refresh and re-issue of sessions.
- **Farm clock drift:** Drift while offline, and the tolerance the cloud accepts.
- **Revocation:** Revoking a compromised device by ID, and delivering that revocation to verifiers. Not implemented in this PoC.
- **Roles and scopes:** Roles, scopes, and RBAC. The design memo assumes one role.
- **Cert renewal:** The certificate renewal endpoint.

## 12. AI-use note (for README)

- The plan was drafted with Claude from the design memo and refined by the author.
- The implementation was done with Claude Code, milestone by milestone.
- The author steered and verified the output as follows: Oleksandr Starnikov.
