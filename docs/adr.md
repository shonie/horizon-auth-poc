# PLAN: Horizon offline-capable authentication (PoC)

Part 2 of the Lely Software Architect take-home. Build a small, self-contained proof of concept of session issuance and verification that:

- works when the farm device (Hub or legacy Windows desktop) has no connectivity;
- produces a session that Lely's cloud can verify later, without a live round trip to an IdP.

Keep it small. We evaluate the soundness of the mechanism and the clarity of the code, not infrastructure. Do not over-engineer.

## 1. Mechanism: delegated signing

Do not derive or copy a private key from the cloud IdP. If every device holds a key that comes from the IdP secret, one compromised device can forge sessions for all devices.

Use a trust chain instead:

1. **Installation (online, once):** The device generates its own Ed25519 key pair. The private key never leaves the device.
2. The device sends its public key and a one-time enrollment code to the cloud (`POST /enroll-hub`).
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
- **Tests:** `node:test` and `node:assert/strict`. Unit tests cover `core/`; a black-box HTTP suite (`e2e/`) runs against a hub and a cloud provided by the environment.
- **Style:** Functional. Use pure functions in `core/` and factories for the servers. Use classes only if a library requires them.
- **Integration setup:** Docker + Docker Compose (Linux). Cross-platform support is out of scope for this PoC; CI runs on Ubuntu only.
  - Take the data directory from the `HORIZON_DATA_DIR` env var.

## 3. Structure

One package. Do not use workspaces.

```
horizon-auth-poc/
  package.json          # "type": "module"
  tsconfig.json
  Dockerfile
  docker-compose.online.yaml   # hub can reach the cloud (enrolls, then serves)
  docker-compose.offline.yaml  # hub isolated from the cloud; already enrolled
  .github/workflows/ci.yml     # ubuntu-only: typecheck job + docker integration job
  src/
    hub/                # produces: device keys + sessions
      keys.ts           # generateDeviceKeys, export/import private JWK
      session.ts        # issueSession (signs with the device key)
      server.ts         # createHubServer(config): POST /session
      enroll-hub.ts     # install-time step; the ONLY hub code that uses the network
      store.ts          # read/write: device private key, device cert, root JWK
      main.ts           # reads env, calls listen
    cloud/              # produces certs; verifies certs + sessions
      device-cert.ts    # issueDeviceCert, verifyDeviceCert
      session.ts        # verifySession
      server.ts         # createCloudServer(config): POST /enroll-hub,
                        # GET /.well-known/jwks.json, GET /whoami
      root-key.ts       # load-or-create the persisted root key (trust anchor)
      main.ts
  e2e/
    verify.test.ts      # black-box HTTP suite; reads HUB_URL / CLOUD_URL
  README.md
```

Each service owns the token logic it needs — the hub only *produces* (keys, sessions), the cloud only *issues certs and verifies*. Nothing is shared at runtime, so there is no shared `core/` package and no hub→cloud dependency. The pure token functions are exercised end-to-end by the black-box suite rather than by separate unit tests.

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

- **Enroll (hub, online):**
  1. Generate the key pair.
  2. `POST /enroll-hub { enrollmentCode, publicJwk }`. The response is `{ deviceId, deviceCert, rootJwk }`.
  3. Persist the key pair, `deviceCert`, and `rootJwk` to the store.
- **Issue a session (hub, offline):**
  1. `POST /session { userId }`. Authenticating the user is out of scope.
  2. Issue a session with a 12 h lifetime, signed by the device key.
  3. Return `{ token }`.
- **Verify (cloud):** `GET /whoami` with `Authorization: Bearer <token>`. The cloud verifies against the pinned root key and returns `{ userId, deviceId }`.

## 7. Emulating network absence

The offline property is proven by the environment, not by the test code. The
same black-box suite runs against two compose setups:

- **Online** (`docker-compose.online.yaml`): hub and cloud share a network; the hub enrolls at startup (setup, not asserted) then serves.
- **Offline** (`docker-compose.offline.yaml`): reuses the enrolled hub identity and the persisted cloud root key, but places the hub on a network the cloud is **not** on. The hub cannot reach the cloud (the hostname does not resolve), yet it still issues sessions; the test carries the token to the cloud, which verifies it.

Because the suite never depends on hub→cloud connectivity at runtime (only enrollment does, and that is setup), the identical suite passes in both — a real network cut rather than a mocked `fetch`. A stronger "no internet at all" demo is `docker run --network none` on the enrolled hub.

## 8. Tests

A single connectivity-agnostic black-box suite, `e2e/verify.test.ts`. It talks HTTP to `HUB_URL` and `CLOUD_URL` (from the environment) and makes no assumptions about connectivity. Enrollment is done by the setup, not asserted here. Each compose file defines a `tester` service that runs it against the hub and cloud over the compose network; the SAME suite runs against both the online and offline setups (see section 7):

- The hub issues a session and the cloud verifies it (`{ userId, deviceId }`).
- The cloud rejects a missing token and a tampered token (401).

There are no separate unit tests: the pure token functions are exercised end-to-end by this suite. The offline CI job additionally asserts, via `docker exec`, that the hub cannot reach the cloud.

## 9. Milestones

Work in this order. Finish each milestone with green tests before you start the next.

1. **Scaffold:** `package.json`, tsconfig, and the scripts:
   - `"test:e2e": "node --test \"e2e/**/*.test.ts\""`
   - `"typecheck": "tsc --noEmit"`
   - `"cloud": "node src/cloud/main.ts"`
   - `"hub": "node src/hub/main.ts"`
   - `"enroll-hub": "node src/hub/enroll-hub.ts"`

   Also add the Dockerfile, the two compose files, and the CI workflow.

2. The cloud (`device-cert.ts`, `session.ts`, `server.ts`, `root-key.ts`).
3. The hub (`keys.ts`, `session.ts`, `store.ts`, `enroll-hub.ts`, `server.ts`).
4. `e2e/verify.test.ts` and the compose `tester` services.
5. `README.md`, with these sections:
   - Run steps: install, start the cloud, enroll the hub, start the hub, run curl examples, verify via compose.
   - A short mechanism explanation with the diagram from section 1.
   - Trade-offs (section 10).
   - Open questions (section 11).
   - AI-use note (section 12).

**Definition of done:** on Ubuntu CI, `npm run typecheck` passes and the black-box suite (the `tester` service) passes against both the online and offline compose setups.

## 10. Decisions and trade-offs

| Decision                                                    | Choice                                                                   | Reason                                                                            |
| ----------------------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| Key type                                                    | Ed25519 (EdDSA)                                                          | Small keys, fast, deterministic signatures, supported by `jose` and `node:crypto` |
| Session lifetime                                            | 12 h                                                                     | One farm shift                                                                    |
| Device cert lifetime                                        | 1 year, renew when online and < 30 days remain (renewal not implemented) | Matches the 1-year durability window in the design memo                           |
| Cert format                                                 | JWT, not X.509                                                           | Smaller PoC. Same trust model as an intermediate CA                               |
| Cert transport                                              | Embedded in the session header (`dcert`)                                 | Cloud verification stays fully stateless                                          |
| Offline proof                                               | Docker network isolation, not a mocked `fetch`                           | Tests the real property (issuance with no cloud route), not an implementation detail. Costs cross-platform CI — Linux only |
| **Rejected:** a cloud registry of device public keys        | —                                                                        | Works, but needs a DB lookup on every verification                                |
| **Rejected:** a shared secret or a key derived from the IdP | —                                                                        | One compromised device could forge sessions for every device                      |

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
