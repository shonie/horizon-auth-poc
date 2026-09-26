# Horizon offline-capable authentication (PoC)

A small proof of concept of session issuance and verification that:

- works when the farm device (Hub or legacy Windows desktop) has **no connectivity**;
- produces a session that Lely's cloud can **verify later**, without a live round trip to an IdP.

## Requirements

- Node **>= 22.18** (runs `.ts` files directly via type stripping; CI uses Node 24).
- No build step. `jose` is the only runtime dependency.
- Docker + Docker Compose for the integration tests (Linux). CI runs on Ubuntu
  only — cross-platform support is out of scope for this PoC.

### Verify

Verification runs **through Docker Compose**. Each setup defines a `tester`
service that runs the connectivity-agnostic black-box suite (`e2e/`) against the
hub and cloud over the compose network — you don't run anything against the host.
The `tester`'s exit code is the result.

```bash
# Online: the hub enrolls against the cloud, then the tester verifies
# issue + verify. (--build builds the image on first run.)
docker compose -f docker-compose.online.yaml run --build --rm tester
docker compose -f docker-compose.online.yaml down     # keep the volumes

# Offline: reuse the enrolled identity + persisted root key. The hub is on a
# network with no route to the cloud, yet the SAME suite passes — the tester
# reaches both services and carries the token across.
docker compose -f docker-compose.offline.yaml run --rm tester
docker compose -f docker-compose.offline.yaml down
```

Run the online setup first — it populates the volumes the offline setup reuses.

### curl examples

```bash
# Issue a session on the hub (offline) and capture the token.
# Authenticating the user is out of scope; the caller supplies the userId.
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/session \
  -H 'content-type: application/json' \
  -d '{"userId":"user-7"}' | \
  sed -E 's/.*"token":"([^"]+)".*/\1/')

# Verify the session in the cloud -> { userId, deviceId }
curl -s http://127.0.0.1:8081/whoami -H "authorization: Bearer $TOKEN"

# The pinned root public key
curl -s http://127.0.0.1:8081/.well-known/jwks.json
```

## How it works

1. **Installation (online, once).** The device generates its own Ed25519 key pair.
   The private key never leaves the device.
2. It sends its public key and a one-time enrollment code to the cloud
   (`POST /enroll-hub`).
3. The cloud signs a **device certificate** — a JWT that binds
   `deviceId + device public key`, signed by the cloud **root key**. The
   device stores the certificate and pins the cloud root public key.
4. **Issue a session (offline).** The device signs a **session JWT** with its
   device private key, embedding the device certificate in the JWT header
   (`dcert`). Authenticating the user is out of scope; the caller supplies the
   `userId`.
5. **Verification (anywhere).** The pinned root key verifies the certificate; the
   public key inside the certificate verifies the session. No IdP call is needed.

`verifySession` enforces: the cert signature (against the pinned root key), the
session signature (against the key in the cert), the cert and session expiry, and
the issuer binding (`iss === "device:" + cert.sub`), with a 300 s clock tolerance
for offline drift. It returns `{ userId, deviceId }`.

The blast radius of a compromised device is **that device alone** — it cannot
forge sessions for any other device, because it does not hold the root key.

### Emulating network absence

The offline proof lives in the **environment**, not in the test code. The same
black-box suite runs against two compose setups:

- **`docker-compose.online.yaml`** — hub and cloud share a network. The hub
  enrolls (setup, not asserted) then serves. Everything works.
- **`docker-compose.offline.yaml`** — reuses the enrolled hub identity and the
  persisted cloud root key from the online run, but puts the hub on a network the
  cloud is **not** on. The hub literally cannot reach the cloud (its hostname
  doesn't resolve), yet it still issues sessions — and those tokens verify at the
  cloud, which the `tester` reaches on the other network (it plays the courier).

Because the suite never depends on hub→cloud connectivity at runtime (only
enrollment does, and that's setup), the identical suite passes in both setups.
That's the proof, and it's a real network cut rather than a mocked `fetch`. CI
additionally asserts, via `docker exec`, that the offline hub genuinely cannot
reach the cloud — so the isolation is verified, not assumed.

For a stronger "no internet at all" demo, run the enrolled hub under
`docker run --network none` (`internal: true` would do it in compose too, but it
also disables published ports).

## Trade-offs

| Decision                                                    | Choice                                                                   | Reason                                                                                                                     |
| ----------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Key type                                                    | Ed25519 (EdDSA)                                                          | Small keys, fast, deterministic signatures, supported by `jose` and `node:crypto`                                          |
| Session lifetime                                            | 12 h                                                                     | One farm shift                                                                                                             |
| Device cert lifetime                                        | 1 year, renew when online and < 30 days remain (renewal not implemented) | Matches the 1-year durability window in the design memo                                                                    |
| Cert format                                                 | JWT, not X.509                                                           | Smaller PoC. Same trust model as an intermediate CA                                                                        |
| Cert transport                                              | Embedded in the session header (`dcert`)                                 | Cloud verification stays fully stateless                                                                                   |
| Offline proof                                               | Docker network isolation, not a mocked `fetch`                           | Tests the real property (issuance with no cloud route), not an implementation detail. Costs cross-platform CI — Linux only |
| **Rejected:** a cloud registry of device public keys        | —                                                                        | Works, but needs a DB lookup on every verification                                                                         |
| **Rejected:** a shared secret or a key derived from the IdP | —                                                                        | One compromised device could forge sessions for every device                                                               |

## Open questions (out of scope for this PoC)

- **Hardware key protection:** TPM on the Hub, TPM or DPAPI on Windows. The PoC
  stores keys as files in the data dir.
- **User authentication:** how the user is authenticated before a session is
  issued (password, PIN, credential sync from the cloud). The PoC takes the
  `userId` as given.
- **Session refresh:** silent refresh and re-issue of sessions.
- **Farm clock drift:** drift while offline, and the tolerance the cloud accepts.
- **Revocation:** revoking a compromised device by ID, and delivering that
  revocation to verifiers. Not implemented in this PoC.
- **Roles and scopes:** roles, scopes, and RBAC. The design memo assumes one role.
- **Cert renewal:** the certificate renewal endpoint.

## AI-use note

- The plan was drafted with Claude from the design memo and refined by the author.
- The implementation was done with Claude Code, milestone by milestone.
- The author steered and verified the output as follows: Oleksandr Starnikov.
