# Horizon offline-capable authentication (PoC)

A small proof of concept of session issuance and verification that:

- works when the farm device (Hub or legacy Windows desktop) has **no connectivity**;
- produces a session that Lely's cloud can **verify later**, without a live round trip to an IdP.

The mechanism is a **delegated-signing trust chain**: the cloud never hands out a
shared secret. Each device holds its own key and a cloud-signed certificate that
binds that key to a device identity.

```
cloud root key ──signs──▶ device cert {sub: deviceId, cnf.jwk} ──key in cert verifies──▶ session token
```

## Requirements

- Node **>= 22.18** (runs `.ts` files directly via type stripping; CI uses Node 24).
- No build step. `jose` is the only runtime dependency.

## Run steps

```bash
# 1. Install
npm install

# 2. Start the cloud (issues device certs, verifies sessions)
npm run cloud
# note the "enrollment code" it prints; the default is enroll-dev-code

# 3. Enroll the hub (the ONLY online step). In a second terminal:
npm run enroll-hub
# generates a device key pair, POSTs the public key + enrollment code to the
# cloud, and stores the returned device cert + pinned root key locally.

# 4. Start the hub (issues sessions, fully offline)
npm run hub
```

Configuration is via environment variables:

| Var                       | Used by                   | Default                 |
| ------------------------- | ------------------------- | ----------------------- |
| `HORIZON_DATA_DIR`        | hub, enroll-hub           | `./data`                |
| `HORIZON_CLOUD_PORT`      | cloud                     | `8081`                  |
| `HORIZON_HUB_PORT`        | hub                       | `8080`                  |
| `HORIZON_CLOUD_URL`       | enroll-hub                | `http://127.0.0.1:8081` |
| `HORIZON_ENROLLMENT_CODE` | cloud, enroll-hub         | `enroll-dev-code`       |

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

### Run the tests

```bash
npm run typecheck   # tsc --noEmit
npm test            # node --test
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

- **By design:** the hub session-issuance path has no network dependency.
  `enroll-hub.ts` is the only network caller.
- **In tests:** enroll the hub while the cloud runs, then close the cloud (a real
  request would now get `ECONNREFUSED`), replace `globalThis.fetch` with a mock
  that throws, issue a session, and assert `fetch.mock.callCount() === 0`. That
  zero-call assertion is the proof.
- **Optional manual demo (Linux only, not in CI):** run the hub under
  `docker run --network none` after enrolling to a mounted data dir.

## Trade-offs

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
