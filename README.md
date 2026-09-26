# Horizon offline-capable authentication (PoC)

A small proof of concept of session issuance and verification that:

- works when the farm device (Hub or legacy Windows desktop) has **no connectivity**;
- produces a session that Lely's cloud can **verify later**, without a live round trip to an IdP.

The mechanism is a **delegated-signing trust chain**: the cloud never hands out a
shared secret. Each device holds its own key and a cloud-signed certificate that
binds it to one farm.

```
cloud root key ──signs──▶ device cert {farm_id, cnf.jwk} ──key in cert verifies──▶ session token
```

## Requirements

- Node **>= 22.18** (runs `.ts` files directly via type stripping; CI uses Node 24).
- No build step. `jose` is the only runtime dependency.

## Run steps

```bash
# 1. Install
npm install

# 2. Start the cloud (issues device certs, verifies cloud-bound sessions)
npm run cloud
# note the "enrollment code" it prints; the default is enroll-dev-code

# 3. Provision the hub (the ONLY online step). In a second terminal:
npm run provision
# generates a device key pair, POSTs the public key + enrollment code to the
# cloud, and stores the returned device cert + pinned root key locally.

# 4. Seed a user (scrypt password hash, stored locally on the hub)
npm run seed-user farmer-joe green-pastures-42

# 5. Start the hub (login + local access, fully offline)
npm run hub
```

Configuration is via environment variables:

| Var                       | Used by                   | Default                 |
| ------------------------- | ------------------------- | ----------------------- |
| `HORIZON_DATA_DIR`        | hub, provision, seed-user | `./data`                |
| `HORIZON_CLOUD_PORT`      | cloud                     | `8081`                  |
| `HORIZON_HUB_PORT`        | hub                       | `8080`                  |
| `HORIZON_CLOUD_URL`       | provision                 | `http://127.0.0.1:8081` |
| `HORIZON_ENROLLMENT_CODE` | cloud, provision          | `enroll-dev-code`       |
| `HORIZON_FARM_ID`         | provision                 | `farm-42`               |

### curl examples

```bash
# Log in on the hub (offline) and capture the session token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/login \
  -H 'content-type: application/json' \
  -d '{"username":"farmer-joe","password":"green-pastures-42"}' | \
  sed -E 's/.*"token":"([^"]+)".*/\1/')

# Local resource on the hub (hub verification policy)
curl -s http://127.0.0.1:8080/local/cows -H "authorization: Bearer $TOKEN"

# Cloud resource (cloud verification policy: cert expiry + revocation enforced)
curl -s http://127.0.0.1:8081/farms/farm-42/reports -H "authorization: Bearer $TOKEN"

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
   (`POST /provision`).
3. The cloud signs a **device certificate** — a JWT that binds
   `deviceId + farmId + device public key`, signed by the cloud **root key**. The
   device stores the certificate and pins the cloud root public key.
4. **Login (offline).** The device verifies the password locally (scrypt) and
   signs a **session JWT** with its device private key, embedding the device
   certificate in the JWT header (`dcert`).
5. **Verification (anywhere).** The pinned root key verifies the certificate; the
   public key inside the certificate verifies the session. No IdP call is needed.

The blast radius of a compromised device is **one farm** — it cannot forge
sessions for others, because it does not hold the root key. The cloud can revoke
a device by device ID.

### One verifier, two policies

`verifySession` runs the same steps everywhere and differs only in policy:

| Policy knob         | Hub                                      | Cloud                                |
| ------------------- | ---------------------------------------- | ------------------------------------ |
| `audience`          | `horizon-local`                          | `horizon-cloud`                      |
| `enforceCertExpiry` | `false` (never lock out an offline farm) | `true`                               |
| `isRevoked`         | always `false`                           | checks the in-memory revocation list |

Both enforce: signature, session expiry (300 s clock tolerance), issuer binding
(`iss === "device:" + cert.sub`), and `session.farm_id === cert.farm_id`.

### Emulating network absence

- **By design:** the hub login path has no network dependency. `provision.ts` is
  the only network caller.
- **In tests:** provision while the cloud runs, then close the cloud (a real
  request would now get `ECONNREFUSED`), replace `globalThis.fetch` with a mock
  that throws, log in and access a local resource, and assert
  `fetch.mock.callCount() === 0`. That zero-call assertion is the proof.
- **Optional manual demo (Linux only, not in CI):** run the hub under
  `docker run --network none` after provisioning to a mounted data dir.

## Trade-offs

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

## Open questions (out of scope for this PoC)

- **Hardware key protection:** TPM on the Hub, TPM or DPAPI on Windows. The PoC
  stores keys as files in the data dir.
- **Credential distribution:** how user credentials reach the farm (synced from
  the cloud, or created locally).
- **Session refresh:** silent refresh and re-issue of sessions.
- **Farm clock drift:** drift while offline, and the tolerance the cloud accepts.
- **Revocation delivery:** how revocation reaches the hub. The PoC checks
  revocation only in the cloud.
- **Roles and scopes:** roles, scopes, and RBAC. The design memo assumes one role.
- **Cert renewal:** the certificate renewal endpoint.

## AI-use note

- The plan was drafted with Claude from the design memo and refined by the author.
- The implementation was done with Claude Code, milestone by milestone.
- The author steered and verified the output as follows: Oleksandr Starnikov.
