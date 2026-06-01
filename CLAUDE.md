# CLAUDE.md

Notes for Claude when working on this repository.

## Project at a glance

MPC-based 2-of-2 signature escrow. Three runtime modes from a single `main.go`, switched by `MODE` env var:

- `server` — public host: MetaMask auth (EIP-191), JWT, pairing, mailbox, escrow, timebox
- `client` — local participant: keygen (ECDSA/FROST), accounts, balance, tx, signing
- `communication` — gRPC + NATS relay for MPC messages between clients

No CLI flags. Everything via env vars / `.env` (loaded by `godotenv`).

## Layout

```
auth/         EIP-191 verify, nonce store, JWT, middleware
config/       Env loading (single source of truth)
server/       Host HTTP server (chi router)
              auth.go, pairing.go, mailbox.go, escrow.go, routes.go
client/       Local HTTP server (chi router)
              keygen_ecdsa.go, keygen_frost.go, accounts.go,
              balance.go, tx.go, send_tx.go, withdrawal.go,
              util.go (validation + party-id normalization)
network/      gRPC + NATS communication relay
mpc/          taurusgroup/multi-party-sig wrappers (CMP, FROST)
storage/      File storage + AES-256-GCM encrypted wrapper
escrow/       Pollination-pattern signature exchange
validation/   Standalone signature verifier (ECDSA/Schnorr)
docs/         Protocol/cryptography docs
docker/       docker-compose for local dev
```

## Conventions

### Identity
- Party IDs are **always** ETH addresses, normalized via `client.normalizePartyID`: lowercase, strip `0x`, strip dashes.
- Both participants in a pair (even for BTC accounts) are identified by their MetaMask ETH addresses.

### Pair IDs
- Deterministic: strip `0x`, lowercase, sort the two addresses, join with `_`.
- Avoid `:` in IDs — macOS filesystem rejects it.

### NATS channel isolation
- All MPC subjects are prefixed with `session_id/`. E.g. accept channel `{session_id}/{my_id}`, send `{session_id}/{another_id}`.
- Without the prefix, parallel sessions collide.

### Storage keys
- Server: `pairs/{id}`, `pairs/by-addr/{addr}`, `mailbox/{id}`, `mailbox/inbox/{addr}`, nonces.
- Client: `accounts/{network}/{index}/{conf-ecdsa|conf-frost|presig-ecdsa|meta}`. `network ∈ {eth, btc}`, `index ∈ [1..100]`.

### Validation (client `util.go`)
- `validateSessionID` — UUID format, ≤36 chars
- `validateETHAddress` — `0x` + 40 hex
- `validateNetwork` — only `eth`/`btc`
- `validateIndex` — `[1..100]`

### Encrypted storage
- `storage.NewEncryptedStorage` wraps file storage when `STORAGE_PASS` is set.
- `Get` must handle nil ciphertext (missing key) — return `nil, nil`, do not fail length check.

## Commit hygiene

- Don't add Claude as co-author unless asked.
- Don't commit `.idea/`. If staged accidentally, unstage before committing.
- Group related changes; user prefers descriptive messages over conventional-commits prefixes.

## Running locally

```bash
# all three roles via docker-compose
docker compose -f docker/docker-compose.yml up

# manually
MODE=communication go run .
MODE=server        go run .
MODE=client CLIENT_ADDR=:8080 STORAGE_PATH=./data-a go run .
MODE=client CLIENT_ADDR=:8081 STORAGE_PATH=./data-b go run .
```

## Tests

- `server/server_test.go` — in-memory tests for auth/pair/mailbox/escrow.
- `e2e_test.go` — hits a live host on `:8282`.
- After non-trivial changes run `go build ./...` and `go test ./server/...`.

## Things to keep in mind

- Keygen handler currently does **not** validate scheme/protocol field — the scheme is implicit per endpoint (`/keygen/ecdsa` vs `/keygen/frost`). If a unified endpoint is added, accept `scheme ∈ {ecdsa, frost, eddsa}` and validate it.
- FROST keygen has no `network` field in request — always BTC; storage path is hardcoded `accounts/btc/{index}`.
- `presig-ecdsa` is for offline-signing optimization (CMP presignatures) — populated optionally.
- The frontend lives in a separate repo (do not commit frontend code here).

## What works today

Auth · Pairing · Mailbox · ECDSA keygen (ETH) · FROST keygen (BTC) · Multi-account per pair · ETH balance/tx/send · BTC via BlockCypher · Incomplete-signature withdrawal flow · Escrow/timebox · Encrypted local storage.

---

# Production deployment & recent work (read this after a context reset)

## Server: root@155.212.147.24 (mpcoven.net)

SSH access is set up (key on server). The user authorized direct SSH.

### Docker stack (`/root/signature-escrow/docker/docker-compose.yml`)
All five services run from ONE image (`docker compose build <svc>`):
- `se-nats` — NATS `2.10-alpine`, command `["-js", "-m", "8222"]`. **The `-m 8222` is required** — the healthcheck hits `http://localhost:8222/healthz`; without it nats is `unhealthy` and every `depends_on` service refuses to start. (I broke this once; don't drop it.)
- `se-communication` — relay, `COMMUNICATION_ADDR=0.0.0.0:6379`, `NATS_URL=nats://nats:4222`
- `se-server` — host API, `:8282`, env `JWT_SECRET`, `STORAGE_PASS`
- `se-client-a` / `se-client-b` — `:8080`/`:8081`, `COMMUNICATION_ADDR=communication:6379`
- nginx (`mpcoven-nginx`, image `fholzer/nginx-brotli`) + certbot are SEPARATE, in `/root/mpcoven/`.

### nginx (config: `/root/mpcoven/nginx-ssl.conf`, mounted into `mpcoven-nginx`)
Two server blocks (`:80` redirect, `:443` TLS). Inside the **443 block** (order matters — gRPC before `/api/`):
- `location /exchange.Exchange/ { grpc_pass grpc://se-communication:6379; ... }` — exposes the MPC relay over TLS so remote clients reach it on `mpcoven.net:443`.
- `location /api/ { proxy_pass http://se-server:8282/; }`
- `/app/` serves the Flutter web build from `/root/mpcoven/build/app/`.
After editing: `docker exec mpcoven-nginx nginx -t` then `nginx -s reload`. The site must stay `200` (`curl https://mpcoven.net/`).

### Deploy a backend change
```bash
scp server/<file>.go root@155.212.147.24:/root/signature-escrow/server/
ssh root@155.212.147.24 'cd /root/signature-escrow/docker && docker compose build server && docker compose up -d server'
# clients use the same image:
ssh root@155.212.147.24 'cd /root/signature-escrow/docker && docker compose build client-a client-b && docker compose up -d client-a client-b'
```
Server git is on `main`; commit after deploy so a clean rebuild doesn't lose changes.
**Edit gotcha:** `Edit` tool string-matches failed silently several times on `routes.go`/`server.go` (matched stale text). After editing routes/struct, ALWAYS verify with `grep -c` before trusting the build.

## Key endpoints added beyond the base set
- `POST /v1/accounts/delete {network,index,address}` (client) — permanently deletes one account's key share (meta/conf/presig). `address` is a confirmation guard (must match stored meta). **Irreversible** — losing the share locks any funds (2-of-2).
- `listAccounts` scans indices 1..100 and **must `continue` over gaps**, not `break` (deletion leaves holes; `break` would hide later accounts).
- `POST /v1/session/claim {session_id}` and `POST /v1/session/cancel {session_id}` (server, `server/session.go`) — in-memory atomic registry (`sessionRegistry`, mutex). Resolves the keygen cancel/accept race: partner `claim`s before running its half; initiator `cancel`s. Exactly one wins. Returns `{ok: bool}`.

## Relay = JetStream (not plain pub/sub)
`network/server.go` uses a JetStream WorkQueue stream `RELAY` (subjects `["*"]`, MemoryStorage, MaxAge 10m). **Why:** plain NATS pub/sub dropped the first message if the peer subscribed late → keygen deadlocked when partners didn't start within ~5s. JetStream buffers it. `network/client.go` `Done()` cancels the gRPC stream so the per-subject consumer frees up for the next phase. ECDSA presign uses a distinct subject suffix (`acceptCh+"/presign"`) so it doesn't collide with the keygen-phase consumer on the WorkQueue.

## TLS relay option
`main.go` client mode: if `COMMUNICATION_TLS=true`, the gRPC client dials with `credentials.NewTLS` instead of insecure. Used so local/native clients reach `mpcoven.net:443`.

## Test wallets (local, user-authorized)
`~/.mpc-test-wallet/wallet.json` (A = `0x5E64B53A…1184f`) and `wallet-b.json` (B = `0x632Bb39…1aCD`), chmod 600. Sign nonces with `cast wallet sign --private-key <pk> <message>`. `eth_account` python is NOT installed — use `cast`.

## How to test keygen end-to-end without the UI
Two local clients on `:8080`/`:8081`. Both keygen halves need the SAME `session_id` (valid UUID, ≤36 chars), swapped `my_id`/`another_id`, same `index`. Fire both concurrently (threads). Identical returned address = success. A staggered start (one side late) is the regression test for the JetStream fix.
