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
