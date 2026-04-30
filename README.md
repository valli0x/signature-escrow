# Signature Escrow

A 2-of-2 MPC wallet: shared ETH/BTC accounts where neither party holds the full private key. Signing requires both. Coordination happens through a host server with MetaMask authentication.

## Architecture

Three independent processes. Same binary, role chosen by the `MODE` env var.

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Client A   │  HTTPS  │ Host Server  │  HTTPS  │  Client B   │
│ (local UI)  │◄───────►│ auth/pair/   │◄───────►│ (local UI)  │
│             │         │   mailbox    │         │             │
└──────┬──────┘         └──────────────┘         └──────┬──────┘
       │                                                 │
       │              ┌──────────────────┐               │
       └─────gRPC────►│  Communication   │◄────gRPC──────┘
                      │   server (NATS)  │
                      └──────────────────┘
```

- **Host server** (`MODE=server`) — public entry point. MetaMask auth (EIP-191), JWT sessions, pairing of two addresses, mailbox for async messages between paired participants, escrow/timebox.
- **Client** (`MODE=client`) — local service per participant. Holds encrypted key material, runs MPC keygen, balance checks, transaction building and signing.
- **Communication** (`MODE=communication`) — gRPC + NATS relay for MPC messages between clients during keygen/sign.

## What works today

### Authentication
- Request nonce → MetaMask `personal_sign` (EIP-191) → JWT (24h)
- In-memory nonce store with 5-minute TTL
- JWT middleware injects the ETH address into the request context

### Pairing
- A creates a pair targeting B's ETH address
- B confirms (only the addressee can accept)
- Deterministic `pair_id` derived from both addresses (sorted, lowercase, no `0x`, joined with `_`)
- Address-indexed storage for fast lookup of incoming/outgoing pair requests
- `GET /v1/pair/pending` returns `{incoming, outgoing}`

### Mailbox
- Async message delivery within a pair
- Validation: sender and recipient must both belong to the specified `pair_id`
- `Type` + arbitrary JSON `Body` (e.g. `keygen-init`, `tx-request`)
- ACK removes the message from the inbox

### MPC keygen (client)
- ECDSA (CMP) — shared ETH account
- FROST (Taproot) — shared BTC account
- MetaMask addresses double as MPC party IDs (normalized: lowercase, no `0x`)
- NATS channels are session-isolated: `{session_id}/{my_id}`, `{session_id}/{another_id}`
- Multiple accounts per pair: `accounts/{network}/{index}/`, `network ∈ {eth, btc}`, `index ∈ [1..100]`
- Stored material: `conf-ecdsa` / `conf-frost`, optional `presig-ecdsa`, plus `meta` (address, pubkey, party-ids)
- Client-side input validation: UUID `session_id`, ETH-format `my_id`/`another_id`, `index` in range

### Accounts (client)
- `GET /v1/accounts/list` — scans indices 1..100 for each network
- `POST /v1/accounts/get` — fetch a single account by `network + index`

### Transactions and balance
- ETH: `checkBalance`, `waitForBalance`, `createTxHash`, `sendTransaction`
- BTC: BlockCypher integration
- Incomplete-signature flow: one side initiates the withdrawal, the other accepts and finishes the signature

### Escrow / Timebox
- Inherited from the original `escrowbox`: pollination-style signature exchange
- Timebox for delayed delivery

### Storage
- File-based, CBOR-serialized
- Optional AES-256-GCM encryption (HashiCorp Vault SDK), key derived from `STORAGE_PASS`
- Client stores MPC key material; server stores nonces, pairs, mailbox

## Running

### Requirements
- Go 1.22+
- NATS server (for `communication` mode)
- ETH RPC endpoint (Infura, Alchemy, etc.) — for transactions
- BlockCypher token — for BTC

### Configuration (`.env`)

```bash
MODE=server                          # server | client | communication

# Host server
SERVER_ADDR=:8282
JWT_SECRET=change-me-in-production

# Local client
CLIENT_ADDR=:8080

# Communication relay
COMMUNICATION_ADDR=localhost:6379
NATS_URL=nats://localhost:4222

# Storage
STORAGE_PATH=./data
STORAGE_PASS=                        # empty = no encryption

# Blockchain
ESCROW_SERVER=localhost:8282
ETHEREUM_RPC=
BLOCKCYPHER_TOKEN=
```

### Commands

```bash
# Host server
MODE=server go run .

# Local client (one per participant)
MODE=client CLIENT_ADDR=:8080 STORAGE_PATH=./data-a go run .
MODE=client CLIENT_ADDR=:8081 STORAGE_PATH=./data-b go run .

# Communication relay
MODE=communication go run .
```

### Docker

```bash
docker compose -f docker/docker-compose.yml up
```

Spins up NATS, the host server, the communication relay, and two client instances.

## HTTP API

### Host server (`:8282`)

Public:
- `POST /v1/auth/nonce` — `{address}` → `{nonce, message}`
- `POST /v1/auth/login` — `{address, signature}` → `{token}`

Protected (Bearer JWT):
- `POST /v1/pair/create` — `{partner_address}` → create a pair request
- `POST /v1/pair/accept` — `{pair_id}` → confirm
- `GET /v1/pair/pending` → `{incoming, outgoing}`
- `POST /v1/mailbox/send` — `{pair_id, to, type, body}`
- `GET /v1/mailbox/pending` → list of incoming messages
- `POST /v1/mailbox/ack` — `{message_id}`
- `POST /v1/escrow`
- `POST /v1/timebox`

### Client (`:8080`)

- `POST /v1/keygen/ecdsa` — `{session_id, my_id, another_id, network, index}`
- `POST /v1/keygen/frost` — `{session_id, my_id, another_id, index}`
- `GET /v1/accounts/list`
- `POST /v1/accounts/get` — `{network, index}`
- `POST /v1/balance/check`
- `POST /v1/balance/wait`
- `POST /v1/tx/hash`
- `POST /v1/tx/send`
- `POST /v1/incomplete-signature/send`
- `POST /v1/incomplete-signature/accept`

## Tests

```bash
go test ./server/...   # unit + integration: auth, pairing, mailbox, escrow
go test .              # e2e against a live host on :8282
```

## Documentation

Detailed cryptography and protocol notes live under `docs/en/`.

## License

See `LICENSE`.
