---
sidebar_position: 7
title: API reference
---

# API reference

Both the server and each client serve interactive **Swagger UI** and an OpenAPI
spec. The spec is generated from annotations with
`swag init -g docs.go --parseDependency --parseInternal -o apidocs`.

- **Server:** [`mpcoven.net/api/swagger/index.html`](https://mpcoven.net/api/swagger/index.html)
- **Client:** `http://<client-host>:8080/swagger/index.html`

## Server endpoints (coordinator)

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/auth/nonce` · `/v1/auth/login` | Wallet sign-in → JWT |
| GET/POST | `/v1/pair/...` | Pairing + pending pairs |
| POST | `/v1/mailbox/...` | Typed messages between partners |
| POST | `/v1/session/claim` · `/v1/session/cancel` | Atomic keygen race resolver |
| POST | `/v1/escrow` · `/v1/escrow/check` | Atomic-swap pollination deposit / poll |

## Client endpoints (key holder)

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/auth/nonce` · `/v1/auth/login` | Client sign-in (owner-bound) |
| GET | `/v1/identity` | `{address, has_keys, bound, auth_required}` (public) |
| POST | `/v1/keygen/ecdsa` · `/v1/keygen/frost` | Distributed key generation |
| GET/POST | `/v1/accounts/{list,get,delete}` | Local accounts |
| POST | `/v1/balance/{check,wait}` | Native balance |
| POST | `/v1/tx/{hash,decode,send}` | Build / decode / broadcast a transaction |
| POST | `/v1/incomplete-signature/{send,accept}` | The two halves of a co-signature |
| GET/POST | `/v1/cosign/{history,complete}` | Local activity log |
| GET/POST | `/v1/exchanges/{list,create,update,upsert,delete}` | Exchanges |
| GET/POST | `/v1/aliases/{list,set,delete}` | Address-book labels |

## Mailbox message types

`keygen-init`, `sign-request`, `sign-result`, `exchange-proposal`,
`exchange-accepted`, `keygen-cancel`, `pair-removed`. Service messages
(`*-cancel`, `*-removed`, `sign-result`, `exchange-accepted`) are handled in the
background and never shown to the user.

## Supported assets

Only **native ETH** and **BTC**. ERC-20 (e.g. USDT) is not yet supported — MPC
signing itself is token-agnostic (it signs any hash), but the tx-builder,
decoder, and balance paths would need token awareness.
