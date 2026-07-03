---
sidebar_position: 6
title: Authentication
---

# Authentication

mpcoven has **two independent logins**, because the app talks to two different
trust domains: the shared **server** and the party's own **client**.

## Server login (mailbox / pairing)

Standard wallet sign-in (SIWE-style, EIP-191):

1. `requestNonce(address)` → the server returns a message to sign.
2. The user signs it with MetaMask / WalletConnect / a pasted signature.
3. `login(address, signature, nonce)` → a 24h JWT.

The token is stored locally and re-verified on start.

## Client login (keys / transactions)

The Go client may be **remote**, so it is *not* trusted just because it is
reachable — it has its **own** login, independent of the server:

- `POST /v1/auth/nonce` + `POST /v1/auth/login` — same EIP-191 message format,
  issuing a **client** JWT attached to every client call.
- `GET /v1/identity` (public) → `{ address, has_keys, bound, auth_required }`.

### Owner binding

A client that already holds key material only authorizes the address matching
its accounts' identity; a **fresh** client binds to the first successful login.
Signing in with the wrong address returns **403 — "this client is bound to X"**.
So a networked client only ever serves its true owner.

### Local convenience

For a **local** client you can disable client auth entirely with
`CLIENT_AUTH=none` — the client drops the requirement, `/v1/identity` reports
`auth_required: false`, and the app skips the second signature. The default is
**on** (secure for remote clients).

## Design notes

This is the standard **OAuth2 resource-server** shape: one authenticator, many
resource servers. The redundant *second signature* can be collapsed to one with
either an asymmetric server-issued JWT (if you trust the server to authenticate)
or a **SIWE + session-key** flow (if you do not) — sign once, then a short-lived
session key authorizes calls to both services.
