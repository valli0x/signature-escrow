---
sidebar_position: 4
title: MPC co-signing
---

# MPC co-signing (withdrawal)

A 2-of-2 transaction is signed **jointly**. Because broadcasting needs the full
transaction, the party who *completes* the signature is the one who broadcasts.

## The flow

### 1. Initiator — "Send for co-signing"

1. `POST /v1/tx/hash` → the client returns the **hash** to sign plus `tx_data`
   (the RLP of the exact unsigned transaction).
2. Sends a `sign-request` to the partner's mailbox with
   `{alg, to, amount, hash_tx, tx_data, escrow?}`.
3. `POST /v1/incomplete-signature/send` — its incomplete signature goes onto the
   relay (buffered by JetStream).

The initiator records an activity entry (`sent`, "awaiting partner").

### 2. Acceptor — "Accept & Sign"

`POST /v1/incomplete-signature/accept` completes the **Ethereum-format**
signature: `mpccmp.SigEthereum` — 65 bytes, low-s, `r‖s‖v` with the recovery id
(this is what a node accepts; the CMP-native encoding is *not*). The acceptor
now holds a broadcastable signature and `tx_data`.

### 3. Broadcast

`POST /v1/tx/send {network, signature, tx_data}` — the client decodes `tx_data`,
attaches the signature with `WithSignature`, and broadcasts it **verbatim**.

Either party can broadcast: after the acceptor completes, it returns the
signature to the initiator (via a `sign-result` mailbox message), whose activity
entry flips to `completed` — it already stored `tx_data`.

## Verify-what-you-sign

The acceptor must **never blind-sign**. Two guarantees:

- **Crypto-level.** The backend rejects the accept unless
  `keccak(tx_data) == hash`. Displayed-≠-signed is therefore impossible: the
  hash you sign provably commits to the exact transaction bytes.
- **UI-level.** The signature-request card decodes `tx_data` via
  `POST /v1/tx/decode` and shows the **real** to / value / nonce (not the
  sender's claimed display fields), with a warning if they differ. It also shows
  *which of your accounts* would be drained.

Each co-sign authorizes **one** transaction from **one** account.

## Presignatures are single-use

Every `send` / `accept` consumes a presignature and triggers a background
interactive **re-presign** on a per-hash subject (`<id>/rotate/<hash>`) so rounds
never collide. If rotation fails, the consumed presignature is **deleted**,
never silently reused.
