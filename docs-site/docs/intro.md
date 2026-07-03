---
slug: /
sidebar_position: 1
title: Overview
---

# mpcoven

**mpcoven** is a **2-of-2 MPC signature-escrow wallet**. Two parties jointly
control a wallet: no single party ever holds a full private key, and **every
transaction is signed together** using multi-party computation (MPC). Neither
side can move funds alone.

It supports:

- <span className="eth">Ethereum</span> — ECDSA via the **CMP** protocol.
- <span className="btc">Bitcoin</span> — Schnorr via **FROST** (Taproot).

On top of joint signing, mpcoven adds a **fair atomic swap** (escrow): two
parties can exchange value so that either both withdrawals settle or neither
does — no trusted third party holds funds.

## Why MPC instead of a multisig contract?

- **Chain-agnostic.** The signature is produced off-chain; on-chain it looks
  like an ordinary single-key transaction. The same design covers ETH and BTC
  without per-chain smart contracts.
- **No key ever exists whole.** Each party holds only a share. Compromising one
  device does not expose the key.
- **Cheaper & private.** No multisig contract, no extra gas, no on-chain hint
  that the account is shared.

## The pieces

| Component | Role |
| --- | --- |
| **Flutter app** | Desktop (macOS) / web UI. Orchestrates keygen, signing, swaps. |
| **Go client** | Holds this party's key **shares**; runs the local half of every MPC round. May be local or remote. |
| **Server** | Coordinator: mailbox, pairing, sessions, escrow pollination. Never sees key material. |
| **Relay** | JetStream (NATS) message bus that carries the MPC rounds between the two clients. |

## Where to go next

- [Architecture](./architecture) — how the pieces fit together.
- [Key generation](./keygen) — creating a shared account.
- [MPC co-signing](./mpc-cosigning) — how a joint transaction is signed & broadcast.
- [Atomic swap](./escrow-swap) — fair exchange via escrow pollination.
- [Authentication](./auth) — the two-login model (server + owner-bound client).
- [API reference](./api) · [Running it](./running).

:::tip Try it
The web wallet is live at **[mpcoven.net/app](https://mpcoven.net/app/)**.
:::
