---
sidebar_position: 2
title: Architecture
---

# Architecture

mpcoven is three programs plus a message relay. The **two parties each run their
own app + client**; they share one server and one relay.

```
        Party A                         Party B
   ┌──────────────┐                ┌──────────────┐
   │  Flutter app │                │  Flutter app │
   └──────┬───────┘                └───────┬──────┘
          │ HTTP                           │ HTTP
   ┌──────▼───────┐                ┌───────▼──────┐
   │  Go client A │  key shares    │  Go client B │  key shares
   │   (:8080)    │                │   (:8081)    │
   └──────┬───────┘                └───────┬──────┘
          │        MPC rounds (relay)      │
          └──────────────┬────────────────┘
                         │
                 ┌───────▼────────┐        ┌──────────────┐
                 │  Relay (NATS   │        │    Server    │
                 │  JetStream)    │        │  mailbox /   │
                 │                │        │  pairing /   │
                 └────────────────┘        │  escrow      │
                                           └──────────────┘
```

## Flutter app

The UI and orchestrator. It never touches key material — it drives the client
over HTTP and the server for coordination. State lives in a single provider
(`AppProvider`). Targets **macOS desktop** and **web** (`mpcoven.net/app`).

## Go client (key holder)

Holds **this party's shares** for every account and runs the local half of each
MPC round (keygen, signing, presignature rotation). One binary, three modes
(`client` / `server` / `communication`), selected by `MODE`.

The client may run **off the user's machine**, so it has its own
[authentication](./auth) and binds to a single owner address.

Two clients never talk directly — they exchange MPC rounds through the relay on
per-hash subjects so concurrent operations never collide.

## Server (coordinator)

A shared, multi-tenant service that holds **no key material**. It provides:

- **Mailbox** — typed messages between paired parties (keygen invites, sign
  requests, exchange proposals).
- **Pairing** — establishing that two ETH addresses are partners.
- **Sessions** — an atomic claim/cancel registry that resolves keygen races.
- **Escrow pollination** — the fair-swap settlement primitive.

## Relay (JetStream)

A NATS JetStream **WorkQueue** carries the MPC protocol rounds. Presignatures
are single-use and re-generated in the background after each signature; co-sign
and rotation run on **per-hash subjects** (`<id>/cosign/<hash>`,
`<id>/rotate/<hash>`) so parallel operations never cross streams.

## Trust model

- The **server is untrusted** for custody: it coordinates but cannot sign or
  move funds. A compromised server cannot authorize a withdrawal — that needs
  both clients' shares.
- Each **client authenticates the human owner independently** (see
  [Authentication](./auth)), so being reachable on the network is not enough to
  operate its keys.
