---
sidebar_position: 3
title: Key generation
---

# Key generation

A shared account is created by running a distributed key-generation (DKG)
protocol between the two paired clients. When it finishes, **each client holds
one share** and both agree on the same public key / address. No party ever sees
the full private key.

## Prerequisites

The two parties must first be **paired** (each knows the other's ETH address and
the server records the pair). Pairing is done from the app's Pairing tab.

## The flow

1. **Initiator** picks a protocol (<span className="eth">ECDSA/CMP</span> or
   <span className="btc">FROST</span>) and a partner, then presses *Generate*.
   The app sends a `keygen-init` message to the partner's mailbox and starts its
   own half on its local client.
2. **Partner** accepts the invite. Before running, it calls the server's atomic
   `session/claim` — if the initiator already cancelled, the claim fails and the
   keygen aborts cleanly instead of hanging.
3. Both clients run the DKG rounds over the relay. On success each stores its
   share; the app refreshes and the new account appears automatically.

## Parallel jobs

Keygen is modelled as independent **jobs** — the *Generate* button is never
disabled, so multiple key generations run at once, each as its own card
(running / done / failed). Account indices are reserved for in-flight jobs so
two concurrent ETH keygens never collide on the same index.

## Cancellation

Cancelling a running job calls the authoritative `session/cancel` on the server
and sends a `keygen-cancel` to the partner. A background poll drops stale
`keygen-init` invites whose session was cancelled, so neither side is left with
a dead keygen.
