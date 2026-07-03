---
sidebar_position: 5
title: Atomic swap (escrow)
---

# Atomic swap via escrow pollination

An **exchange** links two escrow accounts and lets two parties swap value fairly:
either **both** withdrawals settle or **neither** does. No third party ever
holds funds — settlement is enforced by the server's *pollination* primitive.

## Exchange = a shared, per-side object

An exchange links two escrow accounts. Each side has its own partner and invite
status (`address_a / partner_a / status_a` and the `_b` counterparts), plus a
**creator**. The binding is explicit:

- the **creator** withdraws from **escrow A**,
- the **partner** withdraws from **escrow B**.

This binding is what stops both parties from racing to drain the *same* account.

## The swap

Both parties run a [co-signing withdrawal](./mpc-cosigning), but instead of
broadcasting immediately, each **deposits** its completed signature (a "flower")
into escrow under a shared pollination `id` (the exchange id):

```
POST /v1/escrow          deposit  { id, pub, hash, sig }
POST /v1/escrow/check    poll     { id, pub }  -> released sig | "pending"
```

The server validates the two flowers **crosswise** and releases each party
*their own* withdrawal signature **only when both are valid**. Then each party
broadcasts its released transaction (Activity → *Send Transaction*).

Because the pollination id is the exchange id, **multiple concurrent swaps** are
independent.

## One co-sign per swap

The backend rejects a second `accept` for the same `escrow_id` (it scans the
co-sign history for an existing completed acceptor event) — so a party can be
tricked into co-signing **at most one** withdrawal per swap.

:::warning Status
The escrow **release** path is not yet fully verified end-to-end with two live
parties. The open item is whether the server's validator accepts the 65-byte
`SigEthereum` flower format in pollination. A time-locked unilateral fallback
(**timebox**) exists on the server but is not yet wired into the app.
:::
