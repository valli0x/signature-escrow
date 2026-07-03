---
sidebar_position: 8
title: Running it
---

# Running it

The backend is one binary with three modes; a relay ties the two clients
together. On a server, everything runs under Docker Compose behind nginx.

## Modes

Set `MODE` to pick a role:

- `server` — coordinator (mailbox, pairing, escrow). `SERVER_ADDR=:8282`.
- `client` — key holder. `CLIENT_ADDR=:8080`, `STORAGE_PATH=./data`.
- `communication` — the relay endpoint the clients dial.

## Key environment variables

| Variable | Meaning |
| --- | --- |
| `MODE` | `server` / `client` / `communication` |
| `CLIENT_ADDR` | client listen address (`:8080`) |
| `CLIENT_AUTH` | `on` (default) or `none` to disable client login for a local client |
| `JWT_SECRET` | HMAC secret for tokens (client falls back to `STORAGE_PASS`, else random) |
| `STORAGE_PATH` / `STORAGE_PASS` | encrypted key-share storage |
| `COMMUNICATION_ADDR` / `COMMUNICATION_TLS` | relay endpoint (`mpcoven.net:443`, TLS on) |
| `ETHEREUM_RPC` | ETH RPC (defaults to a public node) |

## Two participants on one machine

Run two clients on different ports and storage dirs:

```bash
MODE=client CLIENT_ADDR=:8080 STORAGE_PATH=./data-a COMMUNICATION_ADDR=mpcoven.net:443 COMMUNICATION_TLS=true ./signature-escrow
MODE=client CLIENT_ADDR=:8081 STORAGE_PATH=./data-b COMMUNICATION_ADDR=mpcoven.net:443 COMMUNICATION_TLS=true ./signature-escrow
```

Point one app window at `:8080` and the other at `:8081` (the login screen shows
which client you are connecting to and which owner address it expects).

## Production

On the server, `docker compose` runs the relay, server, both demo clients, NATS,
and an nginx (with Brotli) that terminates TLS and routes `/` (site), `/app/`
(the Flutter wallet), `/docs/` (this documentation), `/api/` (server), and the
gRPC relay.
