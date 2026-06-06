// Package main — Swagger general API info for the signature-escrow service.
//
// The single binary runs in three modes (MODE env): server, client,
// communication. The HTTP APIs documented here belong to the "server" (host
// API, default :8282) and "client" (local participant API, default :8080)
// modes. Swagger UI is served by each at /swagger/index.html.
//
//	@title			Signature Escrow API
//	@version		1.0
//	@description	MPC 2-of-2 signature escrow wallet. Host (server) endpoints
//	@description	handle auth, pairing, mailbox, keygen-session arbitration,
//	@description	escrow and timebox. Local (client) endpoints handle keygen,
//	@description	accounts, exchanges, balance, transactions and withdrawals.
//	@description	Server endpoints under /v1 (except /auth) require a Bearer JWT.
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				JWT obtained from /v1/auth/login, sent as "Bearer <token>".
//
//	@tag.name	auth
//	@tag.description	Host: nonce + EIP-191 login -> JWT
//	@tag.name	pair
//	@tag.description	Host: pairing between two ETH addresses
//	@tag.name	mailbox
//	@tag.description	Host: message relay between paired participants
//	@tag.name	session
//	@tag.description	Host: atomic keygen claim/cancel arbitration
//	@tag.name	escrow
//	@tag.description	Host: escrow signature exchange
//	@tag.name	timebox
//	@tag.description	Host: time-locked withdrawal fallback
//	@tag.name	keygen
//	@tag.description	Client: ECDSA/FROST shared key generation
//	@tag.name	accounts
//	@tag.description	Client: shared accounts (list/get/delete)
//	@tag.name	exchanges
//	@tag.description	Client: linked-account exchanges (CRUD)
//	@tag.name	balance
//	@tag.description	Client: on-chain balance checks
//	@tag.name	tx
//	@tag.description	Client: transaction hash + send
//	@tag.name	incomplete-signature
//	@tag.description	Client: incomplete-signature withdrawal flow
package main
