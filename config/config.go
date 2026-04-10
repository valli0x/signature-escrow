package config

import "os"

type Env struct {
	// Mode: "server", "client", "communication"
	Mode string

	// Server
	ServerAddr string
	JWTSecret  string

	// Client
	ClientAddr string

	// Communication
	Communication string
	NatsURL       string

	// Storage
	StoragePath string
	StoragePass string

	// Blockchain
	EscrowServer     string
	EthereumRPC      string
	BlockCypherToken string
}

func LoadFromEnv() *Env {
	return &Env{
		Mode: getenv("MODE", "server"),

		ServerAddr: getenv("SERVER_ADDR", ":8282"),
		JWTSecret:  getenv("JWT_SECRET", ""),

		ClientAddr: getenv("CLIENT_ADDR", ":8080"),

		Communication: getenv("COMMUNICATION_ADDR", "localhost:6379"),
		NatsURL:       getenv("NATS_URL", "nats://localhost:4222"),

		StoragePath: getenv("STORAGE_PATH", "./data"),
		StoragePass: getenv("STORAGE_PASS", ""),

		EscrowServer:     getenv("ESCROW_SERVER", "localhost:8282"),
		EthereumRPC:      getenv("ETHEREUM_RPC", ""),
		BlockCypherToken: getenv("BLOCKCYPHER_TOKEN", ""),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
