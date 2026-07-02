package config

import "os"

type Env struct {
	Mode string

	ServerAddr string
	JWTSecret  string

	ClientAddr string
	ClientAuth string

	Communication string
	NatsURL       string

	StoragePath string
	StoragePass string

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
		ClientAuth: getenv("CLIENT_AUTH", "on"),

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
