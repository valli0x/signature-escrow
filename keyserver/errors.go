package keyserver

// Common error messages
const (
	ErrInvalidRequestBody     = "invalid request body: %v"
	ErrInvalidRequest         = "invalid request: %w"
	ErrNetworkSetupFailed     = "network setup failed: %w"
	ErrFailedToCreateStorage  = "failed to create encrypted storage: %v"
	ErrUnsupportedNetwork     = "unsupported network: %s"
	ErrFailedToMarshalMessage = "failed to marshal message: %v"
	ErrFailedToUnmarshalMsg   = "failed to unmarshal message: %v"
	ErrInvalidHashFormat      = "invalid hash format: %v"
	ErrUnknownAlgorithm       = "unknown alg(frost or ecdsa)"
	ErrFrostNotImplemented    = "FROST algorithm not implemented yet"
)

// ID generation errors
const (
	ErrFailedToGenerateMyID      = "failed to generate my ID: %w"
	ErrFailedToGenerateAnotherID = "failed to generate another ID: %w"
)

// Keygen errors
const (
	ErrNameMyIDAnotherRequired = "name, my_id, and another_id are required"
	ErrECDSAKeygenFailed       = "ECDSA keygen failed: %w"
	ErrECDSAPresignFailed      = "ECDSA presign failed: %w"
	ErrFailedToGetAddress      = "failed to get address: %w"
	ErrFailedToGetPublicKey    = "failed to get public key: %w"
	ErrFailedToMarshalConfig   = "failed to marshal config: %w"
	ErrFailedToMarshalPresign  = "failed to marshal presignature: %w"
	ErrFailedToSaveConfig      = "failed to save config: %w"
	ErrFailedToSavePresign     = "failed to save presignature: %w"
	ErrFrostKeygenFailed       = "FROST keygen failed: %w"
)

// Balance check errors
const (
	ErrNetworkAddressExpectedRequired = "network, address and expected amount are required"
	ErrFailedToCheckBalance           = "failed to check balance: %v"
	ErrFailedToWaitForEthereumBalance = "failed to wait for Ethereum balance: %v"
	ErrFailedToWaitForBitcoinBalance  = "failed to wait for Bitcoin balance: %v"
)

// Transaction errors
const (
	ErrNetworkFromToAmountRequired   = "network, from, to and amount are required"
	ErrFailedToCreateTxHash          = "failed to create transaction hash: %v"
	ErrNetworkFromToValueSigRequired = "network, from, to, value and signature are required"
	ErrFailedToSendTransaction       = "failed to send transaction: %v"
)

// Withdrawal errors
const (
	ErrAlgNameEscrowHashRequired = "alg, name, escrow_address and hash_tx are required"
	ErrAlgNameEscrowRequired     = "alg, name and escrow_address are required"
	ErrFailedToGetConfig         = "failed to get config: %v"
	ErrFailedToUnmarshalConfig   = "failed to unmarshal config: %v"
	ErrFailedToGetPresign        = "failed to get presign: %v"
	ErrFailedToUnmarshalPresign  = "failed to unmarshal presign: %v"
	ErrFailedToCreateIncSig      = "failed to create incomplete signature: %v"
	ErrFailedToConvertSigToHex   = "failed to convert signature to hex: %v"
	ErrFailedToConvertHexToMsg   = "failed to convert hex to message: %v"
	ErrFailedToCompleteSig       = "failed to complete signature: %v"
	ErrFailedToGetSigBytes       = "failed to get signature bytes: %v"
)
