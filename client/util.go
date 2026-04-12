package client

import (
	"fmt"
	"regexp"
	"strings"
)

// normalizePartyID converts an identifier (ETH address or UUID) to a party ID.
// Strips "0x" prefix and dashes, returns lowercase.
func normalizePartyID(id string) string {
	id = strings.ToLower(id)
	id = strings.TrimPrefix(id, "0x")
	id = strings.ReplaceAll(id, "-", "")
	return id
}

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	ethAddrRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
)

// validateSessionID checks that session_id is a valid UUID (max 36 chars).
func validateSessionID(id string) error {
	if len(id) > 36 {
		return fmt.Errorf("session_id too long (max 36 characters)")
	}
	if !uuidRe.MatchString(id) {
		return fmt.Errorf("session_id must be a valid UUID format")
	}
	return nil
}

// validateNetwork checks that network is "eth" or "btc".
func validateNetwork(network string) error {
	if network != "eth" && network != "btc" {
		return fmt.Errorf("network must be 'eth' or 'btc'")
	}
	return nil
}

// validateIndex checks that index is between 1 and 100.
func validateIndex(index int) error {
	if index < 1 || index > 100 {
		return fmt.Errorf("index must be between 1 and 100")
	}
	return nil
}

// validateETHAddress checks that the string is a valid Ethereum address (0x + 40 hex chars).
func validateETHAddress(addr string) error {
	if !ethAddrRe.MatchString(addr) {
		return fmt.Errorf("invalid ETH address: %s", addr)
	}
	return nil
}
