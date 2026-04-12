package client

import "strings"

// normalizePartyID converts an identifier (ETH address or UUID) to a party ID.
// Strips "0x" prefix and dashes, returns lowercase.
func normalizePartyID(id string) string {
	id = strings.ToLower(id)
	id = strings.TrimPrefix(id, "0x")
	id = strings.ReplaceAll(id, "-", "")
	return id
}
