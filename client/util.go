package client

import (
	"fmt"
	"regexp"
	"strings"
)

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

func validateSessionID(id string) error {
	if len(id) > 36 {
		return fmt.Errorf("session_id too long (max 36 characters)")
	}
	if !uuidRe.MatchString(id) {
		return fmt.Errorf("session_id must be a valid UUID format")
	}
	return nil
}

func validateNetwork(network string) error {
	if network != "eth" && network != "btc" {
		return fmt.Errorf("network must be 'eth' or 'btc'")
	}
	return nil
}

func validateIndex(index int) error {
	if index < 1 || index > 100 {
		return fmt.Errorf("index must be between 1 and 100")
	}
	return nil
}

func validateETHAddress(addr string) error {
	if !ethAddrRe.MatchString(addr) {
		return fmt.Errorf("invalid ETH address: %s", addr)
	}
	return nil
}
