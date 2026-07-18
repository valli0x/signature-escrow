package client

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestERC20SelectorsMatchSignatures(t *testing.T) {
	cases := map[string][]byte{
		"transfer(address,uint256)": selTransfer,
		"balanceOf(address)":        selBalanceOf,
	}
	for sig, want := range cases {
		got := crypto.Keccak256([]byte(sig))[:4]
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("%s: selector %x != %x", sig, want, got)
		}
	}
}

func TestERC20TransferRoundTrip(t *testing.T) {
	to := common.HexToAddress("0x8ad6561019a9b6f3dFB31A7630a2c6271194B7f1")
	amount := big.NewInt(25_000_000) // 25 USDT (6 decimals)

	data := erc20TransferData(to, amount)
	if len(data) != 68 {
		t.Fatalf("calldata len = %d, want 68", len(data))
	}

	rTo, rAmount, ok := decodeERC20Transfer(data)
	if !ok {
		t.Fatal("failed to decode our own transfer calldata")
	}
	if rTo != to {
		t.Fatalf("recipient %s != %s", rTo, to)
	}
	if rAmount.Cmp(amount) != 0 {
		t.Fatalf("amount %s != %s", rAmount, amount)
	}
}

func TestDecodeERC20RejectsNonTransfer(t *testing.T) {
	// native tx (no data)
	if _, _, ok := decodeERC20Transfer(nil); ok {
		t.Fatal("nil data decoded as transfer")
	}
	// wrong selector, right length
	bad := make([]byte, 68)
	copy(bad, []byte{0xde, 0xad, 0xbe, 0xef})
	if _, _, ok := decodeERC20Transfer(bad); ok {
		t.Fatal("wrong selector decoded as transfer")
	}
	// right selector, wrong length
	short := append([]byte{}, selTransfer...)
	if _, _, ok := decodeERC20Transfer(short); ok {
		t.Fatal("truncated data decoded as transfer")
	}
}
