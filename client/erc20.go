package client

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ERC-20 4-byte function selectors (keccak256 of the signature, first 4 bytes).
var (
	selTransfer  = []byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
	selBalanceOf = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
)

// erc20TransferData builds the calldata for transfer(to, amount):
// selector ‖ 32-byte left-padded address ‖ 32-byte amount.
func erc20TransferData(to common.Address, amount *big.Int) []byte {
	data := make([]byte, 0, 4+32+32)
	data = append(data, selTransfer...)
	data = append(data, common.LeftPadBytes(to.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(amount.Bytes(), 32)...)
	return data
}

// decodeERC20Transfer parses transfer(to, amount) calldata. ok=false if the data
// is not a well-formed ERC-20 transfer.
func decodeERC20Transfer(data []byte) (to common.Address, amount *big.Int, ok bool) {
	if len(data) != 4+32+32 {
		return common.Address{}, nil, false
	}
	for i := 0; i < 4; i++ {
		if data[i] != selTransfer[i] {
			return common.Address{}, nil, false
		}
	}
	// address is right-aligned in the first 32-byte word after the selector.
	to = common.BytesToAddress(data[4+12 : 4+32])
	amount = new(big.Int).SetBytes(data[4+32 : 4+64])
	return to, amount, true
}

// erc20BalanceOf calls balanceOf(holder) on the token contract.
func erc20BalanceOf(ctx context.Context, ec *ethclient.Client, token, holder common.Address) (*big.Int, error) {
	data := make([]byte, 0, 4+32)
	data = append(data, selBalanceOf...)
	data = append(data, common.LeftPadBytes(holder.Bytes(), 32)...)
	out, err := ec.CallContract(ctx, ethereum.CallMsg{To: &token, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("balanceOf call: %w", err)
	}
	if len(out) == 0 {
		return big.NewInt(0), nil
	}
	return new(big.Int).SetBytes(out), nil
}
