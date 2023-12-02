package txwithdrawal

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blockcypher/gobcy/v2"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network/testnet"
)

const (
	ethURL     = ""
	gobcyToken = ""
)

// A getting BTC B and B getting ETH A
func TestTxBTC_ETH(t *testing.T) {
	var err error
	net1, send1 := testnet.NewNetwork()
	net2, send2 := testnet.NewNetwork()
	net1.SetSendCh(send2)
	net2.SetSendCh(send1)

	// setup btc network
	btcAPI := gobcy.API{Token: gobcyToken, Coin: "btc", Chain: "main"}

	// setup eth network
	client, err := ethclient.Dial(ethURL)
	if err != nil {
		t.Fatal("net a error", err)
		return
	}

	// BTC and ETH addresses
	bitcoinAddrA := "3HJJTwitVttoZVmYKgBD7c7CqqazWr8Nhv"
	bitcoinAddrB := "1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE"

	ethereumAddrA := "0xD87a8b63aFdD130Fa2264B4fd3D670ce35E7771B"
	ethereumAddrB := "0x31F9E5CF25de6faE56eb971D6e788C0B62F8f139"

	// send BTC tx
	_, hashBTC, err := TxBTC(btcAPI, bitcoinAddrB, bitcoinAddrA, 1)
	if err != nil {
		t.Fatal("error a TxBTC", err)
	}
	fmt.Println("hash BTC:", hex.EncodeToString(hashBTC))
	net1.Send(&protocol.Message{
		Data: hashBTC,
	})

	// send ETH tx
	_, hashETH, err := TxETH(client, ethereumAddrA, ethereumAddrB, 0, 21000, 1)
	if err != nil {
		t.Fatal("error b TxETH", err)
	}
	fmt.Println("hash ETH:", hex.EncodeToString(hashETH))
	net2.Send(&protocol.Message{
		Data: hashETH,
	})

	msg := <-net1.Next()
	fmt.Println("a len:", len(msg.Data))

	msg2 := <-net2.Next()
	fmt.Println("b len:", len(msg2.Data))
}
