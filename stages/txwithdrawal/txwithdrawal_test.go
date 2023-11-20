package txwithdrawal

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/blockcypher/gobcy/v2"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hashicorp/go-hclog"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network/redis"
)

const (
	ethURL   = ""
	gobcyToken = ""
)

// A getting BTC B and B getting ETH A
func TestTxBTC_ETH(t *testing.T) {
	logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
		Output:     os.Stdout,
		Level:      hclog.DefaultLevel,
		JSONFormat: false,
	})

	// setup network
	net1, err := redis.NewRedisNet("localhost:6379", "a", "b", logger.Named("a"))
	if err != nil {
		t.Fatal("net a error", err)
		return
	}

	net2, err := redis.NewRedisNet("localhost:6379", "b", "a", logger.Named("b"))
	if err != nil {
		t.Fatal("net a error", err)
	}

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
	txBTC, err := TxBTC(btcAPI, bitcoinAddrB, bitcoinAddrA, 1)
	if err != nil {
		t.Fatal("error a TxBTC", err)
	}
	hashBTC, err := HashBTC(txBTC)
	if err != nil {
		t.Fatal("error a HashBTC", err)
	}
	fmt.Println("hash BTC:", hex.EncodeToString(hashBTC))
	net1.Send(&protocol.Message{
		Data: hashBTC,
	})

	// send ETH tx
	txETH, err := TxETH(client, ethereumAddrA, ethereumAddrB, 0, 21000)
	if err != nil {
		t.Fatal("error b TxETH", err)
	}
	hashETH, err := HashETH(client, txETH, 1)
	if err != nil {
		t.Fatal("error b HashETH", err)
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
