package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	crypto_ecdsa "crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/go-hclog"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/keygen/eth"
)

func main() {
	logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
		Output:     os.Stdout,
		Level:      hclog.DefaultLevel,
		JSONFormat: false,
	})

	net1, err := redis.NewRedisNet("localhost:6379", "a", "b", logger.Named("a"))
	if err != nil {
		fmt.Println("net a error", err)
		return
	}

	net2, err := redis.NewRedisNet("localhost:6379", "b", "a", logger.Named("b"))
	if err != nil {
		fmt.Println("net a error", err)
		return
	}

	var configA, configB *cmp.Config

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		pl1 := pool.NewPool(0)
		defer pl1.TearDown()

		fmt.Println("start a keygen")
		configA, err = eth.CMPKeygen("a", party.IDSlice{"a", "b"}, 1, net1, pl1)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end a keygen")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		pl2 := pool.NewPool(0)
		defer pl2.TearDown()

		fmt.Println("start b keygen")
		configB, err = eth.CMPKeygen("b", party.IDSlice{"a", "b"}, 1, net2, pl2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end b keygen")
		wg.Done()
	}()

	wg.Wait()

	PrintAddressPubKey("a", configA, logger.NamedIntercept("a"))
	PrintAddressPubKey("b", configB, logger.NamedIntercept("b"))
}

func PrintAddressPubKey(name string, c *cmp.Config, logger hclog.InterceptLogger) {
	pubkeyECDSA, err := GetPubKeyFromConfig(c)
	if err != nil {
		fmt.Println("config a", err)
		return
	}

	pub := crypto.FromECDSAPub(pubkeyECDSA)
	address := crypto.PubkeyToAddress(*pubkeyECDSA).Hex()

	fmt.Println("config", name)
	logger.Info("ETH info", "address", address)
	logger.Info("ETH info", "public key", hex.EncodeToString(pub))
}

func GetPubKeyFromConfig(keygenConfig *cmp.Config) (*crypto_ecdsa.PublicKey, error) {
	// get from address
	publicKey, _ := keygenConfig.PublicPoint().MarshalBinary()
	publicKeyECDSA, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		return nil, err
	}

	return publicKeyECDSA, nil
}
