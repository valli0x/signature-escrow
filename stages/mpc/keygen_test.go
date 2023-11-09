package keygen

import (
	crypto_ecdsa "crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/go-hclog"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/mpc/btcfrost"
	"github.com/valli0x/signature-escrow/stages/mpc/ethcmp"
)

func TestKeygenCMP(t *testing.T) {
	logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
		Output:     os.Stdout,
		Level:      hclog.DefaultLevel,
		JSONFormat: false,
	})

	net1, err := redis.NewRedisNet("localhost:6379", "a", "b", logger.Named("a"))
	if err != nil {
		t.Fatal("net a error", err)
		return
	}

	net2, err := redis.NewRedisNet("localhost:6379", "b", "a", logger.Named("b"))
	if err != nil {
		t.Fatal("net a error", err)
	}

	var configA, configB *cmp.Config

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		pl1 := pool.NewPool(0)
		defer pl1.TearDown()

		fmt.Println("start a keygen")
		configA, err = ethcmp.CMPKeygen("a", party.IDSlice{"a", "b"}, 1, net1, pl1)
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
		configB, err = ethcmp.CMPKeygen("b", party.IDSlice{"a", "b"}, 1, net2, pl2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end b keygen")
		wg.Done()
	}()

	wg.Wait()

	if err := PrintAddressPubKeyECDSA("a", configA, logger.NamedIntercept("a")); err != nil {
		t.Fatal("print address pub key a:", err)
	}

	if err := PrintAddressPubKeyECDSA("b", configB, logger.NamedIntercept("b")); err != nil {
		t.Fatal("print address pub key b:", err)
	}
}

func PrintAddressPubKeyECDSA(name string, c *cmp.Config, logger hclog.InterceptLogger) error {
	pubkeyECDSA, err := GetPubKeyFromConfigECDSA(c)
	if err != nil {
		return err
	}

	pub := crypto.FromECDSAPub(pubkeyECDSA)
	address := crypto.PubkeyToAddress(*pubkeyECDSA).Hex()

	fmt.Println("config", name)
	logger.Info("ETH info", "address", address)
	logger.Info("ETH info", "public key", hex.EncodeToString(pub))
	return nil
}

func GetPubKeyFromConfigECDSA(keygenConfig *cmp.Config) (*crypto_ecdsa.PublicKey, error) {
	// get from address
	publicKey, _ := keygenConfig.PublicPoint().MarshalBinary()
	publicKeyECDSA, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		return nil, err
	}

	return publicKeyECDSA, nil
}

func TestKeygenFROST(t *testing.T) {
	logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
		Output:     os.Stdout,
		Level:      hclog.DefaultLevel,
		JSONFormat: false,
	})

	net1, err := redis.NewRedisNet("localhost:6379", "a", "b", logger.Named("a"))
	if err != nil {
		t.Fatal("net a error", err)
		return
	}

	net2, err := redis.NewRedisNet("localhost:6379", "b", "a", logger.Named("b"))
	if err != nil {
		t.Fatal("net a error", err)
	}

	var configA, configB *frost.TaprootConfig

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		fmt.Println("start a keygen")
		configA, err = btcfrost.FrostKeygenTaproot("a", party.IDSlice{"a", "b"}, 1, net1)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end a keygen")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		fmt.Println("start b keygen")
		configB, err = btcfrost.FrostKeygenTaproot("b", party.IDSlice{"a", "b"}, 1, net2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end b keygen")
		wg.Done()
	}()

	wg.Wait()

	if err := PrintAddressPubKeyTaproot("a", configA, logger.NamedIntercept("a")); err != nil {
		t.Fatal("print address pub key a:", err)
	}

	if err := PrintAddressPubKeyTaproot("b", configB, logger.NamedIntercept("b")); err != nil {
		t.Fatal("print address pub key b:", err)
	}
}

func PrintAddressPubKeyTaproot(name string, c *frost.TaprootConfig, logger hclog.InterceptLogger) error {
	pubkeyECDSA, err := GetPubKeyFromConfigTaproot(c)
	if err != nil {
		return err
	}

	pub := crypto.FromECDSAPub(pubkeyECDSA)
	address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub), &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	fmt.Println("config", name)
	logger.Info("BTC info", "address", address)
	logger.Info("BTC info", "public key", hex.EncodeToString(pub))
	return nil
}

func GetPubKeyFromConfigTaproot(keygenConfig *frost.TaprootConfig) (*crypto_ecdsa.PublicKey, error) {
	publicKeyECDSA, err := schnorr.ParsePubKey(keygenConfig.PublicKey)
	if err != nil {
		return nil, err
	}
	
	return publicKeyECDSA.ToECDSA(), nil
}
