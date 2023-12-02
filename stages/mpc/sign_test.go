package mpc

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	"github.com/valli0x/signature-escrow/network/testnet"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/validation"
)

var (
	cmpConfA = "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" +
		"bfe4hMoAq8banRqUx0="

	cmpConfB = "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" +
		"6Iip/0nfRWmAsD8" +
		"dJE02XlTRZcPuW6Ou4dR8pPiiWJAiwXUmub/agE8myTgIMwyAV7LV7VYP/JaTYzQ3I0vVXnH5RAGaPobteUpHXW1HRzcPs3poCE" +
		"nwVnT2p0Tla3TrW/7DU4MdQyls/iGftitepyggA92hT10aQqumewHyS2czseR0H6b19NKX5MHLXg/wcFtGalHT0jBBwG+fSlhU1k" +
		"BAHehleWkByVK7Bq+3bPGabli5HttOUkvxi69zhaKD4+AYr+Bc5iwiLPkbiB9mDhQeftswaK6KJ9jiUcKBVuRdDmUYJNQDI/b4gM" +
		"2b/o0fb+Kz5GP6XbiiKrErWx4B4KxO3FpuZ/MF0Hj2jh0pXLjAMkAGQA1YPWUVg8mwqh3rWNkZGoNluQRjb04jNR8489B6S7wu1s" +
		"2fPROmJlLblTvfGqYmJH9eRiOpHzvgZyGZcxEGIHMUT98wMHfK27xuIG/0UXLBSdMZPPbIXpI6co1ktwbM81Pip/BZ9Ot5qH/9hr" +
		"M/KCpRqOWUZANFTBvLIUQsXCC6MQDCwKkDj8HC6/lFR9hVFkBACz5m20GNZwL+ceigEvbizp/SmUBD7vJroCpR+xjk9J3TpgHW1k" +
		"SetwR2+hKz6M9xH0G4w/iZ9fMoSRg91nJIrsJ5GGBEz8Rq1fXICjt1uxXTUrvQzvC/Z1aV5G/ud2ONkZwkbRWspZZFujbvLdwYoX" +
		"LMNkpCl+TZ3WIEhEG4j3FBXO5dhUvb70HWW5u95RBL2ctbTnE3v+zvgFUFm7da8ed1bQl+m3hYIOwBBU2ZQAqUZvty7rr/dA+JI8" +
		"SZTlcdRQBCUzxZx/iZ3Zps97PMc8L5a4V3lDeEbp03imOxv9VCYsA5zgQWwgzp/WayKBJqXJH3bfe4hMoAq8banRqUx0="
)

var (
	configAcmp, configBcmp = cmp.EmptyConfig(curve.Secp256k1{}), cmp.EmptyConfig(curve.Secp256k1{})
)

func init() {
	dataAcmp, _ := base64.StdEncoding.DecodeString(cmpConfA)
	dataBcmp, _ := base64.StdEncoding.DecodeString(cmpConfB)

	configAcmp.UnmarshalBinary(dataAcmp)
	configBcmp.UnmarshalBinary(dataBcmp)
}

func TestSignCMP(t *testing.T) {
	net1, send1 := testnet.NewNetwork()
	net2, send2 := testnet.NewNetwork()
	net1.SetSendCh(send2)
	net2.SetSendCh(send1)

	signers := party.IDSlice{"a", "b"}
	msg := []byte("hello")

	var signatureA, signatureB *ecdsa.Signature

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		pl := pool.NewPool(0)
		defer pl.TearDown()

		presignA, err := mpccmp.CMPPreSign(configAcmp, signers, net1, pl)
		if err != nil {
			fmt.Println("error b", err)
			return
		}
		signatureA, err = mpccmp.CMPPreSignOnline(configAcmp, presignA, msg, net1, pl)
		if err != nil {
			fmt.Println("error b", err)
			return
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		pl := pool.NewPool(0)
		defer pl.TearDown()

		presignB, err := mpccmp.CMPPreSign(configBcmp, signers, net2, pl)
		if err != nil {
			fmt.Println("error b", err)
			return
		}
		signatureB, err = mpccmp.CMPPreSignOnline(configBcmp, presignB, msg, net2, pl)
		if err != nil {
			fmt.Println("error b", err)
			return
		}

		wg.Done()
	}()
	wg.Wait()

	sigAbyte, err := mpccmp.GetSigByte(signatureA)
	if err != nil {
		t.Fatal(err)
	}

	sigBbyte, err := mpccmp.GetSigByte(signatureB)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("check signatures")
	p, err := mpccmp.GetPublicKeyByte(configAcmp)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := validation.Validate(validation.Alg("ETH"), p, msg, sigBbyte)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("public key a is not valid with signature b")
	}

	p, err = mpccmp.GetPublicKeyByte(configBcmp)
	if err != nil {
		t.Fatal(err)
	}

	valid, err = validation.Validate(validation.Alg("ETH"), p, msg, sigAbyte)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("public key b is not valid with signature a")
	}
}

func TestSignFROST(t *testing.T) {
	configAfrost, configBfrost := createConfigs()
	fmt.Println("creating configs")

	var err error
	net1, send1 := testnet.NewNetwork()
	net2, send2 := testnet.NewNetwork()
	net1.SetSendCh(send2)
	net2.SetSendCh(send1)

	signers := party.IDSlice{"a", "b"}
	msg := []byte("hello")

	var sigA, sigB []byte

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		sigA, err = mpcfrost.FrostSignTaproot(configAfrost, msg, signers, net1)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		sigB, err = mpcfrost.FrostSignTaproot(configBfrost, msg, signers, net2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		wg.Done()
	}()
	wg.Wait()

	fmt.Println("check signatures")

	valid, err := validation.Validate(validation.Alg("BTC"), configAfrost.PublicKey, msg, sigB)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("public key a is not valid with signature b")
	}

	valid, err = validation.Validate(validation.Alg("BTC"), configBfrost.PublicKey, msg, sigA)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("public key b is not valid with signature a")
	}
}

func createConfigs() (*frost.TaprootConfig, *frost.TaprootConfig) {
	var err error
	net1, send1 := testnet.NewNetwork()
	net2, send2 := testnet.NewNetwork()
	net1.SetSendCh(send2)
	net2.SetSendCh(send1)

	var configA, configB *frost.TaprootConfig

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		configA, err = mpcfrost.FrostKeygenTaproot("a", party.IDSlice{"a", "b"}, 1, net1)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		configB, err = mpcfrost.FrostKeygenTaproot("b", party.IDSlice{"a", "b"}, 1, net2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		wg.Done()
	}()
	wg.Wait()

	return configA, configB
}
