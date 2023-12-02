package mpc

import (
	"fmt"
	"sync"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	"github.com/valli0x/signature-escrow/network/testnet"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
)

func TestKeygenCMP(t *testing.T) {
	var err error
	net1, send1 := testnet.NewNetwork()
	net2, send2 := testnet.NewNetwork()
	net1.SetSendCh(send2)
	net2.SetSendCh(send1)

	var configA, configB *cmp.Config

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		pl1 := pool.NewPool(0)
		defer pl1.TearDown()

		fmt.Println("start a keygen")
		configA, err = mpccmp.CMPKeygen("a", party.IDSlice{"a", "b"}, 1, net1, pl1)
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
		configB, err = mpccmp.CMPKeygen("b", party.IDSlice{"a", "b"}, 1, net2, pl2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end b keygen")
		wg.Done()
	}()

	wg.Wait()

	fmt.Println("config a")
	if err := mpccmp.PrintAddressPubKeyECDSA("a", configA); err != nil {
		t.Fatal("print address pub key a:", err)
	}

	fmt.Println("config b")
	if err := mpccmp.PrintAddressPubKeyECDSA("b", configB); err != nil {
		t.Fatal("print address pub key b:", err)
	}
}

func TestKeygenFROST(t *testing.T) {
	var err error
	net1, send1 := testnet.NewNetwork()
	net2, send2 := testnet.NewNetwork()
	net1.SetSendCh(send2)
	net2.SetSendCh(send1)

	var configA, configB *frost.TaprootConfig

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		fmt.Println("start a keygen")
		configA, err = mpcfrost.FrostKeygenTaproot("a", party.IDSlice{"a", "b"}, 1, net1)
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
		configB, err = mpcfrost.FrostKeygenTaproot("b", party.IDSlice{"a", "b"}, 1, net2)
		if err != nil {
			fmt.Println("error a", err)
			return
		}
		fmt.Println("end b keygen")
		wg.Done()
	}()

	wg.Wait()

	fmt.Println("config a")
	if err := mpcfrost.PrintAddressPubKeyTaproot("a", configA); err != nil {
		t.Fatal("print address pub key a:", err)
	}

	fmt.Println("config b")
	if err := mpcfrost.PrintAddressPubKeyTaproot("b", configB); err != nil {
		t.Fatal("print address pub key b:", err)
	}
}
