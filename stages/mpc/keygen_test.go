package keygen

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
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
