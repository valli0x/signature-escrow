package escrowbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/vault/sdk/logical"
)

type SignaturesType string

const (
	ecdsaType   SignaturesType = "ecdsa"
	schnorrType SignaturesType = "schnorr"
)

func Validate(alg SignaturesType, p, h, s []byte) (bool, error) {
	switch alg {
	case ecdsaType:
		return crypto.VerifySignature(p, h, s), nil
	case schnorrType:
		sig, err := schnorr.ParseSignature(s)
		if err != nil {
			return false, err
		}
		pub, err := schnorr.ParsePubKey(p)
		if err != nil {
			return false, nil
		}
		return sig.Verify(h, pub), nil
	default:
		return false, errors.New("unknown alg type")
	}
}

type Pollination struct {
	Flower1, Flower2 *flower
	Pollinated       bool
}

type pollinationMarshal struct {
	Flower1, Flower2 *flower
	Pollinated       bool
}

type flower struct {
	ID             string
	Alg            SignaturesType
	Pub, Hash, Sig []byte
}

func (p *Pollination) Pollinate() (bool, error) {
	f1 := p.Flower1
	f2 := p.Flower2

	f1Pollinated, err := Validate(f1.Alg, f1.Pub, f1.Hash, f2.Sig)
	if err != nil {
		return false, err
	}

	f2Pollinated, err := Validate(f2.Alg, f2.Pub, f2.Hash, f1.Sig)
	if err != nil {
		return false, err
	}

	p.Pollinated = f1Pollinated && f2Pollinated
	return p.Pollinated, nil
}

func (p *Pollination) AddFlower(flower *flower) {
	if p.Flower1 == nil || bytes.Equal(p.Flower1.Pub, flower.Pub) {
		p.Flower1 = flower
	}
	if p.Flower2 == nil || bytes.Equal(p.Flower2.Pub, flower.Pub) {
		p.Flower2 = flower
	}
}

func (p *Pollination) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(&pollinationMarshal{
		Flower1:    p.Flower1,
		Flower2:    p.Flower2,
		Pollinated: p.Pollinated,
	})
}

func (p *Pollination) UnmarshalBinary(data []byte) error {
	pm := &pollinationMarshal{}
	if err := cbor.Unmarshal(data, pm); err != nil {
		return err
	}
	p.Flower1 = pm.Flower1
	p.Flower2 = pm.Flower2
	p.Pollinated = pm.Pollinated
	return nil
}

func GetPollination(id string, storage logical.Storage) (*Pollination, error) { // TODO
	entry, err := storage.Get(context.Background(), id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("entry not found")
	}
	p := &Pollination{}
	if err := p.UnmarshalBinary(entry.Value); err != nil {
		return nil, err
	}
	return p, nil
}

func PutPollination(id string, p *Pollination, storage logical.Storage) error { // TODO
	data, err  := p.MarshalBinary()
	if err != nil {
		return err
	}
	return storage.Put(context.Background(), &logical.StorageEntry{
		Key:   id,
		Value: data,
	})
}
