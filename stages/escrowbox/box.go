package escrowbox

import (
	"context"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/valli0x/signature-escrow/validation"
)

type pollination struct {
	flower1, flower2 *flower
	m                sync.Mutex
}

type flower struct {
	ID             string
	Alg            validation.SignaturesType
	Pub, Hash, Sig []byte
}

func NewPollination() *pollination {
	return &pollination{}
}

func (p *pollination) Pollinate() (bool, error) {
	p.m.Lock()
	defer p.m.Unlock()

	if p.flower1 == nil || p.flower2 == nil {
		return false, nil
	}

	f1 := p.flower1
	f2 := p.flower2

	f1Pollinated, err := validation.Validate(f1.Alg, f1.Pub, f1.Hash, f2.Sig)
	if err != nil {
		return false, err
	}

	f2Pollinated, err := validation.Validate(f2.Alg, f2.Pub, f2.Hash, f1.Sig)
	if err != nil {
		return false, err
	}

	return f1Pollinated && f2Pollinated, nil
}

func (p *pollination) AddFlower(flower *flower) {
	switch {
	case p.flower1 == nil || string(p.flower1.Pub) == string(flower.Pub):
		p.flower1 = flower
		return
	case p.flower2 == nil || string(p.flower2.Pub) == string(flower.Pub):
		p.flower2 = flower
		return
	}
}

// ! nil is possible
func (p *pollination) GetFlower(pub []byte) *flower {
	if p.flower1 != nil && string(p.flower1.Pub) == string(pub) {
		return p.flower1
	}
	if p.flower2 != nil && string(p.flower2.Pub) == string(pub) {
		return p.flower2
	}
	return nil
}

type pollinationMarshal struct {
	Flower1, Flower2 *flower
}

func (p *pollination) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(&pollinationMarshal{
		Flower1: p.flower1,
		Flower2: p.flower2,
	})
}

func (p *pollination) UnmarshalBinary(data []byte) error {
	pm := &pollinationMarshal{}
	if err := cbor.Unmarshal(data, pm); err != nil {
		return err
	}
	p.flower1 = pm.Flower1
	p.flower2 = pm.Flower2
	return nil
}

func GetPollination(id string, storage logical.Storage) (*pollination, error) {
	entry, err := storage.Get(context.Background(), id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	p := &pollination{}
	if err := p.UnmarshalBinary(entry.Value); err != nil {
		return nil, err
	}
	return p, nil
}

func PutPollination(id string, p *pollination, storage logical.Storage) error {
	data, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	return storage.Put(context.Background(), &logical.StorageEntry{
		Key:   id,
		Value: data,
	})
}
