package btcfrost

import (
	"errors"
	"github.com/valli0x/signature-escrow/network"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func FrostKeygen(id party.ID, ids party.IDSlice, threshold int, n network.Network) (*frost.Config, error) {
	h, err := protocol.NewMultiHandler(frost.Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(id, h, n)

	r, err := h.Result()
	if err != nil {
		return nil, err
	}
	return r.(*frost.Config), nil
}

func FrostSign(c *frost.Config, id party.ID, m []byte, signers party.IDSlice, n network.Network) error {
	h, err := protocol.NewMultiHandler(frost.Sign(c, signers, m), nil)
	if err != nil {
		return err
	}

	network.HandlerLoop(id, h, n)

	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(frost.Signature)
	if !signature.Verify(c.PublicKey, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}

func FrostKeygenTaproot(id party.ID, ids party.IDSlice, threshold int, n network.Network) (*frost.TaprootConfig, error) {
	h, err := protocol.NewMultiHandler(frost.KeygenTaproot(id, ids, threshold), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(id, h, n)

	r, err := h.Result()
	if err != nil {
		return nil, err
	}
	return r.(*frost.TaprootConfig), nil
}

func FrostSignTaproot(c *frost.TaprootConfig, id party.ID, m []byte, signers party.IDSlice, n network.Network) error {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return err
	}

	network.HandlerLoop(id, h, n)

	r, err := h.Result()
	if err != nil {
		return err
	}

	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return errors.New("failed to verify frost signature")
	}
	return nil
}
