package mpcfrost

import (
	"errors"

	"github.com/valli0x/signature-escrow/network"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func FrostKeygen(id party.ID, ids party.IDSlice, threshold int, n network.Channel) (*frost.Config, error) {
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

func FrostSign(c *frost.Config, id party.ID, m []byte, signers party.IDSlice, n network.Channel) error {
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

func FrostKeygenTaproot(id party.ID, ids party.IDSlice, threshold int, n network.Channel) (*frost.TaprootConfig, error) {
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

func FrostSignTaproot(c *frost.TaprootConfig, m []byte, signers party.IDSlice, n network.Channel) (taproot.Signature, error) {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(c.ID, h, n)

	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return nil, errors.New("failed to verify frost signature")
	}
	return signature, nil
}

/*
	incompelete signature:
	send a message: round 2, from: a, to , protocol: frost/sign-threshold-taproot
	accept: a message: round 2, from: b, to , protocol: frost/sign-threshold-taproot
	send a message: round 3, from: a, to , protocol: frost/sign-threshold-taproot

	complete signature:
	accept: a message: round 3, from: b, to , protocol: frost/sign-threshold-taproot
*/

// incomplete signature
func FrostSignTaprootInc(c *frost.TaprootConfig, m []byte, signers party.IDSlice, n network.Channel) error {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return err
	}

	// send round2
	round2, ok := <-h.Listen()
	if !ok {
		return errors.New("failed to getting incomplete signature, send round2")
	}
	n.Send(round2)

	// accept round2
	round2, ok = <-n.Next()
	if !ok {
		return errors.New("failed to getting incomplete signature, accept round2")
	}
	h.Accept(round2)

	// send round3
	round3, ok := <-h.Listen()
	if !ok {
		return errors.New("failed to getting incomplete signature, send round3")
	}
	n.Send(round3)

	return nil
}

func FrostSignTaprootCoSign(c *frost.TaprootConfig, incSig *protocol.Message, m []byte, signers party.IDSlice, n network.Channel) (taproot.Signature, error) {
	h, err := protocol.NewMultiHandler(frost.SignTaproot(c, signers, m), nil)
	if err != nil {
		return nil, err
	}

	// send round2
	round2, ok := <-h.Listen()
	if !ok {
		return nil, errors.New("failed to getting incomplete signature, send round2")
	}
	n.Send(round2)

	// accept round2
	round2, ok = <-n.Next()
	if !ok {
		return nil, errors.New("failed to getting incomplete signature, accept round2")
	}
	h.Accept(round2)

	// skip own round3
	<-h.Listen()

	// accept round3
	round3, ok := <-n.Next()
	if !ok {
		return nil, errors.New("failed to getting incomplete signature, accept round3")
	}
	h.Accept(round3)

	// getting complete signature
	r, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := r.(taproot.Signature)
	if !c.PublicKey.Verify(signature, m) {
		return nil, errors.New("failed to verify frost signature")
	}
	return signature, nil
}
