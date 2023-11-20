package mpccmp

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"

	"github.com/valli0x/signature-escrow/network"
)

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n network.Network, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(id, h, n)

	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign(c *cmp.Config, m []byte, ids party.IDSlice, n network.Network, pl *pool.Pool) (*ecdsa.Signature, error) {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, ids, m, pl), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := signResult.(*ecdsa.Signature)

	if !signature.Verify(c.PublicPoint(), m) {
		return nil, errors.New("failed to verify cmp signature")
	}

	return signature, nil
}

func CMPRefresh(c *cmp.Config, n network.Network, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(c.ID, hRefresh, n)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPPreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n network.Network, pl *pool.Pool) (*ecdsa.Signature, error) {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return nil, errors.New("failed to verify cmp signature")
	}
	return signature, nil
}

func CMPPreSign(c *cmp.Config, signers party.IDSlice, n network.Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
	if err != nil {
		return nil, err
	}

	network.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

// incomplete signature
func CMPPreSignOnlineInc(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, pl *pool.Pool) (*protocol.Message, error) {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
	if err != nil {
		return nil, err
	}
	round8, ok := <-h.Listen()
	if !ok {
		return nil, errors.New("failed to getting incomplete signature")
	}
	return round8, nil
}

func CMPPreSignOnlineCoSign(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, incSig *protocol.Message, pl *pool.Pool) (*ecdsa.Signature, error) {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
	if err != nil {
		return nil, err
	}
	<-h.Listen() // skip first message
	h.Accept(incSig)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return nil, errors.New("failed to verify cmp signature")
	}
	return signature, nil
}

// get a signature in ethereum format
func SigEthereum(sig *ecdsa.Signature) ([]byte, error) {
	IsOverHalfOrder := sig.S.IsOverHalfOrder() // s-values greater than secp256k1n/2 are considered invalid

	if IsOverHalfOrder {
		sig.S.Negate()
	}

	r, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs := make([]byte, 0, 65)
	rs = append(rs, r...)
	rs = append(rs, s...)

	if IsOverHalfOrder {
		v := rs[0] - 2 // Convert to Ethereum signature format with 'recovery id' v at the end.
		copy(rs, rs[1:])
		rs[64] = v ^ 1
	} else {
		v := rs[0] - 2
		copy(rs, rs[1:])
		rs[64] = v
	}

	r[0] = rs[64] + 2
	if err := sig.R.UnmarshalBinary(r); err != nil {
		return nil, err
	}

	return rs, nil
}
