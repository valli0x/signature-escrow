package server

import (
	"testing"

	"github.com/valli0x/signature-escrow/validation"
)

func fl(pub, sig, dep string) *flower {
	return &flower{ID: "swap1", Alg: validation.ECDSA, Pub: []byte(pub), Hash: []byte("h"), Sig: []byte(sig), Depositor: dep}
}

func TestAddFlowerHappyPath(t *testing.T) {
	p := newPollination()
	if err := p.addFlower(fl("pubA", "sigA", "alice")); err != nil {
		t.Fatal(err)
	}
	if err := p.addFlower(fl("pubB", "sigB", "bob")); err != nil {
		t.Fatal(err)
	}
	if p.flower1 == nil || p.flower2 == nil {
		t.Fatal("both slots should be filled")
	}
}

func TestAddFlowerForeignOverwriteRejected(t *testing.T) {
	p := newPollination()
	_ = p.addFlower(fl("pubA", "sigA", "alice"))
	if err := p.addFlower(fl("pubA", "evil", "mallory")); err == nil {
		t.Fatal("expected rejection: another depositor overwriting alice's slot")
	}
	if string(p.flower1.Sig) != "sigA" {
		t.Fatal("alice's flower was clobbered")
	}
}

func TestAddFlowerSigImmutable(t *testing.T) {
	p := newPollination()
	_ = p.addFlower(fl("pubA", "sigA", "alice"))
	if err := p.addFlower(fl("pubA", "different", "alice")); err == nil {
		t.Fatal("expected rejection: signature already deposited")
	}
	// idempotent identical re-post is fine
	if err := p.addFlower(fl("pubA", "sigA", "alice")); err != nil {
		t.Fatalf("idempotent re-post should pass: %v", err)
	}
}

func TestAddFlowerOneDepositorCannotHoldBothSlots(t *testing.T) {
	p := newPollination()
	_ = p.addFlower(fl("pubA", "sigA", "alice"))
	if err := p.addFlower(fl("pubB", "sigB", "alice")); err == nil {
		t.Fatal("expected rejection: same depositor occupying both slots")
	}
}

func TestAddFlowerThirdParticipantRejected(t *testing.T) {
	p := newPollination()
	_ = p.addFlower(fl("pubA", "sigA", "alice"))
	_ = p.addFlower(fl("pubB", "sigB", "bob"))
	if err := p.addFlower(fl("pubC", "sigC", "mallory")); err == nil {
		t.Fatal("expected rejection: escrow already has two participants")
	}
}
