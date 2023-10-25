package escrowbox

type SignaturesType uint32

const (
	ecdsaType SignaturesType = iota
	schnorrType
)

func (c SignaturesType) String() string {
	switch c {
	case 0:
		return "ECDSA"
	case 1:
		return "Schnorr"
	default:
		return "Unknown"
	}
}
