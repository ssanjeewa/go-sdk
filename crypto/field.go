package zkpcrypto

import (
	"fmt"
	"math/big"
)

// BN254ScalarField is the BN254 scalar field modulus.
// All field elements (n, s, scope, public signals) must be strictly less than this value.
//
// Note: we do NOT import go-ethereum here — use golang.org/x/crypto/sha3 for
// any Keccak256 needs to keep this package lightweight.
var BN254ScalarField, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617",
	10,
)

// IsValidFieldElement reports whether v is a valid BN254 scalar field element:
// v must be non-nil, non-negative, and strictly less than BN254ScalarField.
func IsValidFieldElement(v *big.Int) bool {
	return v != nil && v.Sign() >= 0 && v.Cmp(BN254ScalarField) < 0
}

// ParseFieldElement parses a decimal string into a BN254 field element.
// Returns *ValidationError if s is not a valid decimal integer or is out of range.
func ParseFieldElement(s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, &ValidationError{
			Message: fmt.Sprintf("field element must be a decimal integer, got %q", s),
		}
	}
	if !IsValidFieldElement(v) {
		return nil, &ValidationError{
			Message: fmt.Sprintf("field element out of BN254 range: %s", s),
		}
	}
	return v, nil
}
