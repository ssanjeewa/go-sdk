package zkpcrypto

import (
	"errors"
	"math/big"
	"testing"
)

func TestIsValidFieldElement_Zero(t *testing.T) {
	if !IsValidFieldElement(big.NewInt(0)) {
		t.Error("0 should be a valid field element")
	}
}

func TestIsValidFieldElement_MaxValid(t *testing.T) {
	maxValid := new(big.Int).Sub(BN254ScalarField, big.NewInt(1))
	if !IsValidFieldElement(maxValid) {
		t.Error("BN254ScalarField-1 should be valid")
	}
}

func TestIsValidFieldElement_FieldItself(t *testing.T) {
	if IsValidFieldElement(new(big.Int).Set(BN254ScalarField)) {
		t.Error("BN254ScalarField itself should NOT be valid (exclusive upper bound)")
	}
}

func TestIsValidFieldElement_Negative(t *testing.T) {
	if IsValidFieldElement(big.NewInt(-1)) {
		t.Error("negative value should NOT be valid")
	}
}

func TestIsValidFieldElement_Nil(t *testing.T) {
	if IsValidFieldElement(nil) {
		t.Error("nil should NOT be valid")
	}
}

func TestParseFieldElement_ValidDecimal(t *testing.T) {
	v, err := ParseFieldElement("12345678901234567890")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := new(big.Int).SetString("12345678901234567890", 10)
	if v.Cmp(want) != 0 {
		t.Errorf("got %s, want %s", v, want)
	}
}

func TestParseFieldElement_Zero(t *testing.T) {
	v, err := ParseFieldElement("0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Sign() != 0 {
		t.Errorf("expected 0, got %s", v)
	}
}

func TestParseFieldElement_OutOfRange(t *testing.T) {
	// BN254ScalarField itself is out of range.
	_, err := ParseFieldElement(BN254ScalarField.String())
	if err == nil {
		t.Fatal("expected error for out-of-range value")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestParseFieldElement_NonDecimal(t *testing.T) {
	_, err := ParseFieldElement("0x1234abcd")
	if err == nil {
		t.Fatal("expected error for non-decimal input")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestParseFieldElement_EmptyString(t *testing.T) {
	_, err := ParseFieldElement("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}
