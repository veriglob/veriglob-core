// Package circuits provides zk-SNARK circuits for predicate proofs.
package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// ShiftConstant is 2^64 as a big.Int for use in commitment calculations
var ShiftConstant = new(big.Int).Lsh(big.NewInt(1), 64)

// RangeProofCircuit proves that a private value satisfies a range predicate.
// It can prove: value > threshold, value >= threshold, value < threshold, value <= threshold
type RangeProofCircuit struct {
	// Value is the private input (the actual credential field value)
	Value frontend.Variable `gnark:",secret"`

	// Threshold is the public comparison value
	Threshold frontend.Variable `gnark:",public"`

	// Commitment links this proof to the credential (hash of value + salt)
	Commitment frontend.Variable `gnark:",public"`

	// Salt is used to compute the commitment
	Salt frontend.Variable `gnark:",secret"`

	// BitWidth is the number of bits for range checking
	BitWidth int
}

// Define implements the circuit constraints for proving value > threshold.
func (c *RangeProofCircuit) Define(api frontend.API) error {
	// 1. Verify the commitment: commitment == hash(value, salt)
	// Using a simple commitment: commitment = value + salt * 2^128
	// In production, use Poseidon or MiMC hash
	// Shift by 128 bits = shift by 64 twice
	saltShifted := api.Mul(c.Salt, ShiftConstant)
	saltShifted = api.Mul(saltShifted, ShiftConstant) // shift by 128 bits total
	computedCommitment := api.Add(c.Value, saltShifted)
	api.AssertIsEqual(computedCommitment, c.Commitment)

	// 2. Prove value > threshold
	// This is equivalent to proving (value - threshold - 1) >= 0
	// Which means (value - threshold - 1) can be represented in BitWidth bits

	// Compute diff = value - threshold - 1
	diff := api.Sub(c.Value, c.Threshold)
	diff = api.Sub(diff, 1)

	// Range check: decompose diff into bits and verify it's non-negative
	// This implicitly proves diff >= 0, which means value >= threshold + 1
	bits := api.ToBinary(diff, c.BitWidth)

	// Recompose to verify the decomposition is correct
	recomposed := frontend.Variable(0)
	coeff := frontend.Variable(1)
	for i := 0; i < len(bits); i++ {
		recomposed = api.Add(recomposed, api.Mul(bits[i], coeff))
		coeff = api.Mul(coeff, 2)
	}
	api.AssertIsEqual(recomposed, diff)

	return nil
}

// RangeProofGreaterOrEqualCircuit proves value >= threshold.
type RangeProofGreaterOrEqualCircuit struct {
	Value      frontend.Variable `gnark:",secret"`
	Threshold  frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`
	Salt       frontend.Variable `gnark:",secret"`
	BitWidth   int
}

// Define implements the circuit for value >= threshold.
func (c *RangeProofGreaterOrEqualCircuit) Define(api frontend.API) error {
	// Verify commitment
	saltShifted := api.Mul(c.Salt, ShiftConstant)
	saltShifted = api.Mul(saltShifted, ShiftConstant)
	computedCommitment := api.Add(c.Value, saltShifted)
	api.AssertIsEqual(computedCommitment, c.Commitment)

	// Prove value >= threshold: (value - threshold) >= 0
	diff := api.Sub(c.Value, c.Threshold)

	bits := api.ToBinary(diff, c.BitWidth)
	recomposed := frontend.Variable(0)
	coeff := frontend.Variable(1)
	for i := 0; i < len(bits); i++ {
		recomposed = api.Add(recomposed, api.Mul(bits[i], coeff))
		coeff = api.Mul(coeff, 2)
	}
	api.AssertIsEqual(recomposed, diff)

	return nil
}

// RangeProofLessThanCircuit proves value < threshold.
type RangeProofLessThanCircuit struct {
	Value      frontend.Variable `gnark:",secret"`
	Threshold  frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`
	Salt       frontend.Variable `gnark:",secret"`
	BitWidth   int
}

// Define implements the circuit for value < threshold.
func (c *RangeProofLessThanCircuit) Define(api frontend.API) error {
	// Verify commitment
	saltShifted := api.Mul(c.Salt, ShiftConstant)
	saltShifted = api.Mul(saltShifted, ShiftConstant)
	computedCommitment := api.Add(c.Value, saltShifted)
	api.AssertIsEqual(computedCommitment, c.Commitment)

	// Prove value < threshold: (threshold - value - 1) >= 0
	diff := api.Sub(c.Threshold, c.Value)
	diff = api.Sub(diff, 1)

	bits := api.ToBinary(diff, c.BitWidth)
	recomposed := frontend.Variable(0)
	coeff := frontend.Variable(1)
	for i := 0; i < len(bits); i++ {
		recomposed = api.Add(recomposed, api.Mul(bits[i], coeff))
		coeff = api.Mul(coeff, 2)
	}
	api.AssertIsEqual(recomposed, diff)

	return nil
}

// AgeVerificationCircuit proves age >= minAge based on birth year.
// This is a specialized circuit for the common use case of age verification.
type AgeVerificationCircuit struct {
	// Private inputs
	BirthYear frontend.Variable `gnark:",secret"`

	// Public inputs
	CurrentYear frontend.Variable `gnark:",public"`
	MinAge      frontend.Variable `gnark:",public"`
	Commitment  frontend.Variable `gnark:",public"` // hash(birthYear, salt)

	// Salt for commitment
	Salt frontend.Variable `gnark:",secret"`

	BitWidth int
}

// Define implements the age verification circuit.
func (c *AgeVerificationCircuit) Define(api frontend.API) error {
	// 1. Verify commitment to birth year
	saltShifted := api.Mul(c.Salt, ShiftConstant)
	saltShifted = api.Mul(saltShifted, ShiftConstant)
	computedCommitment := api.Add(c.BirthYear, saltShifted)
	api.AssertIsEqual(computedCommitment, c.Commitment)

	// 2. Compute age = currentYear - birthYear
	age := api.Sub(c.CurrentYear, c.BirthYear)

	// 3. Prove age >= minAge: (age - minAge) >= 0
	diff := api.Sub(age, c.MinAge)

	bits := api.ToBinary(diff, c.BitWidth)
	recomposed := frontend.Variable(0)
	coeff := frontend.Variable(1)
	for i := 0; i < len(bits); i++ {
		recomposed = api.Add(recomposed, api.Mul(bits[i], coeff))
		coeff = api.Mul(coeff, 2)
	}
	api.AssertIsEqual(recomposed, diff)

	return nil
}

// EqualityProofCircuit proves value == expected without revealing value.
type EqualityProofCircuit struct {
	Value      frontend.Variable `gnark:",secret"`
	Expected   frontend.Variable `gnark:",public"`
	Commitment frontend.Variable `gnark:",public"`
	Salt       frontend.Variable `gnark:",secret"`
}

// Define implements the equality proof circuit.
func (c *EqualityProofCircuit) Define(api frontend.API) error {
	// Verify commitment
	saltShifted := api.Mul(c.Salt, ShiftConstant)
	saltShifted = api.Mul(saltShifted, ShiftConstant)
	computedCommitment := api.Add(c.Value, saltShifted)
	api.AssertIsEqual(computedCommitment, c.Commitment)

	// Prove equality
	api.AssertIsEqual(c.Value, c.Expected)

	return nil
}

// SetMembershipCircuit proves value is one of the allowed values.
type SetMembershipCircuit struct {
	Value      frontend.Variable   `gnark:",secret"`
	SetHash    frontend.Variable   `gnark:",public"` // Hash of the allowed set
	Commitment frontend.Variable   `gnark:",public"`
	Salt       frontend.Variable   `gnark:",secret"`
	SetValues  []frontend.Variable `gnark:",secret"` // The actual set values
	Index      frontend.Variable   `gnark:",secret"` // Which set element matches
}

// Define implements the set membership proof circuit.
func (c *SetMembershipCircuit) Define(api frontend.API) error {
	// Verify commitment
	saltShifted := api.Mul(c.Salt, ShiftConstant)
	saltShifted = api.Mul(saltShifted, ShiftConstant)
	computedCommitment := api.Add(c.Value, saltShifted)
	api.AssertIsEqual(computedCommitment, c.Commitment)

	// Prove value equals one of the set values
	// Using a simple approach: compute product of (value - setValues[i]) for all i
	// If value is in the set, exactly one factor is zero, making the product zero
	product := frontend.Variable(1)
	for i := 0; i < len(c.SetValues); i++ {
		diff := api.Sub(c.Value, c.SetValues[i])
		product = api.Mul(product, diff)
	}
	api.AssertIsEqual(product, 0)

	return nil
}
