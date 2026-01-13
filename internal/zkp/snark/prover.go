// Package snark provides zk-SNARK proof generation and verification.
package snark

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/veriglob/veriglob-core/internal/zkp/snark/circuits"
)

// CircuitType identifies the type of predefined circuit.
type CircuitType string

const (
	CircuitRangeGreaterThan    CircuitType = "range_gt"
	CircuitRangeGreaterOrEqual CircuitType = "range_gte"
	CircuitRangeLessThan       CircuitType = "range_lt"
	CircuitAgeVerification     CircuitType = "age_verify"
	CircuitEquality            CircuitType = "equality"
	CircuitSetMembership       CircuitType = "set_membership"
)

// DefaultBitWidth is the default bit width for range proofs.
const DefaultBitWidth = 64

// ProvingKey wraps a Groth16 proving key with metadata.
type ProvingKey struct {
	Type     CircuitType
	Key      groth16.ProvingKey
	CS       constraint.ConstraintSystem
	BitWidth int
}

// VerifyingKey wraps a Groth16 verifying key with metadata.
type VerifyingKey struct {
	Type     CircuitType
	Key      groth16.VerifyingKey
	BitWidth int
}

// SetupRangeProof performs the trusted setup for range proof circuits.
func SetupRangeProof(circuitType CircuitType, bitWidth int) (*ProvingKey, *VerifyingKey, error) {
	var circuit frontend.Circuit

	switch circuitType {
	case CircuitRangeGreaterThan:
		circuit = &circuits.RangeProofCircuit{BitWidth: bitWidth}
	case CircuitRangeGreaterOrEqual:
		circuit = &circuits.RangeProofGreaterOrEqualCircuit{BitWidth: bitWidth}
	case CircuitRangeLessThan:
		circuit = &circuits.RangeProofLessThanCircuit{BitWidth: bitWidth}
	case CircuitAgeVerification:
		circuit = &circuits.AgeVerificationCircuit{BitWidth: bitWidth}
	case CircuitEquality:
		circuit = &circuits.EqualityProofCircuit{}
	default:
		return nil, nil, errors.New("snark: unsupported circuit type")
	}

	// Compile the circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, err
	}

	// Run the trusted setup
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, nil, err
	}

	return &ProvingKey{
			Type:     circuitType,
			Key:      pk,
			CS:       cs,
			BitWidth: bitWidth,
		}, &VerifyingKey{
			Type:     circuitType,
			Key:      vk,
			BitWidth: bitWidth,
		}, nil
}

// RangeProofInput contains inputs for range proof generation.
type RangeProofInput struct {
	Value      *big.Int // The actual value (private)
	Threshold  *big.Int // The comparison threshold (public)
	Salt       *big.Int // Salt for commitment (private)
	Commitment *big.Int // Commitment to value (public)
}

// GenerateRangeProof creates a proof that value > threshold (or other predicate).
func GenerateRangeProof(pk *ProvingKey, input *RangeProofInput) (groth16.Proof, error) {
	var assignment frontend.Circuit

	switch pk.Type {
	case CircuitRangeGreaterThan:
		assignment = &circuits.RangeProofCircuit{
			Value:      input.Value,
			Threshold:  input.Threshold,
			Salt:       input.Salt,
			Commitment: input.Commitment,
			BitWidth:   pk.BitWidth,
		}
	case CircuitRangeGreaterOrEqual:
		assignment = &circuits.RangeProofGreaterOrEqualCircuit{
			Value:      input.Value,
			Threshold:  input.Threshold,
			Salt:       input.Salt,
			Commitment: input.Commitment,
			BitWidth:   pk.BitWidth,
		}
	case CircuitRangeLessThan:
		assignment = &circuits.RangeProofLessThanCircuit{
			Value:      input.Value,
			Threshold:  input.Threshold,
			Salt:       input.Salt,
			Commitment: input.Commitment,
			BitWidth:   pk.BitWidth,
		}
	default:
		return nil, errors.New("snark: circuit type mismatch")
	}

	// Create witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	// Generate proof
	proof, err := groth16.Prove(pk.CS, pk.Key, witness)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyRangeProof verifies a range proof.
func VerifyRangeProof(vk *VerifyingKey, proof groth16.Proof, threshold, commitment *big.Int) error {
	var publicWitnessCircuit frontend.Circuit

	switch vk.Type {
	case CircuitRangeGreaterThan:
		publicWitnessCircuit = &circuits.RangeProofCircuit{
			Threshold:  threshold,
			Commitment: commitment,
			BitWidth:   vk.BitWidth,
		}
	case CircuitRangeGreaterOrEqual:
		publicWitnessCircuit = &circuits.RangeProofGreaterOrEqualCircuit{
			Threshold:  threshold,
			Commitment: commitment,
			BitWidth:   vk.BitWidth,
		}
	case CircuitRangeLessThan:
		publicWitnessCircuit = &circuits.RangeProofLessThanCircuit{
			Threshold:  threshold,
			Commitment: commitment,
			BitWidth:   vk.BitWidth,
		}
	default:
		return errors.New("snark: circuit type mismatch")
	}

	// Create public witness
	publicWitness, err := frontend.NewWitness(publicWitnessCircuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	// Verify proof
	err = groth16.Verify(proof, vk.Key, publicWitness)
	if err != nil {
		return err
	}

	return nil
}

// AgeProofInput contains inputs for age verification proof.
type AgeProofInput struct {
	BirthYear   *big.Int // Private
	CurrentYear *big.Int // Public
	MinAge      *big.Int // Public
	Salt        *big.Int // Private
	Commitment  *big.Int // Public
}

// GenerateAgeProof creates a proof that age >= minAge.
func GenerateAgeProof(pk *ProvingKey, input *AgeProofInput) (groth16.Proof, error) {
	if pk.Type != CircuitAgeVerification {
		return nil, errors.New("snark: wrong proving key type for age proof")
	}

	assignment := &circuits.AgeVerificationCircuit{
		BirthYear:   input.BirthYear,
		CurrentYear: input.CurrentYear,
		MinAge:      input.MinAge,
		Salt:        input.Salt,
		Commitment:  input.Commitment,
		BitWidth:    pk.BitWidth,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}

	proof, err := groth16.Prove(pk.CS, pk.Key, witness)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyAgeProof verifies an age proof.
func VerifyAgeProof(vk *VerifyingKey, proof groth16.Proof, currentYear, minAge, commitment *big.Int) error {
	if vk.Type != CircuitAgeVerification {
		return errors.New("snark: wrong verifying key type for age proof")
	}

	publicWitnessCircuit := &circuits.AgeVerificationCircuit{
		CurrentYear: currentYear,
		MinAge:      minAge,
		Commitment:  commitment,
		BitWidth:    vk.BitWidth,
	}

	publicWitness, err := frontend.NewWitness(publicWitnessCircuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}

	return groth16.Verify(proof, vk.Key, publicWitness)
}

// ComputeCommitment computes a commitment to a value using the scheme used in circuits.
// commitment = value + salt * 2^128
func ComputeCommitment(value, salt *big.Int) *big.Int {
	// salt * 2^128
	shift := new(big.Int).Lsh(big.NewInt(1), 128)
	saltShifted := new(big.Int).Mul(salt, shift)

	// value + salt * 2^128
	commitment := new(big.Int).Add(value, saltShifted)
	return commitment
}

// GenerateSalt generates a random salt for commitments.
func GenerateSalt() (*big.Int, error) {
	// Generate 128 bits of randomness
	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(randBytes), nil
}

// SerializeProof converts a Groth16 proof to bytes.
func SerializeProof(proof groth16.Proof) ([]byte, error) {
	var buf bytes.Buffer
	_, err := proof.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeserializeProof reconstructs a Groth16 proof from bytes.
func DeserializeProof(data []byte) (groth16.Proof, error) {
	proof := groth16.NewProof(ecc.BN254)
	_, err := proof.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return proof, nil
}
