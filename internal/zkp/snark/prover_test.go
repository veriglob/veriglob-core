package snark

import (
	"math/big"
	"testing"
)

func TestSetupRangeProof(t *testing.T) {
	tests := []struct {
		name        string
		circuitType CircuitType
		bitWidth    int
		wantErr     bool
	}{
		{
			name:        "range greater than circuit",
			circuitType: CircuitRangeGreaterThan,
			bitWidth:    32,
			wantErr:     false,
		},
		{
			name:        "range greater or equal circuit",
			circuitType: CircuitRangeGreaterOrEqual,
			bitWidth:    32,
			wantErr:     false,
		},
		{
			name:        "range less than circuit",
			circuitType: CircuitRangeLessThan,
			bitWidth:    32,
			wantErr:     false,
		},
		{
			name:        "age verification circuit",
			circuitType: CircuitAgeVerification,
			bitWidth:    16,
			wantErr:     false,
		},
		{
			name:        "equality circuit",
			circuitType: CircuitEquality,
			bitWidth:    32,
			wantErr:     false,
		},
		{
			name:        "unsupported circuit type",
			circuitType: "invalid",
			bitWidth:    32,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, vk, err := SetupRangeProof(tt.circuitType, tt.bitWidth)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetupRangeProof() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pk == nil {
					t.Error("Proving key is nil")
				}
				if vk == nil {
					t.Error("Verifying key is nil")
				}
				if pk.Type != tt.circuitType {
					t.Errorf("ProvingKey.Type = %v, want %v", pk.Type, tt.circuitType)
				}
				if vk.Type != tt.circuitType {
					t.Errorf("VerifyingKey.Type = %v, want %v", vk.Type, tt.circuitType)
				}
			}
		})
	}
}

func TestGenerateAndVerifyRangeProofGreaterThan(t *testing.T) {
	// Setup
	pk, vk, err := SetupRangeProof(CircuitRangeGreaterThan, 32)
	if err != nil {
		t.Fatalf("SetupRangeProof() error = %v", err)
	}

	// Test case: prove that 100 > 50
	value := big.NewInt(100)
	threshold := big.NewInt(50)
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	commitment := ComputeCommitment(value, salt)

	input := &RangeProofInput{
		Value:      value,
		Threshold:  threshold,
		Salt:       salt,
		Commitment: commitment,
	}

	// Generate proof
	proof, err := GenerateRangeProof(pk, input)
	if err != nil {
		t.Fatalf("GenerateRangeProof() error = %v", err)
	}

	// Verify proof
	err = VerifyRangeProof(vk, proof, threshold, commitment)
	if err != nil {
		t.Errorf("VerifyRangeProof() error = %v", err)
	}
}

func TestGenerateAndVerifyRangeProofGreaterOrEqual(t *testing.T) {
	pk, vk, err := SetupRangeProof(CircuitRangeGreaterOrEqual, 32)
	if err != nil {
		t.Fatalf("SetupRangeProof() error = %v", err)
	}

	// Test case: prove that 50 >= 50 (equality case)
	value := big.NewInt(50)
	threshold := big.NewInt(50)
	salt, _ := GenerateSalt()
	commitment := ComputeCommitment(value, salt)

	input := &RangeProofInput{
		Value:      value,
		Threshold:  threshold,
		Salt:       salt,
		Commitment: commitment,
	}

	proof, err := GenerateRangeProof(pk, input)
	if err != nil {
		t.Fatalf("GenerateRangeProof() error = %v", err)
	}

	err = VerifyRangeProof(vk, proof, threshold, commitment)
	if err != nil {
		t.Errorf("VerifyRangeProof() error = %v", err)
	}
}

func TestGenerateAndVerifyRangeProofLessThan(t *testing.T) {
	pk, vk, err := SetupRangeProof(CircuitRangeLessThan, 32)
	if err != nil {
		t.Fatalf("SetupRangeProof() error = %v", err)
	}

	// Test case: prove that 25 < 100
	value := big.NewInt(25)
	threshold := big.NewInt(100)
	salt, _ := GenerateSalt()
	commitment := ComputeCommitment(value, salt)

	input := &RangeProofInput{
		Value:      value,
		Threshold:  threshold,
		Salt:       salt,
		Commitment: commitment,
	}

	proof, err := GenerateRangeProof(pk, input)
	if err != nil {
		t.Fatalf("GenerateRangeProof() error = %v", err)
	}

	err = VerifyRangeProof(vk, proof, threshold, commitment)
	if err != nil {
		t.Errorf("VerifyRangeProof() error = %v", err)
	}
}

func TestAgeProof(t *testing.T) {
	pk, vk, err := SetupRangeProof(CircuitAgeVerification, 16)
	if err != nil {
		t.Fatalf("SetupRangeProof() error = %v", err)
	}

	// Test case: prove age >= 21 for someone born in 1990 (current year 2024)
	birthYear := big.NewInt(1990)
	currentYear := big.NewInt(2024)
	minAge := big.NewInt(21)
	salt, _ := GenerateSalt()
	commitment := ComputeCommitment(birthYear, salt)

	input := &AgeProofInput{
		BirthYear:   birthYear,
		CurrentYear: currentYear,
		MinAge:      minAge,
		Salt:        salt,
		Commitment:  commitment,
	}

	proof, err := GenerateAgeProof(pk, input)
	if err != nil {
		t.Fatalf("GenerateAgeProof() error = %v", err)
	}

	err = VerifyAgeProof(vk, proof, currentYear, minAge, commitment)
	if err != nil {
		t.Errorf("VerifyAgeProof() error = %v", err)
	}
}

func TestAgeProofWrongKeyType(t *testing.T) {
	// Setup with wrong circuit type
	pk, _, err := SetupRangeProof(CircuitRangeGreaterThan, 32)
	if err != nil {
		t.Fatalf("SetupRangeProof() error = %v", err)
	}

	input := &AgeProofInput{
		BirthYear:   big.NewInt(1990),
		CurrentYear: big.NewInt(2024),
		MinAge:      big.NewInt(21),
		Salt:        big.NewInt(123),
		Commitment:  big.NewInt(456),
	}

	_, err = GenerateAgeProof(pk, input)
	if err == nil {
		t.Error("GenerateAgeProof() should fail with wrong key type")
	}
}

func TestComputeCommitment(t *testing.T) {
	value := big.NewInt(100)
	salt := big.NewInt(12345)

	commitment := ComputeCommitment(value, salt)
	if commitment == nil {
		t.Fatal("ComputeCommitment() returned nil")
	}

	// Commitment should be deterministic
	commitment2 := ComputeCommitment(value, salt)
	if commitment.Cmp(commitment2) != 0 {
		t.Error("ComputeCommitment() is not deterministic")
	}

	// Different values should produce different commitments
	commitment3 := ComputeCommitment(big.NewInt(101), salt)
	if commitment.Cmp(commitment3) == 0 {
		t.Error("Different values produced same commitment")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	if salt1 == nil {
		t.Fatal("GenerateSalt() returned nil")
	}

	// Salts should be unique
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	if salt1.Cmp(salt2) == 0 {
		t.Error("GenerateSalt() returned same salt twice")
	}
}

func TestProofSerialization(t *testing.T) {
	pk, vk, err := SetupRangeProof(CircuitRangeGreaterThan, 32)
	if err != nil {
		t.Fatalf("SetupRangeProof() error = %v", err)
	}

	value := big.NewInt(100)
	threshold := big.NewInt(50)
	salt, _ := GenerateSalt()
	commitment := ComputeCommitment(value, salt)

	input := &RangeProofInput{
		Value:      value,
		Threshold:  threshold,
		Salt:       salt,
		Commitment: commitment,
	}

	proof, err := GenerateRangeProof(pk, input)
	if err != nil {
		t.Fatalf("GenerateRangeProof() error = %v", err)
	}

	// Serialize
	proofBytes, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("SerializeProof() error = %v", err)
	}
	if len(proofBytes) == 0 {
		t.Fatal("SerializeProof() returned empty slice")
	}

	// Deserialize
	reconstructedProof, err := DeserializeProof(proofBytes)
	if err != nil {
		t.Fatalf("DeserializeProof() error = %v", err)
	}

	// Verify deserialized proof
	err = VerifyRangeProof(vk, reconstructedProof, threshold, commitment)
	if err != nil {
		t.Errorf("VerifyRangeProof() with deserialized proof error = %v", err)
	}
}
