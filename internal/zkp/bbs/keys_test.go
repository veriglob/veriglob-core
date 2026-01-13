package bbs

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name         string
		messageCount int
		wantErr      bool
	}{
		{
			name:         "valid key pair with 5 messages",
			messageCount: 5,
			wantErr:      false,
		},
		{
			name:         "valid key pair with 15 messages",
			messageCount: 15,
			wantErr:      false,
		},
		{
			name:         "valid key pair with 1 message",
			messageCount: 1,
			wantErr:      false,
		},
		{
			name:         "invalid zero messages",
			messageCount: 0,
			wantErr:      true,
		},
		{
			name:         "invalid negative messages",
			messageCount: -1,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := GenerateKeyPair(tt.messageCount)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if kp == nil {
					t.Error("GenerateKeyPair() returned nil key pair")
					return
				}
				if kp.SecretKey == nil {
					t.Error("SecretKey is nil")
				}
				if kp.PublicKey == nil {
					t.Error("PublicKey is nil")
				}
				// We need messageCount + 1 generators (h0 for blinding + h1..hn for messages)
				if len(kp.Generators) != tt.messageCount+1 {
					t.Errorf("Expected %d generators, got %d", tt.messageCount+1, len(kp.Generators))
				}
				if kp.MessageCount != tt.messageCount {
					t.Errorf("MessageCount = %d, want %d", kp.MessageCount, tt.messageCount)
				}
			}
		})
	}
}

func TestKeyPairSerialization(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test secret key serialization
	skBytes := kp.SecretKeyBytes()
	if len(skBytes) == 0 {
		t.Error("SecretKeyBytes() returned empty slice")
	}

	// Reconstruct secret key
	reconstructedSK := SecretKeyFromBytes(skBytes)
	if reconstructedSK.Cmp(kp.SecretKey) != 0 {
		t.Error("Secret key round-trip failed")
	}

	// Test public key serialization
	pkBytes := kp.PublicKeyBytes()
	if len(pkBytes) == 0 {
		t.Error("PublicKeyBytes() returned empty slice")
	}

	// Reconstruct public key
	reconstructedPK, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes() error = %v", err)
	}
	if !reconstructedPK.Equal(kp.PublicKey) {
		t.Error("Public key round-trip failed")
	}

	// Test generators serialization
	genBytes := kp.GeneratorsBytes()
	expectedLen := (kp.MessageCount + 1) * 48 // Each G1 point is 48 bytes compressed
	if len(genBytes) != expectedLen {
		t.Errorf("GeneratorsBytes() length = %d, want %d", len(genBytes), expectedLen)
	}

	// Reconstruct generators
	reconstructedGens, err := GeneratorsFromBytes(genBytes, kp.MessageCount+1)
	if err != nil {
		t.Fatalf("GeneratorsFromBytes() error = %v", err)
	}
	if len(reconstructedGens) != len(kp.Generators) {
		t.Errorf("Generators count mismatch: got %d, want %d", len(reconstructedGens), len(kp.Generators))
	}
	for i := range kp.Generators {
		if !reconstructedGens[i].Equal(&kp.Generators[i]) {
			t.Errorf("Generator %d round-trip failed", i)
		}
	}
}

func TestGeneratorsFromBytesErrors(t *testing.T) {
	// Test with invalid data length
	_, err := GeneratorsFromBytes([]byte{1, 2, 3}, 5)
	if err == nil {
		t.Error("GeneratorsFromBytes() should error with invalid data length")
	}
}

func TestHashToScalar(t *testing.T) {
	data1 := []byte("test message 1")
	data2 := []byte("test message 2")

	scalar1 := HashToScalar(data1)
	scalar2 := HashToScalar(data2)

	// Same input should produce same output
	scalar1Again := HashToScalar(data1)
	if !scalar1.Equal(scalar1Again) {
		t.Error("HashToScalar is not deterministic")
	}

	// Different inputs should produce different outputs
	if scalar1.Equal(scalar2) {
		t.Error("HashToScalar produced same output for different inputs")
	}
}
