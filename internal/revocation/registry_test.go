package revocation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCredentialID(t *testing.T) {
	id1, err := GenerateCredentialID()
	if err != nil {
		t.Fatalf("Failed to generate credential ID: %v", err)
	}

	if id1 == "" {
		t.Error("Generated ID is empty")
	}

	if len(id1) < 20 {
		t.Errorf("Generated ID is too short: %s", id1)
	}

	// Check URN format
	if id1[:9] != "urn:uuid:" {
		t.Errorf("ID should start with 'urn:uuid:', got: %s", id1)
	}

	// Ensure uniqueness
	id2, _ := GenerateCredentialID()
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.entries == nil {
		t.Error("Registry entries map should be initialized")
	}
}

func TestRegistryRegisterAndCheck(t *testing.T) {
	r := NewRegistry()

	credID := "urn:uuid:test-123"
	issuerDID := "did:key:issuer"
	subjectDID := "did:key:subject"

	// Register credential
	err := r.Register(credID, issuerDID, subjectDID)
	if err != nil {
		t.Fatalf("Failed to register credential: %v", err)
	}

	// Check status
	entry, err := r.CheckStatus(credID)
	if err != nil {
		t.Fatalf("Failed to check status: %v", err)
	}

	if entry.CredentialID != credID {
		t.Errorf("Expected credential ID %s, got %s", credID, entry.CredentialID)
	}

	if entry.Status != StatusActive {
		t.Errorf("Expected status %s, got %s", StatusActive, entry.Status)
	}

	if entry.IssuerDID != issuerDID {
		t.Errorf("Expected issuer DID %s, got %s", issuerDID, entry.IssuerDID)
	}

	if entry.SubjectDID != subjectDID {
		t.Errorf("Expected subject DID %s, got %s", subjectDID, entry.SubjectDID)
	}
}

func TestRegistryRevoke(t *testing.T) {
	r := NewRegistry()

	credID := "urn:uuid:test-456"
	r.Register(credID, "did:key:issuer", "did:key:subject")

	// Revoke
	reason := "Test revocation"
	err := r.Revoke(credID, reason)
	if err != nil {
		t.Fatalf("Failed to revoke: %v", err)
	}

	// Check status
	entry, _ := r.CheckStatus(credID)
	if entry.Status != StatusRevoked {
		t.Errorf("Expected status %s, got %s", StatusRevoked, entry.Status)
	}

	if entry.Reason != reason {
		t.Errorf("Expected reason %s, got %s", reason, entry.Reason)
	}

	if entry.RevokedAt.IsZero() {
		t.Error("RevokedAt should be set")
	}
}

func TestRegistryRevokeNotFound(t *testing.T) {
	r := NewRegistry()

	err := r.Revoke("urn:uuid:nonexistent", "reason")
	if err != ErrCredentialNotFound {
		t.Errorf("Expected ErrCredentialNotFound, got %v", err)
	}
}

func TestRegistryRevokeAlreadyRevoked(t *testing.T) {
	r := NewRegistry()

	credID := "urn:uuid:test-789"
	r.Register(credID, "did:key:issuer", "did:key:subject")
	r.Revoke(credID, "first revocation")

	err := r.Revoke(credID, "second revocation")
	if err != ErrAlreadyRevoked {
		t.Errorf("Expected ErrAlreadyRevoked, got %v", err)
	}
}

func TestRegistryIsRevoked(t *testing.T) {
	r := NewRegistry()

	credID := "urn:uuid:test-revoked"
	r.Register(credID, "did:key:issuer", "did:key:subject")

	revoked, err := r.IsRevoked(credID)
	if err != nil {
		t.Fatalf("Failed to check IsRevoked: %v", err)
	}
	if revoked {
		t.Error("Credential should not be revoked initially")
	}

	r.Revoke(credID, "revoked")

	revoked, err = r.IsRevoked(credID)
	if err != nil {
		t.Fatalf("Failed to check IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("Credential should be revoked after revocation")
	}
}

func TestRegistryListByIssuer(t *testing.T) {
	r := NewRegistry()

	issuer1 := "did:key:issuer1"
	issuer2 := "did:key:issuer2"

	r.Register("urn:uuid:1", issuer1, "did:key:subject1")
	r.Register("urn:uuid:2", issuer1, "did:key:subject2")
	r.Register("urn:uuid:3", issuer2, "did:key:subject3")

	entries := r.ListByIssuer(issuer1)
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries for issuer1, got %d", len(entries))
	}

	entries = r.ListByIssuer(issuer2)
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry for issuer2, got %d", len(entries))
	}
}

func TestRegistryListBySubject(t *testing.T) {
	r := NewRegistry()

	subject1 := "did:key:subject1"

	r.Register("urn:uuid:1", "did:key:issuer1", subject1)
	r.Register("urn:uuid:2", "did:key:issuer2", subject1)
	r.Register("urn:uuid:3", "did:key:issuer3", "did:key:subject2")

	entries := r.ListBySubject(subject1)
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries for subject1, got %d", len(entries))
	}
}

func TestRegistryWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "registry.json")

	// Create and save
	r1, err := NewRegistryWithFile(path)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	credID := "urn:uuid:persist-test"
	r1.Register(credID, "did:key:issuer", "did:key:subject")

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Registry file should exist after registration")
	}

	// Load from file
	r2, err := NewRegistryWithFile(path)
	if err != nil {
		t.Fatalf("Failed to load registry: %v", err)
	}

	entry, err := r2.CheckStatus(credID)
	if err != nil {
		t.Fatalf("Failed to find credential in loaded registry: %v", err)
	}

	if entry.Status != StatusActive {
		t.Errorf("Expected status %s, got %s", StatusActive, entry.Status)
	}
}

func TestRegistryExport(t *testing.T) {
	r := NewRegistry()
	r.Register("urn:uuid:export-test", "did:key:issuer", "did:key:subject")

	data, err := r.Export()
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	if len(data) == 0 {
		t.Error("Export should return non-empty data")
	}
}
