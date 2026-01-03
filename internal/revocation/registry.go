package revocation

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

var (
	ErrCredentialNotFound = errors.New("credential not found in registry")
	ErrAlreadyRevoked     = errors.New("credential already revoked")
)

// Status represents the revocation status of a credential
type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// Entry represents a single credential entry in the registry
type Entry struct {
	CredentialID string    `json:"credentialId"`
	IssuerDID    string    `json:"issuerDid"`
	SubjectDID   string    `json:"subjectDid"`
	Status       Status    `json:"status"`
	IssuedAt     time.Time `json:"issuedAt"`
	RevokedAt    time.Time `json:"revokedAt,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}

// Registry manages credential revocation status
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*Entry
	path    string
}

// NewRegistry creates a new in-memory revocation registry
func NewRegistry() *Registry {
	return &Registry{
		entries: make(map[string]*Entry),
	}
}

// NewRegistryWithFile creates a registry that persists to a file
func NewRegistryWithFile(path string) (*Registry, error) {
	r := &Registry{
		entries: make(map[string]*Entry),
		path:    path,
	}

	// Load existing entries if file exists
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &r.entries); err != nil {
				return nil, err
			}
		}
	}

	return r, nil
}

// GenerateCredentialID creates a unique credential ID
func GenerateCredentialID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "urn:uuid:" + hex.EncodeToString(bytes[:4]) + "-" +
		hex.EncodeToString(bytes[4:6]) + "-" +
		hex.EncodeToString(bytes[6:8]) + "-" +
		hex.EncodeToString(bytes[8:10]) + "-" +
		hex.EncodeToString(bytes[10:]), nil
}

// Register adds a new credential to the registry
func (r *Registry) Register(credentialID, issuerDID, subjectDID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries[credentialID] = &Entry{
		CredentialID: credentialID,
		IssuerDID:    issuerDID,
		SubjectDID:   subjectDID,
		Status:       StatusActive,
		IssuedAt:     time.Now(),
	}

	return r.save()
}

// Revoke marks a credential as revoked
func (r *Registry) Revoke(credentialID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.entries[credentialID]
	if !exists {
		return ErrCredentialNotFound
	}

	if entry.Status == StatusRevoked {
		return ErrAlreadyRevoked
	}

	entry.Status = StatusRevoked
	entry.RevokedAt = time.Now()
	entry.Reason = reason

	return r.save()
}

// CheckStatus returns the status of a credential
func (r *Registry) CheckStatus(credentialID string) (*Entry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.entries[credentialID]
	if !exists {
		return nil, ErrCredentialNotFound
	}

	return entry, nil
}

// IsRevoked checks if a credential is revoked
func (r *Registry) IsRevoked(credentialID string) (bool, error) {
	entry, err := r.CheckStatus(credentialID)
	if err != nil {
		return false, err
	}
	return entry.Status == StatusRevoked, nil
}

// ListByIssuer returns all credentials issued by a specific DID
func (r *Registry) ListByIssuer(issuerDID string) []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*Entry
	for _, entry := range r.entries {
		if entry.IssuerDID == issuerDID {
			results = append(results, entry)
		}
	}
	return results
}

// ListBySubject returns all credentials for a specific subject DID
func (r *Registry) ListBySubject(subjectDID string) []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*Entry
	for _, entry := range r.entries {
		if entry.SubjectDID == subjectDID {
			results = append(results, entry)
		}
	}
	return results
}

// save persists the registry to disk if a path is configured
func (r *Registry) save() error {
	if r.path == "" {
		return nil
	}

	data, err := json.MarshalIndent(r.entries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(r.path, data, 0644)
}

// Export returns all entries as JSON
func (r *Registry) Export() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return json.MarshalIndent(r.entries, "", "  ")
}
