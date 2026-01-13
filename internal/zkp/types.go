// Package zkp provides zero-knowledge proof capabilities for Veriglob credentials.
// It supports BBS+ signatures for selective disclosure and zk-SNARKs for predicate proofs.
package zkp

import (
	"time"

	"github.com/veriglob/veriglob-core/internal/vc"
)

// ZKCredentialSubject extends CredentialSubject for ZK operations.
// Types implementing this interface can be used with BBS+ selective disclosure.
type ZKCredentialSubject interface {
	vc.CredentialSubject

	// ToFieldElements converts the subject to BBS+ message array.
	// Each field becomes a separate message for selective disclosure.
	ToFieldElements() ([][]byte, error)

	// FieldNames returns the ordered list of field names corresponding to ToFieldElements.
	FieldNames() []string

	// GetField returns a field value by name.
	GetField(name string) (interface{}, bool)
}

// PredicateType identifies the type of predicate proof.
type PredicateType int

const (
	// PredicateGreaterThan proves value > threshold
	PredicateGreaterThan PredicateType = iota
	// PredicateLessThan proves value < threshold
	PredicateLessThan
	// PredicateGreaterOrEqual proves value >= threshold
	PredicateGreaterOrEqual
	// PredicateLessOrEqual proves value <= threshold
	PredicateLessOrEqual
	// PredicateEquals proves value == threshold
	PredicateEquals
	// PredicateNotEquals proves value != threshold
	PredicateNotEquals
	// PredicateInSet proves value is in a set
	PredicateInSet
)

// String returns a human-readable name for the predicate type.
func (p PredicateType) String() string {
	switch p {
	case PredicateGreaterThan:
		return "GreaterThan"
	case PredicateLessThan:
		return "LessThan"
	case PredicateGreaterOrEqual:
		return "GreaterOrEqual"
	case PredicateLessOrEqual:
		return "LessOrEqual"
	case PredicateEquals:
		return "Equals"
	case PredicateNotEquals:
		return "NotEquals"
	case PredicateInSet:
		return "InSet"
	default:
		return "Unknown"
	}
}

// PredicateProof defines a predicate to prove without revealing the actual value.
type PredicateProof struct {
	// FieldName is the credential field to prove about
	FieldName string
	// Predicate is the type of comparison
	Predicate PredicateType
	// Threshold is the comparison value
	Threshold interface{}
}

// SelectiveDisclosureRequest specifies which fields to reveal and which predicates to prove.
type SelectiveDisclosureRequest struct {
	// RevealedFields lists field names to disclose
	RevealedFields []string
	// Predicates lists predicates to prove without revealing values
	Predicates []PredicateProof
}

// ZKCredential wraps a credential with ZK capabilities.
// It contains both the original PASETO token (for backward compatibility)
// and BBS+ signature components for selective disclosure.
type ZKCredential struct {
	// OriginalToken is the PASETO v4 token for backward compatibility
	OriginalToken string `json:"originalToken"`

	// BBSSignature is the BBS+ signature over credential fields
	BBSSignature []byte `json:"bbsSignature"`

	// BBSPublicKey is the issuer's BBS+ public key
	BBSPublicKey []byte `json:"bbsPublicKey"`

	// Messages are the credential fields as BBS+ messages
	Messages [][]byte `json:"messages"`

	// FieldNames maps indexes to field names
	FieldNames []string `json:"fieldNames"`

	// Metadata
	CredentialID string    `json:"credentialId"`
	IssuerDID    string    `json:"issuerDid"`
	SubjectDID   string    `json:"subjectDid"`
	IssuedAt     time.Time `json:"issuedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// SNARKProof contains a zk-SNARK proof for a predicate.
type SNARKProof struct {
	// FieldName is the field this proof is about
	FieldName string `json:"fieldName"`
	// PredicateType identifies what is being proven
	PredicateType PredicateType `json:"predicateType"`
	// Proof is the serialized SNARK proof
	Proof []byte `json:"proof"`
	// PublicInputs contains the public inputs to the circuit
	PublicInputs []byte `json:"publicInputs"`
	// Threshold is the comparison value (public)
	Threshold interface{} `json:"threshold"`
}

// ZKPresentation contains selective disclosure proofs and predicate proofs.
type ZKPresentation struct {
	// ID is a unique identifier for this presentation
	ID string `json:"id"`

	// Holder is the DID of the credential holder
	Holder string `json:"holder"`

	// Audience is the intended verifier
	Audience string `json:"audience"`

	// Nonce is the challenge from the verifier
	Nonce string `json:"nonce"`

	// DisclosedFields contains the revealed field values
	DisclosedFields map[string]interface{} `json:"disclosedFields"`

	// BBSProof is the BBS+ selective disclosure proof
	BBSProof []byte `json:"bbsProof"`

	// BBSPublicKey is the issuer's BBS+ public key (needed for verification)
	BBSPublicKey []byte `json:"bbsPublicKey"`

	// RevealedIndexes indicates which message indexes were revealed
	RevealedIndexes []int `json:"revealedIndexes"`

	// PredicateProofs contains SNARK proofs for predicates
	PredicateProofs []SNARKProof `json:"predicateProofs,omitempty"`

	// Timestamps
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
