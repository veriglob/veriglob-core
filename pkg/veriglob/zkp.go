package veriglob

import (
	"crypto/ed25519"

	"github.com/veriglob/veriglob-core/internal/vc"
	"github.com/veriglob/veriglob-core/internal/zkp"
	"github.com/veriglob/veriglob-core/internal/zkp/bbs"
	"github.com/veriglob/veriglob-core/internal/zkp/snark"
)

// ============================================================================
// ZKP Type Exports
// ============================================================================

// ZK Credential types
type (
	// ZKCredential is a credential with both PASETO and BBS+ signatures
	ZKCredential = zkp.ZKCredential

	// ZKPresentation is a presentation with selective disclosure
	ZKPresentation = zkp.ZKPresentation

	// SelectiveDisclosureRequest specifies fields to reveal and predicates to prove
	SelectiveDisclosureRequest = zkp.SelectiveDisclosureRequest

	// PredicateProof defines a predicate to prove without revealing the value
	PredicateProof = zkp.PredicateProof

	// PredicateType identifies the type of predicate
	PredicateType = zkp.PredicateType

	// SNARKProof contains a zk-SNARK proof for a predicate
	SNARKProof = zkp.SNARKProof

	// ZKCredentialSubject is the interface for credential subjects supporting ZK proofs
	ZKCredentialSubject = zkp.ZKCredentialSubject
)

// BBS+ types
type (
	// BBSKeyPair contains BBS+ signing keys
	BBSKeyPair = bbs.KeyPair

	// BBSSignature is a BBS+ signature
	BBSSignature = bbs.Signature

	// BBSSelectiveDisclosureProof is a proof revealing only selected messages
	BBSSelectiveDisclosureProof = bbs.SelectiveDisclosureProof
)

// SNARK types
type (
	// SNARKProvingKey is a proving key for SNARK circuits
	SNARKProvingKey = snark.ProvingKey

	// SNARKVerifyingKey is a verifying key for SNARK circuits
	SNARKVerifyingKey = snark.VerifyingKey

	// SNARKCircuitType identifies a predefined circuit
	SNARKCircuitType = snark.CircuitType
)

// ZK-capable credential subject types
type (
	// ZKIdentitySubject is an identity subject with ZK capabilities
	ZKIdentitySubject = vc.ZKIdentitySubject

	// ZKEducationSubject is an education subject with ZK capabilities
	ZKEducationSubject = vc.ZKEducationSubject

	// ZKEmploymentSubject is an employment subject with ZK capabilities
	ZKEmploymentSubject = vc.ZKEmploymentSubject

	// ZKMembershipSubject is a membership subject with ZK capabilities
	ZKMembershipSubject = vc.ZKMembershipSubject
)

// ============================================================================
// ZKP Constants
// ============================================================================

// Predicate type constants
const (
	PredicateGreaterThan    = zkp.PredicateGreaterThan
	PredicateLessThan       = zkp.PredicateLessThan
	PredicateGreaterOrEqual = zkp.PredicateGreaterOrEqual
	PredicateLessOrEqual    = zkp.PredicateLessOrEqual
	PredicateEquals         = zkp.PredicateEquals
	PredicateNotEquals      = zkp.PredicateNotEquals
	PredicateInSet          = zkp.PredicateInSet
)

// SNARK circuit type constants
const (
	CircuitRangeGreaterThan    = snark.CircuitRangeGreaterThan
	CircuitRangeGreaterOrEqual = snark.CircuitRangeGreaterOrEqual
	CircuitRangeLessThan       = snark.CircuitRangeLessThan
	CircuitAgeVerification     = snark.CircuitAgeVerification
	CircuitEquality            = snark.CircuitEquality
)

// DefaultBitWidth is the default bit width for range proofs
const DefaultBitWidth = snark.DefaultBitWidth

// ============================================================================
// ZKP Errors
// ============================================================================

var (
	ErrZKInvalidKeySize          = zkp.ErrInvalidKeySize
	ErrZKInvalidMessageCount     = zkp.ErrInvalidMessageCount
	ErrZKInvalidSignature        = zkp.ErrInvalidSignature
	ErrZKProofVerificationFailed = zkp.ErrProofVerificationFailed
	ErrZKFieldNotFound           = zkp.ErrFieldNotFound
	ErrZKPresentationExpired     = zkp.ErrPresentationExpired
	ErrZKAudienceMismatch        = zkp.ErrAudienceMismatch
	ErrZKNonceMismatch           = zkp.ErrNonceMismatch
	ErrZKUnsupportedPredicate    = zkp.ErrUnsupportedPredicate
	ErrZKBBSProofInvalid         = zkp.ErrBBSProofInvalid
	ErrZKSNARKProofInvalid       = zkp.ErrSNARKProofInvalid
)

// ============================================================================
// BBS+ Key Generation
// ============================================================================

// GenerateBBSKeyPair creates a new BBS+ key pair for ZK credentials.
// messageCount specifies the maximum number of messages (credential fields) that can be signed.
// For identity credentials, use at least 20 to accommodate all fields plus metadata.
func GenerateBBSKeyPair(messageCount int) (*BBSKeyPair, error) {
	return bbs.GenerateKeyPair(messageCount)
}

// ============================================================================
// ZK Credential Functions
// ============================================================================

// IssueZKCredential creates a ZK-enabled credential with both PASETO and BBS+ signatures.
// This provides backward compatibility with existing verifiers while enabling selective disclosure.
//
// Parameters:
//   - issuerDID: The DID of the credential issuer
//   - subjectDID: The DID of the credential subject (holder)
//   - ed25519PrivateKey: The issuer's Ed25519 private key for PASETO signing
//   - bbsKeyPair: The issuer's BBS+ key pair for selective disclosure
//   - subject: The credential subject implementing ZKCredentialSubject interface
//   - credentialID: A unique identifier for this credential
//
// Returns a ZKCredential containing both signature types.
func IssueZKCredential(
	issuerDID string,
	subjectDID string,
	ed25519PrivateKey ed25519.PrivateKey,
	bbsKeyPair *BBSKeyPair,
	subject zkp.ZKCredentialSubject,
	credentialID string,
) (*ZKCredential, error) {
	return zkp.IssueZKCredential(
		issuerDID, subjectDID, ed25519PrivateKey, bbsKeyPair, subject, credentialID,
	)
}

// VerifyZKCredentialSignature verifies the BBS+ signature on a ZK credential.
func VerifyZKCredentialSignature(cred *ZKCredential, bbsKeyPair *BBSKeyPair) error {
	return zkp.VerifyZKCredentialSignature(cred, bbsKeyPair)
}

// ============================================================================
// ZK Presentation Functions
// ============================================================================

// CreateZKPresentation creates a presentation with selective disclosure and predicate proofs.
//
// Parameters:
//   - credential: The ZK credential to present
//   - holderDID: The DID of the credential holder
//   - bbsKeyPair: The issuer's BBS+ key pair (for proof generation)
//   - request: Specifies which fields to reveal and predicates to prove
//   - audience: The intended verifier's DID
//   - nonce: A challenge nonce from the verifier
//
// Example request for revealing only name and proving age > 21:
//
//	request := SelectiveDisclosureRequest{
//	    RevealedFields: []string{"givenName", "familyName"},
//	    Predicates: []PredicateProof{{
//	        FieldName: "dateOfBirth",
//	        Predicate: PredicateGreaterThan,
//	        Threshold: 21,
//	    }},
//	}
func CreateZKPresentation(
	credential *ZKCredential,
	holderDID string,
	bbsKeyPair *BBSKeyPair,
	request SelectiveDisclosureRequest,
	audience string,
	nonce string,
) (*ZKPresentation, error) {
	return zkp.CreateZKPresentation(
		credential, holderDID, bbsKeyPair, request, audience, nonce,
	)
}

// VerifyZKPresentation verifies a ZK presentation including BBS+ proofs and SNARK predicates.
//
// Parameters:
//   - presentation: The ZK presentation to verify
//   - bbsKeyPair: The issuer's BBS+ key pair
//   - expectedAudience: The expected audience (verifier DID), empty to skip check
//   - expectedNonce: The expected nonce, empty to skip check
func VerifyZKPresentation(
	presentation *ZKPresentation,
	bbsKeyPair *BBSKeyPair,
	expectedAudience string,
	expectedNonce string,
) error {
	return zkp.VerifyZKPresentation(
		presentation, bbsKeyPair, expectedAudience, expectedNonce,
	)
}

// GenerateZKNonce creates a random nonce for ZK presentation challenge-response.
func GenerateZKNonce() (string, error) {
	return zkp.GenerateNonce()
}

// ============================================================================
// SNARK Circuit Setup Functions
// ============================================================================

// SetupRangeProofCircuit performs trusted setup for a range proof circuit.
// This generates proving and verifying keys for the specified circuit type.
// In production, these keys should be pre-computed and stored securely.
func SetupRangeProofCircuit(circuitType SNARKCircuitType, bitWidth int) (*SNARKProvingKey, *SNARKVerifyingKey, error) {
	return snark.SetupRangeProof(circuitType, bitWidth)
}

// ============================================================================
// Helper Functions
// ============================================================================

// MapFieldsToIndexes converts field names to message indexes in a ZK credential.
func MapFieldsToIndexes(cred *ZKCredential, fieldNames []string) ([]int, error) {
	return zkp.MapFieldsToIndexes(cred, fieldNames)
}
