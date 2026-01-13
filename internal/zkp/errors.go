package zkp

import "errors"

// ZKP-specific errors
var (
	// Key errors
	ErrInvalidKeySize      = errors.New("zkp: invalid key size")
	ErrKeyGenerationFailed = errors.New("zkp: key generation failed")

	// Signature errors
	ErrInvalidMessageCount  = errors.New("zkp: message count does not match generator count")
	ErrInvalidSignature     = errors.New("zkp: invalid BBS+ signature")
	ErrSignatureVerifyFailed = errors.New("zkp: signature verification failed")

	// Proof errors
	ErrProofGenerationFailed   = errors.New("zkp: proof generation failed")
	ErrProofVerificationFailed = errors.New("zkp: proof verification failed")
	ErrInvalidProof            = errors.New("zkp: invalid proof")
	ErrBBSProofInvalid         = errors.New("zkp: BBS+ selective disclosure proof invalid")
	ErrSNARKProofInvalid       = errors.New("zkp: SNARK proof invalid")

	// Field errors
	ErrFieldNotFound      = errors.New("zkp: field not found in credential")
	ErrInvalidFieldIndex  = errors.New("zkp: field index out of bounds")
	ErrFieldTypeMismatch  = errors.New("zkp: field type does not match expected type")

	// Presentation errors
	ErrPresentationExpired  = errors.New("zkp: presentation has expired")
	ErrAudienceMismatch     = errors.New("zkp: audience mismatch")
	ErrNonceMismatch        = errors.New("zkp: nonce mismatch")
	ErrInvalidPresentation  = errors.New("zkp: invalid presentation format")

	// Predicate errors
	ErrUnsupportedPredicate = errors.New("zkp: unsupported predicate type")
	ErrPredicateFailed      = errors.New("zkp: predicate condition not satisfied")

	// Circuit errors
	ErrCircuitCompileFailed = errors.New("zkp: circuit compilation failed")
	ErrCircuitSetupFailed   = errors.New("zkp: circuit setup failed")
	ErrWitnessGenerationFailed = errors.New("zkp: witness generation failed")

	// Credential errors
	ErrInvalidCredential      = errors.New("zkp: invalid credential")
	ErrCredentialNotZKEnabled = errors.New("zkp: credential does not have ZK capabilities")
	ErrPublicKeyMismatch      = errors.New("zkp: public key does not match credential")
)
