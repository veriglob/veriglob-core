package zkp

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/veriglob/veriglob-core/internal/zkp/bbs"
	"github.com/veriglob/veriglob-core/internal/zkp/snark"
)

// CreateZKPresentation creates a presentation with selective disclosure and predicate proofs.
func CreateZKPresentation(
	credential *ZKCredential,
	holderDID string,
	bbsKeyPair *bbs.KeyPair,
	request SelectiveDisclosureRequest,
	audience string,
	nonce string,
) (*ZKPresentation, error) {
	// 1. Parse the BBS+ signature from the credential
	sig, err := bbs.DeserializeSignature(credential.BBSSignature)
	if err != nil {
		return nil, err
	}

	// 2. Map revealed field names to message indexes
	revealedIndexes, err := MapFieldsToIndexes(credential, request.RevealedFields)
	if err != nil {
		return nil, err
	}

	// 3. Create BBS+ selective disclosure proof
	// Slice generators to match message count (len(messages)+1)
	generators := bbsKeyPair.Generators[:len(credential.Messages)+1]
	bbsProof, err := bbs.CreateSelectiveDisclosureProof(
		sig,
		bbsKeyPair.PublicKey,
		generators,
		credential.Messages,
		revealedIndexes,
		[]byte(nonce),
	)
	if err != nil {
		return nil, err
	}

	// 4. Extract revealed field values
	disclosedFields := make(map[string]interface{})
	for i, idx := range revealedIndexes {
		fieldName := credential.FieldNames[idx]
		disclosedFields[fieldName] = string(bbsProof.RevealedMessages[i])
	}

	// 5. Generate SNARK proofs for predicates (if any)
	var predicateProofs []SNARKProof
	for _, pred := range request.Predicates {
		proof, err := createPredicateProof(credential, pred, nonce)
		if err != nil {
			return nil, err
		}
		predicateProofs = append(predicateProofs, *proof)
	}

	// 6. Generate presentation ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	presentationID := "urn:uuid:" + hex.EncodeToString(idBytes[:4]) + "-" +
		hex.EncodeToString(idBytes[4:6]) + "-" +
		hex.EncodeToString(idBytes[6:8]) + "-" +
		hex.EncodeToString(idBytes[8:10]) + "-" +
		hex.EncodeToString(idBytes[10:])

	now := time.Now()

	return &ZKPresentation{
		ID:              presentationID,
		Holder:          holderDID,
		Audience:        audience,
		Nonce:           nonce,
		DisclosedFields: disclosedFields,
		BBSProof:        bbsProof.Serialize(),
		BBSPublicKey:    credential.BBSPublicKey,
		RevealedIndexes: revealedIndexes,
		PredicateProofs: predicateProofs,
		IssuedAt:        now,
		ExpiresAt:       now.Add(15 * time.Minute), // Short-lived
	}, nil
}

// createPredicateProof generates a SNARK proof for a predicate.
func createPredicateProof(credential *ZKCredential, pred PredicateProof, nonce string) (*SNARKProof, error) {
	// Get the field value
	fieldValue, err := credential.GetFieldValue(pred.FieldName)
	if err != nil {
		return nil, err
	}

	// Convert field value to big.Int (assuming numeric value)
	value := new(big.Int).SetBytes(fieldValue)

	// Convert threshold to big.Int
	var threshold *big.Int
	switch t := pred.Threshold.(type) {
	case int:
		threshold = big.NewInt(int64(t))
	case int64:
		threshold = big.NewInt(t)
	case *big.Int:
		threshold = t
	default:
		return nil, ErrFieldTypeMismatch
	}

	// Generate salt and commitment
	salt, err := snark.GenerateSalt()
	if err != nil {
		return nil, err
	}
	commitment := snark.ComputeCommitment(value, salt)

	// Determine circuit type based on predicate
	var circuitType snark.CircuitType
	switch pred.Predicate {
	case PredicateGreaterThan:
		circuitType = snark.CircuitRangeGreaterThan
	case PredicateGreaterOrEqual:
		circuitType = snark.CircuitRangeGreaterOrEqual
	case PredicateLessThan:
		circuitType = snark.CircuitRangeLessThan
	default:
		return nil, ErrUnsupportedPredicate
	}

	// Setup circuit (in production, these would be pre-computed)
	pk, _, err := snark.SetupRangeProof(circuitType, snark.DefaultBitWidth)
	if err != nil {
		return nil, err
	}

	// Generate proof
	input := &snark.RangeProofInput{
		Value:      value,
		Threshold:  threshold,
		Salt:       salt,
		Commitment: commitment,
	}

	proof, err := snark.GenerateRangeProof(pk, input)
	if err != nil {
		return nil, err
	}

	proofBytes, err := snark.SerializeProof(proof)
	if err != nil {
		return nil, err
	}

	// Serialize public inputs
	publicInputs := append(threshold.Bytes(), commitment.Bytes()...)

	return &SNARKProof{
		FieldName:     pred.FieldName,
		PredicateType: pred.Predicate,
		Proof:         proofBytes,
		PublicInputs:  publicInputs,
		Threshold:     pred.Threshold,
	}, nil
}

// VerifyZKPresentation verifies a ZK presentation.
func VerifyZKPresentation(
	presentation *ZKPresentation,
	bbsKeyPair *bbs.KeyPair,
	expectedAudience string,
	expectedNonce string,
) error {
	// 1. Check expiration
	if time.Now().After(presentation.ExpiresAt) {
		return ErrPresentationExpired
	}

	// 2. Verify audience
	if expectedAudience != "" && presentation.Audience != expectedAudience {
		return ErrAudienceMismatch
	}

	// 3. Verify nonce
	if expectedNonce != "" && presentation.Nonce != expectedNonce {
		return ErrNonceMismatch
	}

	// 4. Parse and verify BBS+ proof
	bbsProof, err := bbs.DeserializeProof(presentation.BBSProof)
	if err != nil {
		return err
	}

	// Determine message count from proof (revealed + hidden responses)
	totalMessages := len(bbsProof.RevealedIndexes) + len(bbsProof.ResponseMessages)
	generators := bbsKeyPair.Generators[:totalMessages+1]

	err = bbs.VerifySelectiveDisclosureProof(
		bbsProof,
		bbsKeyPair.PublicKey,
		generators,
		[]byte(presentation.Nonce),
	)
	if err != nil {
		return ErrBBSProofInvalid
	}

	// 5. Verify SNARK proofs for predicates
	for _, snarkProof := range presentation.PredicateProofs {
		err := verifyPredicateProof(&snarkProof)
		if err != nil {
			return err
		}
	}

	return nil
}

// verifyPredicateProof verifies a single SNARK predicate proof.
func verifyPredicateProof(proof *SNARKProof) error {
	// Determine circuit type
	var circuitType snark.CircuitType
	switch proof.PredicateType {
	case PredicateGreaterThan:
		circuitType = snark.CircuitRangeGreaterThan
	case PredicateGreaterOrEqual:
		circuitType = snark.CircuitRangeGreaterOrEqual
	case PredicateLessThan:
		circuitType = snark.CircuitRangeLessThan
	default:
		return ErrUnsupportedPredicate
	}

	// Setup circuit to get verifying key (in production, these would be pre-loaded)
	_, vk, err := snark.SetupRangeProof(circuitType, snark.DefaultBitWidth)
	if err != nil {
		return err
	}

	// Deserialize proof
	groth16Proof, err := snark.DeserializeProof(proof.Proof)
	if err != nil {
		return err
	}

	// Parse public inputs (threshold and commitment)
	// For simplicity, assuming threshold is first 32 bytes, commitment is rest
	threshold := new(big.Int).SetBytes(proof.PublicInputs[:32])
	commitment := new(big.Int).SetBytes(proof.PublicInputs[32:])

	// Verify proof
	err = snark.VerifyRangeProof(vk, groth16Proof, threshold, commitment)
	if err != nil {
		return ErrSNARKProofInvalid
	}

	return nil
}

// GenerateNonce creates a random nonce for challenge-response.
func GenerateNonce() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
