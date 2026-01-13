package zkp

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"

	"github.com/veriglob/veriglob-core/internal/vc"
	"github.com/veriglob/veriglob-core/internal/zkp/bbs"
)

// IssueZKCredential creates a ZK-enabled credential with both PASETO and BBS+ signatures.
// This provides backward compatibility with existing verifiers while enabling selective disclosure.
func IssueZKCredential(
	issuerDID string,
	subjectDID string,
	ed25519PrivateKey ed25519.PrivateKey,
	bbsKeyPair *bbs.KeyPair,
	subject ZKCredentialSubject,
	credentialID string,
) (*ZKCredential, error) {
	// 1. Issue traditional PASETO credential for backward compatibility
	pasetoToken, err := vc.IssueVCWithID(
		issuerDID, subjectDID, ed25519PrivateKey, subject, credentialID,
	)
	if err != nil {
		return nil, err
	}

	// 2. Convert subject to BBS+ messages
	fieldMessages, err := subject.ToFieldElements()
	if err != nil {
		return nil, err
	}
	fieldNames := subject.FieldNames()

	// 3. Build complete message array with metadata
	// Message format: [credentialID, issuerDID, subjectDID, issuedAt, expiresAt, ...fields]
	now := time.Now()
	expires := now.Add(365 * 24 * time.Hour)

	messages := make([][]byte, 0, 5+len(fieldMessages))

	// Metadata messages
	messages = append(messages, []byte(credentialID))
	messages = append(messages, []byte(issuerDID))
	messages = append(messages, []byte(subjectDID))
	messages = append(messages, encodeTime(now))
	messages = append(messages, encodeTime(expires))

	// Field messages
	messages = append(messages, fieldMessages...)

	// Build complete field names list
	allFieldNames := []string{"credentialId", "issuerDid", "subjectDid", "issuedAt", "expiresAt"}
	allFieldNames = append(allFieldNames, fieldNames...)

	// 4. Verify we have enough generators
	if len(messages) > bbsKeyPair.MessageCount {
		return nil, ErrInvalidMessageCount
	}

	// 5. Create BBS+ signature
	// We need len(messages)+1 generators (h0 for blinding + one per message)
	generators := bbsKeyPair.Generators[:len(messages)+1]
	bbsSig, err := bbs.Sign(bbsKeyPair.SecretKey, generators, messages)
	if err != nil {
		return nil, err
	}

	return &ZKCredential{
		OriginalToken: pasetoToken,
		BBSSignature:  bbsSig.Serialize(),
		BBSPublicKey:  bbsKeyPair.PublicKeyBytes(),
		Messages:      messages,
		FieldNames:    allFieldNames,
		CredentialID:  credentialID,
		IssuerDID:     issuerDID,
		SubjectDID:    subjectDID,
		IssuedAt:      now,
		ExpiresAt:     expires,
	}, nil
}

// VerifyZKCredentialSignature verifies the BBS+ signature on a ZK credential.
// The verification uses the public key and generators from the provided key pair.
// The credential's embedded public key must match the provided key pair's public key.
func VerifyZKCredentialSignature(cred *ZKCredential, bbsKeyPair *bbs.KeyPair) error {
	// Parse BBS+ signature
	sig, err := bbs.DeserializeSignature(cred.BBSSignature)
	if err != nil {
		return err
	}

	// Verify that the credential's public key matches the provided key pair
	credPkBytes := cred.BBSPublicKey
	kpPkBytes := bbsKeyPair.PublicKeyBytes()
	if len(credPkBytes) != len(kpPkBytes) {
		return ErrPublicKeyMismatch
	}
	for i := range credPkBytes {
		if credPkBytes[i] != kpPkBytes[i] {
			return ErrPublicKeyMismatch
		}
	}

	// Slice generators to match message count (len(messages)+1)
	generators := bbsKeyPair.Generators[:len(cred.Messages)+1]

	// Verify signature using the key pair's public key
	return bbs.Verify(sig, bbsKeyPair.PublicKey, generators, cred.Messages)
}

// GetFieldIndex returns the index of a field in the credential.
// Returns -1 if the field is not found.
func (c *ZKCredential) GetFieldIndex(fieldName string) int {
	for i, name := range c.FieldNames {
		if name == fieldName {
			return i
		}
	}
	return -1
}

// GetFieldValue returns the value of a field by name.
func (c *ZKCredential) GetFieldValue(fieldName string) ([]byte, error) {
	idx := c.GetFieldIndex(fieldName)
	if idx < 0 || idx >= len(c.Messages) {
		return nil, ErrFieldNotFound
	}
	return c.Messages[idx], nil
}

// MapFieldsToIndexes converts field names to message indexes.
func MapFieldsToIndexes(cred *ZKCredential, fieldNames []string) ([]int, error) {
	indexes := make([]int, len(fieldNames))
	for i, name := range fieldNames {
		idx := cred.GetFieldIndex(name)
		if idx < 0 {
			return nil, ErrFieldNotFound
		}
		indexes[i] = idx
	}
	return indexes, nil
}

// encodeTime encodes a time.Time to bytes for BBS+ messages.
func encodeTime(t time.Time) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t.Unix()))
	return buf
}

// decodeTime decodes bytes to time.Time.
func decodeTime(data []byte) time.Time {
	if len(data) < 8 {
		return time.Time{}
	}
	unix := binary.BigEndian.Uint64(data)
	return time.Unix(int64(unix), 0)
}

// Serialize converts a ZKCredential to JSON bytes.
func (c *ZKCredential) Serialize() ([]byte, error) {
	// Implementation would use encoding/json
	// Keeping simple for now
	return nil, nil
}
