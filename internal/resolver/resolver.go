package resolver

import (
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/mr-tron/base58"
)

var (
	ErrInvalidDID        = errors.New("invalid DID format")
	ErrUnsupportedMethod = errors.New("unsupported DID method")
	ErrInvalidMulticodec = errors.New("invalid multicodec prefix")
	ErrInvalidKeyLength  = errors.New("invalid public key length")
)

// ed25519Multicodec is the multicodec prefix for Ed25519 public keys (0xed01)
var ed25519Multicodec = []byte{0xed, 0x01}

// Resolver resolves DIDs to their public keys
type Resolver struct{}

// New creates a new DID resolver
func NewResolver() *Resolver {
	return &Resolver{}
}

// Resolve extracts the public key from a DID
// Currently supports: did:key
func (r *Resolver) Resolve(did string) (ed25519.PublicKey, error) {
	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return nil, ErrInvalidDID
	}

	if parts[0] != "did" {
		return nil, ErrInvalidDID
	}

	method := parts[1]
	switch method {
	case "key":
		return r.resolveKey(parts[2])
	default:
		return nil, ErrUnsupportedMethod
	}
}

// resolveKey extracts the public key from a did:key identifier
func (r *Resolver) resolveKey(identifier string) (ed25519.PublicKey, error) {
	// did:key uses multibase encoding with 'z' prefix (base58btc)
	if len(identifier) == 0 || identifier[0] != 'z' {
		return nil, ErrInvalidDID
	}

	// Decode base58 (skip the 'z' prefix)
	decoded, err := base58.Decode(identifier[1:])
	if err != nil {
		return nil, err
	}

	// Check multicodec prefix (0xed01 for Ed25519)
	if len(decoded) < 2 {
		return nil, ErrInvalidMulticodec
	}

	if decoded[0] != ed25519Multicodec[0] || decoded[1] != ed25519Multicodec[1] {
		return nil, ErrInvalidMulticodec
	}

	// Extract public key (skip the 2-byte multicodec prefix)
	pubKeyBytes := decoded[2:]

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeyLength
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// ResolveDID is a convenience function that creates a resolver and resolves a DID
func ResolveDID(did string) (ed25519.PublicKey, error) {
	return NewResolver().Resolve(did)
}
