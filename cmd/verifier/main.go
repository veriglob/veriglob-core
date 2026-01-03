package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"veriglob/internal/presentation"
	"veriglob/internal/resolver"
	"veriglob/internal/revocation"
	"veriglob/internal/vc"
)

const defaultRegistryPath = "revocation_registry.json"

func main() {
	// Credential verification flags
	tokenFlag := flag.String("token", "", "PASETO token to verify")
	publicKeyFlag := flag.String("pubkey", "", "Issuer's public key (hex encoded)")
	issuerDID := flag.String("issuer", "", "Issuer's DID (will auto-resolve public key)")
	inputFile := flag.String("input", "", "Input file containing credential JSON (from issuer)")
	registryPath := flag.String("registry", defaultRegistryPath, "Path to revocation registry file")
	skipRevocation := flag.Bool("skip-revocation", false, "Skip revocation check")

	// Presentation verification flags
	presentationFile := flag.String("presentation", "", "Input file containing presentation JSON (from holder)")
	expectedNonce := flag.String("nonce", "", "Expected nonce for presentation verification")
	expectedAudience := flag.String("audience", "", "Expected audience (verifier DID) for presentation")

	flag.Parse()

	// Handle presentation verification
	if *presentationFile != "" {
		verifyPresentation(*presentationFile, *expectedNonce, *expectedAudience, *registryPath, *skipRevocation)
		return
	}

	// Handle credential verification
	verifyCredential(*inputFile, *tokenFlag, *publicKeyFlag, *issuerDID, *registryPath, *skipRevocation)
}

func verifyPresentation(presentationFile, expectedNonce, expectedAudience, registryPath string, skipRevocation bool) {
	data, err := os.ReadFile(presentationFile)
	if err != nil {
		log.Fatalf("Failed to read presentation file: %v", err)
	}

	var pres struct {
		Holder struct {
			DID       string `json:"did"`
			PublicKey string `json:"publicKey"`
		} `json:"holder"`
		Audience     string `json:"audience"`
		Nonce        string `json:"nonce"`
		Presentation string `json:"presentation"`
	}

	if err := json.Unmarshal(data, &pres); err != nil {
		log.Fatalf("Failed to parse presentation file: %v", err)
	}

	// Try to resolve holder public key from DID first, fall back to hex-encoded key
	var holderPubKey ed25519.PublicKey
	if pres.Holder.DID != "" {
		resolved, err := resolver.ResolveDID(pres.Holder.DID)
		if err == nil {
			holderPubKey = resolved
			fmt.Printf("🔑 Resolved holder public key from DID\n")
		}
	}

	// Fall back to hex-encoded public key if DID resolution failed
	if holderPubKey == nil && pres.Holder.PublicKey != "" {
		holderPubBytes, err := hex.DecodeString(pres.Holder.PublicKey)
		if err != nil {
			log.Fatalf("Failed to decode holder public key: %v", err)
		}
		holderPubKey = ed25519.PublicKey(holderPubBytes)
	}

	if holderPubKey == nil {
		log.Fatalf("Could not determine holder public key")
	}

	// Use file values if not overridden
	if expectedNonce == "" {
		expectedNonce = pres.Nonce
	}
	if expectedAudience == "" {
		expectedAudience = pres.Audience
	}

	// Verify the presentation
	vpClaims, err := presentation.VerifyPresentation(pres.Presentation, holderPubKey, expectedAudience, expectedNonce)
	if err != nil {
		fmt.Println("❌ PRESENTATION VERIFICATION FAILED")
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ PRESENTATION VERIFIED")
	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("Presentation ID: %s\n", vpClaims.VP.ID)
	fmt.Printf("Holder:          %s\n", vpClaims.VP.Holder)
	fmt.Printf("Audience:        %s\n", vpClaims.Audience)
	fmt.Printf("Nonce:           %s\n", vpClaims.Nonce)
	fmt.Printf("Issued At:       %s\n", vpClaims.IssuedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Expires At:      %s\n", vpClaims.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Credentials:     %d\n", len(vpClaims.VP.VerifiableCredential))

	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("Embedded Credentials:")

	// Verify each embedded credential using DID resolution
	for i, credToken := range vpClaims.VP.VerifiableCredential {
		fmt.Printf("\n[Credential %d]\n", i+1)
		verifyEmbeddedCredential(credToken, registryPath, skipRevocation)
	}
}

func verifyEmbeddedCredential(token, registryPath string, skipRevocation bool) {
	// First, we need to decode the token to get the issuer DID
	// PASETO tokens are base64url encoded, we can parse the payload
	// For now, we'll try to verify by resolving the issuer from the token claims

	// Try common issuer DIDs or extract from token
	// Since PASETO is encrypted, we need to try verification with resolved keys
	// This is a simplified approach - in production, you'd have issuer metadata

	// Parse the token to extract issuer (PASETO v4 public tokens have readable payload)
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		fmt.Println("  ⚠️  Invalid token format")
		return
	}

	// For demonstration, show token prefix
	fmt.Printf("  Token: %s...\n", token[:min(60, len(token))])
	fmt.Println("  ℹ️  To verify embedded credentials, issuer DID resolution is needed")
	fmt.Println("  ℹ️  Use: verifier -token <token> -issuer <issuer_did>")
}

func verifyCredential(inputFile, tokenFlag, publicKeyFlag, issuerDIDFlag, registryPath string, skipRevocation bool) {
	var token string
	var publicKey ed25519.PublicKey
	var issuerDIDResolved string

	// Load from file if provided
	if inputFile != "" {
		data, err := os.ReadFile(inputFile)
		if err != nil {
			log.Fatalf("Failed to read input file: %v", err)
		}

		var credential struct {
			CredentialID string `json:"credentialId"`
			Issuer       struct {
				DID       string `json:"did"`
				PublicKey string `json:"publicKey"`
			} `json:"issuer"`
			Token string `json:"token"`
		}

		if err := json.Unmarshal(data, &credential); err != nil {
			log.Fatalf("Failed to parse credential file: %v", err)
		}

		token = credential.Token

		// Try to resolve public key from issuer DID first
		if credential.Issuer.DID != "" {
			resolved, err := resolver.ResolveDID(credential.Issuer.DID)
			if err == nil {
				publicKey = resolved
				issuerDIDResolved = credential.Issuer.DID
				fmt.Printf("🔑 Resolved issuer public key from DID\n")
			}
		}

		// Fall back to hex-encoded public key
		if publicKey == nil && credential.Issuer.PublicKey != "" {
			pubKeyBytes, err := hex.DecodeString(credential.Issuer.PublicKey)
			if err != nil {
				log.Fatalf("Failed to decode public key: %v", err)
			}
			publicKey = ed25519.PublicKey(pubKeyBytes)
		}
	} else if tokenFlag != "" {
		token = tokenFlag

		// Try DID resolution first
		if issuerDIDFlag != "" {
			resolved, err := resolver.ResolveDID(issuerDIDFlag)
			if err != nil {
				log.Fatalf("Failed to resolve issuer DID: %v", err)
			}
			publicKey = resolved
			issuerDIDResolved = issuerDIDFlag
			fmt.Printf("🔑 Resolved issuer public key from DID\n")
		} else if publicKeyFlag != "" {
			// Fall back to hex-encoded public key
			pubKeyBytes, err := hex.DecodeString(publicKeyFlag)
			if err != nil {
				log.Fatalf("Failed to decode public key: %v", err)
			}
			publicKey = ed25519.PublicKey(pubKeyBytes)
		} else {
			printUsage()
			os.Exit(1)
		}
	} else {
		printUsage()
		os.Exit(1)
	}

	if publicKey == nil {
		log.Fatalf("Could not determine issuer public key")
	}

	// Verify the credential signature
	claims, err := vc.VerifyVC(token, publicKey)
	if err != nil {
		fmt.Println("❌ VERIFICATION FAILED")
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Check revocation status
	credentialID := claims.GetCredentialID()
	revocationStatus := "not tracked"
	isRevoked := false

	if credentialID != "" && !skipRevocation {
		registry, err := revocation.NewRegistryWithFile(registryPath)
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not load revocation registry: %v\n", err)
		} else {
			entry, err := registry.CheckStatus(credentialID)
			if err == nil {
				revocationStatus = string(entry.Status)
				isRevoked = entry.Status == revocation.StatusRevoked
			} else if err == revocation.ErrCredentialNotFound {
				revocationStatus = "not in registry"
			}
		}
	}

	if isRevoked {
		fmt.Println("❌ CREDENTIAL REVOKED")
	} else {
		fmt.Println("✅ VERIFICATION SUCCESSFUL")
	}
	fmt.Println(strings.Repeat("─", 50))

	// Display claims
	if credentialID != "" {
		fmt.Printf("Credential ID: %s\n", credentialID)
	}
	if issuerDIDResolved != "" {
		fmt.Printf("Issuer:        %s (resolved)\n", claims.Issuer)
	} else {
		fmt.Printf("Issuer:        %s\n", claims.Issuer)
	}
	fmt.Printf("Subject:       %s\n", claims.Subject)
	fmt.Printf("Issued At:     %s\n", claims.IssuedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Expires At:    %s\n", claims.ExpiresAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Status:        %s\n", revocationStatus)

	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("Credential Types:")
	for _, t := range claims.VC.Type {
		fmt.Printf("  • %s\n", t)
	}

	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("Credential Subject:")

	subjectJSON, err := json.MarshalIndent(claims.VC.CredentialSubject, "  ", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal subject: %v", err)
	}
	fmt.Printf("  %s\n", subjectJSON)

	// Exit with error code if revoked
	if isRevoked {
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Verifier CLI - Verify Credentials and Presentations")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  Verify credential:")
	fmt.Println("    verifier -input <credential.json>")
	fmt.Println("    verifier -token <paseto_token> -issuer <issuer_did>")
	fmt.Println("    verifier -token <paseto_token> -pubkey <hex_public_key>")
	fmt.Println()
	fmt.Println("  Verify presentation:")
	fmt.Println("    verifier -presentation <presentation.json>")
	fmt.Println("    verifier -presentation <presentation.json> -nonce <expected_nonce> -audience <verifier_did>")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -issuer <did>       Issuer's DID (auto-resolves public key)")
	fmt.Println("  -pubkey <hex>       Issuer's public key (hex encoded)")
	fmt.Println("  -registry <path>    Path to revocation registry (default: revocation_registry.json)")
	fmt.Println("  -skip-revocation    Skip revocation status check")
	fmt.Println("  -nonce              Expected nonce for presentation verification")
	fmt.Println("  -audience           Expected audience for presentation verification")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
