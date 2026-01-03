package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/veriglob/veriglob-core/internal/crypto"
	"github.com/veriglob/veriglob-core/internal/did"
	"github.com/veriglob/veriglob-core/internal/revocation"
	"github.com/veriglob/veriglob-core/internal/vc"
)

const defaultRegistryPath = "revocation_registry.json"

func main() {
	credType := flag.String("type", "identity", "Credential type: identity, education, employment, membership")
	output := flag.String("output", "", "Output file for the credential (optional)")
	registryPath := flag.String("registry", defaultRegistryPath, "Path to revocation registry file")
	revokeID := flag.String("revoke", "", "Credential ID to revoke (instead of issuing)")
	revokeReason := flag.String("reason", "", "Reason for revocation")
	listRevoked := flag.Bool("list", false, "List all credentials in registry")
	flag.Parse()

	// Load or create revocation registry
	registry, err := revocation.NewRegistryWithFile(*registryPath)
	if err != nil {
		log.Fatalf("Failed to load revocation registry: %v", err)
	}

	// Handle revocation command
	if *revokeID != "" {
		if err := registry.Revoke(*revokeID, *revokeReason); err != nil {
			log.Fatalf("Failed to revoke credential: %v", err)
		}
		fmt.Printf("Credential %s has been revoked\n", *revokeID)
		return
	}

	// Handle list command
	if *listRevoked {
		data, err := registry.Export()
		if err != nil {
			log.Fatalf("Failed to export registry: %v", err)
		}
		fmt.Println(string(data))
		return
	}

	// Generate issuer keypair and DID
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		log.Fatalf("Failed to generate issuer keypair: %v", err)
	}

	issuerDID, err := did.CreateDIDKey(issuerPub)
	if err != nil {
		log.Fatalf("Failed to create issuer DID: %v", err)
	}

	// Generate subject keypair and DID
	subjectPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		log.Fatalf("Failed to generate subject keypair: %v", err)
	}

	subjectDID, err := did.CreateDIDKey(subjectPub)
	if err != nil {
		log.Fatalf("Failed to create subject DID: %v", err)
	}

	// Generate credential ID for revocation tracking
	credentialID, err := revocation.GenerateCredentialID()
	if err != nil {
		log.Fatalf("Failed to generate credential ID: %v", err)
	}

	// Create credential subject based on type
	var subject vc.CredentialSubject
	switch *credType {
	case "identity":
		subject = vc.IdentitySubject{
			ID:            subjectDID.DID,
			GivenName:     "John",
			FamilyName:    "Doe",
			DateOfBirth:   "1990-01-15",
			Nationality:   "US",
			DocumentType:  "passport",
			DocumentID:    "AB1234567",
			VerifiedAt:    "2024-01-15T10:30:00Z",
			VerifiedLevel: "high",
		}
	case "education":
		subject = vc.EducationSubject{
			ID:              subjectDID.DID,
			InstitutionName: "University of Technology",
			Degree:          "Bachelor of Science",
			FieldOfStudy:    "Computer Science",
			GraduationDate:  "2020-05-15",
			Grade:           "3.8 GPA",
		}
	case "employment":
		subject = vc.EmploymentSubject{
			ID:              subjectDID.DID,
			EmployerName:    "Tech Corp Inc.",
			JobTitle:        "Software Engineer",
			Department:      "Engineering",
			StartDate:       "2021-06-01",
			EmploymentType:  "full-time",
			CurrentEmployee: true,
		}
	case "membership":
		subject = vc.MembershipSubject{
			ID:               subjectDID.DID,
			OrganizationName: "Professional Developers Association",
			MembershipID:     "PDA-2024-001234",
			MembershipType:   "premium",
			Role:             "member",
			AccessLevel:      "full",
			StartDate:        "2024-01-01",
			ActiveMember:     true,
		}
	default:
		log.Fatalf("Unknown credential type: %s. Use: identity, education, employment, membership", *credType)
	}

	// Issue the credential with ID
	token, err := vc.IssueVCWithID(issuerDID.DID, subjectDID.DID, issuerPriv, subject, credentialID)
	if err != nil {
		log.Fatalf("Failed to issue credential: %v", err)
	}

	// Register credential in revocation registry
	if err := registry.Register(credentialID, issuerDID.DID, subjectDID.DID); err != nil {
		log.Fatalf("Failed to register credential: %v", err)
	}

	// Prepare output
	result := map[string]interface{}{
		"credentialId": credentialID,
		"issuer": map[string]string{
			"did":       issuerDID.DID,
			"publicKey": fmt.Sprintf("%x", issuerPub),
		},
		"subject": map[string]string{
			"did": subjectDID.DID,
		},
		"credentialType": subject.CredentialType(),
		"token":          token,
	}

	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal output: %v", err)
	}

	// Output to file or stdout
	if *output != "" {
		if err := os.WriteFile(*output, jsonOutput, 0644); err != nil {
			log.Fatalf("Failed to write output file: %v", err)
		}
		fmt.Printf("Credential written to %s\n", *output)
	} else {
		fmt.Println(string(jsonOutput))
	}
}
