package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/veriglob/veriglob-core/internal/crypto"
	"github.com/veriglob/veriglob-core/internal/did"
	"github.com/veriglob/veriglob-core/internal/presentation"
	"github.com/veriglob/veriglob-core/internal/storage"

	"golang.org/x/term"
)

func getDefaultWalletPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".veriglob/wallet.json"
	}
	return filepath.Join(home, ".veriglob", "wallet.json")
}

func main() {
	credentialFile := flag.String("credential", "", "Path to credential JSON file")
	credentialID := flag.String("cred-id", "", "Credential ID to use from wallet")
	walletPath := flag.String("wallet", getDefaultWalletPath(), "Path to wallet file")
	audience := flag.String("audience", "", "Verifier DID (audience for the presentation)")
	nonce := flag.String("nonce", "", "Challenge nonce from verifier (optional, will generate if not provided)")
	output := flag.String("output", "", "Output file for the presentation (optional)")
	generateNonce := flag.Bool("generate-nonce", false, "Generate and print a nonce for challenge-response")
	flag.Parse()

	// Generate nonce command
	if *generateNonce {
		nonce, err := presentation.GenerateNonce()
		if err != nil {
			log.Fatalf("Failed to generate nonce: %v", err)
		}
		fmt.Println(nonce)
		return
	}

	if *credentialFile == "" && *credentialID == "" {
		printUsage()
		os.Exit(1)
	}

	var holderPub ed25519.PublicKey
	var holderPriv ed25519.PrivateKey
	var holderDIDStr string
	var credToken string
	var credID string

	// Try to use wallet
	wallet, walletErr := tryOpenWallet(*walletPath)

	if *credentialID != "" {
		// Load credential from wallet
		if walletErr != nil {
			log.Fatalf("Cannot use -cred-id without a wallet: %v", walletErr)
		}

		cred, err := wallet.GetCredential(*credentialID)
		if err != nil {
			log.Fatalf("Credential not found in wallet: %v", err)
		}

		credToken = cred.Token
		credID = cred.ID

		// Use wallet keys
		holderPub, holderPriv, err = wallet.GetKeys()
		if err != nil {
			log.Fatalf("Failed to get keys from wallet: %v", err)
		}
		holderDIDStr = wallet.GetDID()
		fmt.Printf("Using wallet identity: %s\n", holderDIDStr)
	} else {
		// Load credential from file
		credData, err := os.ReadFile(*credentialFile)
		if err != nil {
			log.Fatalf("Failed to read credential file: %v", err)
		}

		var credential struct {
			CredentialID string `json:"credentialId"`
			Subject      struct {
				DID string `json:"did"`
			} `json:"subject"`
			Token string `json:"token"`
		}

		if err := json.Unmarshal(credData, &credential); err != nil {
			log.Fatalf("Failed to parse credential file: %v", err)
		}

		credToken = credential.Token
		credID = credential.CredentialID

		// Try to use wallet keys if available
		if wallet != nil {
			holderPub, holderPriv, err = wallet.GetKeys()
			if err == nil {
				holderDIDStr = wallet.GetDID()
				fmt.Printf("Using wallet identity: %s\n", holderDIDStr)
			}
		}

		// Fall back to generating new keys
		if holderPriv == nil {
			holderPub, holderPriv, err = crypto.GenerateEd25519Keypair()
			if err != nil {
				log.Fatalf("Failed to generate holder keypair: %v", err)
			}

			holderDID, err := did.CreateDIDKey(holderPub)
			if err != nil {
				log.Fatalf("Failed to create holder DID: %v", err)
			}
			holderDIDStr = holderDID.DID
			fmt.Println("Generated temporary holder identity")
		}
	}

	// Use provided nonce or generate one
	challengeNonce := *nonce
	if challengeNonce == "" {
		var err error
		challengeNonce, err = presentation.GenerateNonce()
		if err != nil {
			log.Fatalf("Failed to generate nonce: %v", err)
		}
	}

	// Use provided audience or generate placeholder
	aud := *audience
	if aud == "" {
		aud = "did:key:verifier"
	}

	// Create the presentation
	vpToken, err := presentation.CreatePresentation(
		holderDIDStr,
		holderPriv,
		[]string{credToken},
		aud,
		challengeNonce,
	)
	if err != nil {
		log.Fatalf("Failed to create presentation: %v", err)
	}

	// Prepare output
	result := map[string]interface{}{
		"holder": map[string]string{
			"did":       holderDIDStr,
			"publicKey": fmt.Sprintf("%x", holderPub),
		},
		"audience": aud,
		"nonce":    challengeNonce,
		"credentials": []string{
			credID,
		},
		"presentation": vpToken,
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
		fmt.Printf("Presentation written to %s\n", *output)
	} else {
		fmt.Println(string(jsonOutput))
	}
}

func tryOpenWallet(path string) (*storage.Wallet, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, storage.ErrWalletNotFound
	}

	pass := readPassword("Enter wallet passphrase (or press Enter to skip): ")
	if pass == "" {
		return nil, storage.ErrWalletNotFound
	}

	return storage.OpenWallet(path, pass)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		return strings.TrimSpace(line)
	}
	return string(password)
}

func printUsage() {
	fmt.Println("Holder CLI - Create Verifiable Presentations")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  holder -credential <cred.json> -audience <verifier_did> [-nonce <challenge>]")
	fmt.Println("  holder -cred-id <id> -audience <verifier_did> [-nonce <challenge>]")
	fmt.Println("  holder -generate-nonce")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -credential    Path to credential JSON file from issuer")
	fmt.Println("  -cred-id       Credential ID to use from wallet")
	fmt.Println("  -wallet        Path to wallet file (default: ~/.veriglob/wallet.json)")
	fmt.Println("  -audience      Verifier's DID (who the presentation is for)")
	fmt.Println("  -nonce         Challenge nonce from verifier")
	fmt.Println("  -output        Output file for presentation JSON")
	fmt.Println("  -generate-nonce  Generate a random nonce")
}
