package main

import (
	"bufio"
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
	walletPath := flag.String("wallet", getDefaultWalletPath(), "Path to wallet file")
	createCmd := flag.Bool("create", false, "Create a new wallet")
	showCmd := flag.Bool("show", false, "Show wallet DID and info")
	listCreds := flag.Bool("list", false, "List stored credentials")
	addCred := flag.String("add", "", "Add credential from file")
	exportCmd := flag.Bool("export", false, "Export wallet data (unencrypted)")
	flag.Parse()

	// Create wallet
	if *createCmd {
		createWallet(*walletPath)
		return
	}

	// Show wallet info
	if *showCmd {
		showWallet(*walletPath)
		return
	}

	// List credentials
	if *listCreds {
		listCredentials(*walletPath)
		return
	}

	// Add credential
	if *addCred != "" {
		addCredential(*walletPath, *addCred)
		return
	}

	// Export wallet
	if *exportCmd {
		exportWallet(*walletPath)
		return
	}

	// Default: show usage
	printUsage()
}

func readMnemonic(prompt string) string {
	fmt.Print(prompt)
	// Try to read from terminal (hidden input)
	mnemonic, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// Fallback for non-terminal input
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		return strings.TrimSpace(line)
	}
	return string(mnemonic)
}

func createWallet(path string) {
	// Check if wallet exists
	if _, err := os.Stat(path); err == nil {
		fmt.Println("Wallet already exists at:", path)
		fmt.Print("Overwrite? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(response)) != "y" {
			fmt.Println("Aborted.")
			return
		}
		os.Remove(path)
	}

	fmt.Println("Enter your 12 or 24 word mnemonic recovery phrase.")
	fmt.Println("Words should be separated by spaces.")
	fmt.Println()

	// Get mnemonic
	mnemonic := readMnemonic("Mnemonic: ")

	// Validate mnemonic
	if err := storage.ValidateMnemonic(mnemonic); err != nil {
		log.Fatalf("Invalid mnemonic: %v", err)
	}

	// Confirm mnemonic
	mnemonic2 := readMnemonic("Confirm mnemonic: ")

	if mnemonic != mnemonic2 {
		log.Fatal("Mnemonics do not match")
	}

	// Create wallet
	wallet, err := storage.CreateWallet(path, mnemonic)
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	// Derive keypair from mnemonic for deterministic keys
	pub, priv, err := storage.DeriveKeysFromMnemonic(mnemonic)
	if err != nil {
		// Fallback to random keys if derivation fails
		pub, priv, err = crypto.GenerateEd25519Keypair()
		if err != nil {
			log.Fatalf("Failed to generate keypair: %v", err)
		}
	}

	// Create DID
	didKey, err := did.CreateDIDKey(pub)
	if err != nil {
		log.Fatalf("Failed to create DID: %v", err)
	}

	// Store in wallet
	if err := wallet.SetKeys(pub, priv, didKey.DID); err != nil {
		log.Fatalf("Failed to save keys: %v", err)
	}

	fmt.Println()
	fmt.Println("Wallet created successfully!")
	fmt.Println()
	fmt.Println("DID:", didKey.DID)
	fmt.Println("Wallet:", path)
	fmt.Println()
	fmt.Println("IMPORTANT: Your mnemonic is the ONLY way to recover your wallet.")
	fmt.Println("Store it securely and never share it with anyone.")
}

func showWallet(path string) {
	mnemonic := readMnemonic("Enter mnemonic: ")

	wallet, err := storage.OpenWallet(path, mnemonic)
	if err != nil {
		if err == storage.ErrWalletNotFound {
			fmt.Println("Wallet not found. Create one with: wallet -create")
			return
		}
		if err == storage.ErrInvalidMnemonic {
			fmt.Println("Invalid mnemonic")
			return
		}
		if err == storage.ErrInvalidWordCount {
			fmt.Println("Invalid mnemonic: must be 12 or 24 words")
			return
		}
		log.Fatalf("Failed to open wallet: %v", err)
	}

	pub, _, err := wallet.GetKeys()
	if err != nil {
		log.Fatalf("Failed to get keys: %v", err)
	}

	didKey, err := did.CreateDIDKey(pub)
	if err != nil {
		log.Fatalf("Failed to create DID: %v", err)
	}

	fmt.Println("DID:")
	fmt.Println(wallet.GetDID())
	fmt.Println()
	fmt.Println("DID Document:")
	doc, _ := didKey.PrettyPrint()
	fmt.Println(doc)
	fmt.Println()
	fmt.Printf("Stored Credentials: %d\n", len(wallet.ListCredentials()))
}

func listCredentials(path string) {
	mnemonic := readMnemonic("Enter mnemonic: ")

	wallet, err := storage.OpenWallet(path, mnemonic)
	if err != nil {
		if err == storage.ErrInvalidMnemonic || err == storage.ErrInvalidWordCount {
			fmt.Println("Invalid mnemonic")
			return
		}
		log.Fatalf("Failed to open wallet: %v", err)
	}

	creds := wallet.ListCredentials()
	if len(creds) == 0 {
		fmt.Println("No credentials stored.")
		return
	}

	fmt.Printf("Stored Credentials (%d):\n\n", len(creds))
	for i, c := range creds {
		fmt.Printf("[%d] %s\n", i+1, c.ID)
		fmt.Printf("    Type:      %s\n", c.Type)
		fmt.Printf("    Issuer:    %s\n", c.IssuerDID)
		fmt.Printf("    Issued:    %s\n", c.IssuedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Expires:   %s\n", c.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Stored:    %s\n", c.StoredAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}
}

func addCredential(walletPath, credPath string) {
	mnemonic := readMnemonic("Enter mnemonic: ")

	wallet, err := storage.OpenWallet(walletPath, mnemonic)
	if err != nil {
		if err == storage.ErrInvalidMnemonic || err == storage.ErrInvalidWordCount {
			fmt.Println("Invalid mnemonic")
			return
		}
		log.Fatalf("Failed to open wallet: %v", err)
	}

	// Read credential file
	data, err := os.ReadFile(credPath)
	if err != nil {
		log.Fatalf("Failed to read credential file: %v", err)
	}

	var cred struct {
		CredentialID   string `json:"credentialId"`
		CredentialType string `json:"credentialType"`
		Issuer         struct {
			DID       string `json:"did"`
			PublicKey string `json:"publicKey"`
		} `json:"issuer"`
		Token string `json:"token"`
	}

	if err := json.Unmarshal(data, &cred); err != nil {
		log.Fatalf("Failed to parse credential: %v", err)
	}

	storedCred := storage.StoredCredential{
		ID:              cred.CredentialID,
		Type:            cred.CredentialType,
		IssuerDID:       cred.Issuer.DID,
		IssuerPublicKey: cred.Issuer.PublicKey,
		Token:           cred.Token,
	}

	if err := wallet.AddCredential(storedCred); err != nil {
		if err == storage.ErrCredentialExists {
			fmt.Println("Credential already exists in wallet")
			return
		}
		log.Fatalf("Failed to add credential: %v", err)
	}

	fmt.Println("Credential added to wallet:")
	fmt.Printf("  ID:   %s\n", storedCred.ID)
	fmt.Printf("  Type: %s\n", storedCred.Type)
}

func exportWallet(path string) {
	mnemonic := readMnemonic("Enter mnemonic: ")

	wallet, err := storage.OpenWallet(path, mnemonic)
	if err != nil {
		if err == storage.ErrInvalidMnemonic || err == storage.ErrInvalidWordCount {
			fmt.Println("Invalid mnemonic")
			return
		}
		log.Fatalf("Failed to open wallet: %v", err)
	}

	data, err := wallet.Export()
	if err != nil {
		log.Fatalf("Failed to export wallet: %v", err)
	}

	fmt.Println(string(data))
}

func printUsage() {
	fmt.Println("Wallet CLI - Manage your decentralized identity")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  wallet -create              Create a new wallet")
	fmt.Println("  wallet -show                Show wallet DID and info")
	fmt.Println("  wallet -list                List stored credentials")
	fmt.Println("  wallet -add <cred.json>     Add credential to wallet")
	fmt.Println("  wallet -export              Export wallet data")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -wallet <path>    Path to wallet file (default: ~/.veriglob/wallet.json)")
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Println("  All operations require your 12 or 24 word mnemonic recovery phrase.")
}
