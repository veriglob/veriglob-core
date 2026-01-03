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

	"veriglob/internal/crypto"
	"veriglob/internal/did"
	"veriglob/internal/storage"

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

func readPassword(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// Fallback for non-terminal input
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		return strings.TrimSpace(line)
	}
	return string(password)
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

	// Get passphrase
	pass1 := readPassword("Enter passphrase: ")
	pass2 := readPassword("Confirm passphrase: ")

	if pass1 != pass2 {
		log.Fatal("Passphrases do not match")
	}

	if len(pass1) < 8 {
		log.Fatal("Passphrase must be at least 8 characters")
	}

	// Create wallet
	wallet, err := storage.CreateWallet(path, pass1)
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	// Generate keypair
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		log.Fatalf("Failed to generate keypair: %v", err)
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

	fmt.Println("Wallet created successfully!")
	fmt.Println()
	fmt.Println("DID:", didKey.DID)
	fmt.Println("Wallet:", path)
	fmt.Println()
	fmt.Println("IMPORTANT: Remember your passphrase. It cannot be recovered.")
}

func showWallet(path string) {
	pass := readPassword("Enter passphrase: ")

	wallet, err := storage.OpenWallet(path, pass)
	if err != nil {
		if err == storage.ErrWalletNotFound {
			fmt.Println("Wallet not found. Create one with: wallet -create")
			return
		}
		if err == storage.ErrInvalidPassword {
			fmt.Println("Invalid passphrase")
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
	pass := readPassword("Enter passphrase: ")

	wallet, err := storage.OpenWallet(path, pass)
	if err != nil {
		if err == storage.ErrInvalidPassword {
			fmt.Println("Invalid passphrase")
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
	pass := readPassword("Enter passphrase: ")

	wallet, err := storage.OpenWallet(walletPath, pass)
	if err != nil {
		if err == storage.ErrInvalidPassword {
			fmt.Println("Invalid passphrase")
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
	pass := readPassword("Enter passphrase: ")

	wallet, err := storage.OpenWallet(path, pass)
	if err != nil {
		if err == storage.ErrInvalidPassword {
			fmt.Println("Invalid passphrase")
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
}
