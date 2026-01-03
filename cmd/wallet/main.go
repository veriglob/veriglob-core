package main

import (
	"fmt"
	"log"

	"veriglob/internal/crypto"
	"veriglob/internal/did"
)

func main() {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		log.Fatal(err)
	}

	didKey, err := did.CreateDIDKey(pub)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("DID:")
	fmt.Println(didKey.DID)
	fmt.Println("\nDID Document:")

	doc, err := didKey.PrettyPrint()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(doc)
}
