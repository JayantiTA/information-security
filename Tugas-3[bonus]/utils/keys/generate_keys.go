package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {
	// Check if command-line arguments are provided
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run generate_keys.go <A/B>")
	}

	// Generate private and public keys
	if os.Args[1] == "A" {
		privateKeyA, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal("Failed to generate private key:", err)
		}

		// Save the new keys
		savePrivateKey("../../initiator/private_key_A.pem", privateKeyA) // save to initiator folder
		savePublicKey("./public_key_A.pem", &privateKeyA.PublicKey)
	} else if os.Args[1] == "B" {
		privateKeyB, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal("Failed to generate private key:", err)
		}

		// Save the new keys
		savePrivateKey("../../responder/private_key_B.pem", privateKeyB) // save to responder folder
		savePublicKey("./public_key_B.pem", &privateKeyB.PublicKey)
	} else {
		log.Fatal("Usage: go run generate_keys.go <A/B>")
	}
}

func savePrivateKey(filename string, key *rsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("Failed to create private key file:", err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		log.Fatal("Failed to write private key to file:", err)
	}
}

func savePublicKey(filename string, key *rsa.PublicKey) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal("Failed to create public key file:", err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(key)})
	if err != nil {
		log.Fatal("Failed to write public key to file:", err)
	}
}
