package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Fungsi untuk mengekspor kunci publik ke dalam file
func exportPublicKeyToFile(publicKey *rsa.PublicKey, filePath string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyPEM := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &publicKeyPEM)
	if err != nil {
		return err
	}

	fmt.Println("\nPublic key exported to", filePath)
	return nil
}

// Fungsi untuk mengekspor kunci privat ke dalam file
func exportPrivateKeyToFile(privateKey *rsa.PrivateKey, filePath string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &privateKeyPEM)
	if err != nil {
		return err
	}

	fmt.Println("Private key exported to", filePath)
	return nil
}

func main() {
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating server private key:", err)
		return
	}

	serverPublicKey := &serverPrivateKey.PublicKey
	
	// Export kunci publik server ke dalam file
	exportPublicKeyToFile(serverPublicKey, "server/server_public.key")

	// Export kunci privat server ke dalam file
	exportPrivateKeyToFile(serverPrivateKey, "server/server_private.key")

	fmt.Println("Keys generated for server")

	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating client private key:", err)
		return
	}

	clientPublicKey := &clientPrivateKey.PublicKey
	
	// Export kunci publik client ke dalam file
	exportPublicKeyToFile(clientPublicKey, "client/client_public.key")

	// Export kunci privat client ke dalam file
	exportPrivateKeyToFile(clientPrivateKey, "client/client_private.key")

	fmt.Println("Keys generated for client")
}
