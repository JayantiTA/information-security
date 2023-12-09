package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/rpc"
	"os"
)

const (
	privateKeyFile = "private_key.pem"
	publicKeyFile  = "public_key.pem"
)

type KDCRequest struct {
	FromID  string
	ToID    string
	Nonce   []byte
	Session *rsa.PublicKey
}

type KDCResponse struct {
	SessionKey       []byte
	EncryptedInfoToA string
}

func main() {
	privateKeyA, publicKeyA := loadOrGenerateKeys()

	serverAddress := "127.0.0.1:1234"

	client, err := rpc.Dial("tcp", serverAddress)
	if err != nil {
		log.Fatal("Dialing:", err)
	}
	fmt.Printf("Initiator connected to server at %s\n\n", serverAddress)

	// Langkah 1: Mengirim permintaan ke KDC untuk kunci sesi
	requestToKDC := KDCRequest{
		FromID:  "IDA",
		ToID:    "IDB",
		Nonce:   generateNonce(),
		Session: publicKeyA,
	}
	// fmt.Printf("Mengirim permintaan ke KDC: \n%+v\n\n", requestToKDC)
	fmt.Printf("Mengirim permintaan ke KDC: \nFromID: %s\nToID: %s\nNonce: %s\nSession: %v\n\n", requestToKDC.FromID, requestToKDC.ToID, base64.StdEncoding.EncodeToString(requestToKDC.Nonce), base64.StdEncoding.EncodeToString(requestToKDC.Session.N.Bytes()))

	// Mengirim permintaan ke KDC
	var responseFromKDC KDCResponse
	err = client.Call("KDC.RequestSessionKey", requestToKDC, &responseFromKDC)
	if err != nil {
		log.Fatal("KDC error:", err)
	}

	// Langkah 2: Mendekripsi respons dari KDC
	// Decrypt the session key
	decryptedSessionKey, err := decryptMessage(privateKeyA, string(responseFromKDC.SessionKey))
	if err != nil {
		log.Fatal("Failed to decrypt session key:", err)
	}
	fmt.Printf("Decrypted Session Key: %s\n", decryptedSessionKey)

	// Decrypt the encrypted information
	decryptedInfoToA, err := decryptMessage(privateKeyA, responseFromKDC.EncryptedInfoToA)
	if err != nil {
		log.Fatal("Failed to decrypt EncryptedInfoToA:", err)
	}
	fmt.Printf("Decrypted Info To A: %s\n", decryptedInfoToA)
	// fmt.Printf("Menerima respon dari KDC: \nSessionKey: %s\nEncryptedInfoToB: %s\n\n", base64.StdEncoding.EncodeToString(responseFromKDC.SessionKey), responseFromKDC.EncryptedInfoToB)
}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}

func decryptMessage(key *rsa.PrivateKey, encrypted string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, key, decoded)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func loadOrGenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	// Try to load existing keys
	privateKey, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		// If loading fails, generate new keys
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal("Failed to generate private key:", err)
		}

		// Save the new keys
		savePrivateKey(privateKeyFile, privateKey)
		savePublicKey(publicKeyFile, &privateKey.PublicKey)
	}

	// Load or generate public key
	publicKey, err := loadPublicKey(publicKeyFile)
	if err != nil {
		log.Fatal("Failed to load public key:", err)
	}

	return privateKey, publicKey
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

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
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

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
