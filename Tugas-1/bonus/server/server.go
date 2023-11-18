package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/JayantiTA/information-security/bonus/utils"
)

var serverPrivateKey *rsa.PrivateKey

const (
	authSuccess   = "Authentication successful!"
	authChallenge = "Authentication challenge: prove your identity"
)

func init() {
	var err error
	serverPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating server private key: %s", err)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	// Exchange public keys
	clientPublicKey, err := exchangeKeys(conn)
	if err != nil {
		log.Fatalf("Error exchanging public keys: %s", err)
	}

	// Authenticate the client
	if !authenticateClient(conn, clientPublicKey) {
		log.Fatalf("Client authentication failed.")
	}

	err = exchangeMessage(conn)
	if err != nil {
		log.Fatalf("Error exchanging message: %s", err)
	}
}

func exchangeKeys(conn net.Conn) (*rsa.PublicKey, error) {
	// Marshal server's public key to the client
	serverPublicKey := &serverPrivateKey.PublicKey
	err := utils.SendPublicKey(conn, serverPublicKey)
	if err != nil {
		log.Printf("Error sending server's public key: %s", err)
		return nil, err
	}

	// Receive client's public key
	clientPublicKey, err := utils.ReceivePublicKey(conn)
	if err != nil {
		log.Printf("Error receiving client's public key: %s", err)
		return nil, err
	}

	return clientPublicKey, nil
}

func authenticateClient(conn net.Conn, clientPublicKey *rsa.PublicKey) bool {
	// Send a challenge message to the client
	encryptedChallenge, err := utils.Encrypt(authChallenge, clientPublicKey)
	if err != nil {
		log.Printf("Error encrypting challenge: %s", err)
		return false
	}

	// Send the encrypted challenge to the client
	_, err = conn.Write([]byte(encryptedChallenge))
	if err != nil {
		log.Printf("Error sending challenge: %s", err)
		return false
	}

	// Receive the response from the client and verify
	response, err := utils.ReceiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving response: %s", err)
		return false
	}

	// Decrypt and verify the response
	decryptedResponse, err := decryptAndVerify(string(response), clientPublicKey, serverPrivateKey)
	if err != nil {
		log.Printf("Error decrypting response: %s", err)
		return false
	}

	log.Printf("Received auth client response: %s", decryptedResponse)
	return decryptedResponse == authSuccess
}

func decryptAndVerify(ciphertextWithSignature string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (string, error) {
	// Separate the ciphertext and signature
	parts := strings.Split(ciphertextWithSignature, "|")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid ciphertext with signature")
	}
	encryptedMessageBase64, signatureBase64 := parts[0], parts[1]

	// Verify the signature
	err := utils.Verify(encryptedMessageBase64, signatureBase64, publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to verify signature")
	}

	// Decrypt the message
	decodedMessage, err := utils.DecryptFromBase64String(encryptedMessageBase64, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message")
	}

	return string(decodedMessage), nil
}

func exchangeMessage(conn net.Conn) error {
	// Receive and decrypt the session key from the client
	sessionKey, err := utils.ReceiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving message: %s", err)
		return err
	}

	// Decrypt the session key
	decryptedSessionKey, err := utils.Decrypt(sessionKey, serverPrivateKey)
	if err != nil {
		log.Printf("Error decrypting message: %s", err)
		return err
	}

	// Receive and decrypt the message from the client
	encryptedMessage, err := utils.ReceiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving message: %s", err)
		return err
	}

	// Decrypt the message
	decryptedMessage := utils.DecryptWithSessionKey(encryptedMessage, []byte(decryptedSessionKey))
	log.Printf("Received and decrypted message: %s", string(decryptedMessage))

	return nil
}

func main() {
	listener, _ := net.Listen("tcp", ":8080")
	defer listener.Close()

	log.Println("Server is listening on port 8080")

	for {
		conn, _ := listener.Accept()
		go handleClient(conn)
	}
}
