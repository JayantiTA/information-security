package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/JayantiTA/information-security/bonus/utils"
)

var serverPrivateKey *rsa.PrivateKey
var serverPublicKey *rsa.PublicKey

const (
	authSuccess   = "Authentication successful!"
	authChallenge = "Authentication challenge: prove your identity"
)

func init() {
	// Generate server's public and private keys if they don't exist
	// Read server's public and private keys if they exist
	if _, err := os.Stat("./server_private.pem"); os.IsNotExist(err) {
		serverPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Error generating server private key: %s", err)
		}

		err = utils.SavePrivateKeyToFile(serverPrivateKey, "./server_private.pem")
		if err != nil {
			log.Fatalf("Error exporting private key: %s", err)
		}

		serverPublicKey = &serverPrivateKey.PublicKey
		err = utils.SavePublicKeyToFile(serverPublicKey, "./server_public.pem")
		if err != nil {
			log.Fatalf("Error exporting public key: %s", err)
		}
	} else {
		log.Printf("Read server key from file.")
		serverPrivateKey, err = utils.ReadPrivateKeyFromFile("./server_private.pem")
		if err != nil {
			log.Fatalf("Error reading server private key: %s", err)
		}

		serverPublicKey, err = utils.ReadPublicKeyFromFile("./server_public.pem")
		if err != nil {
			log.Fatalf("Error reading server public key: %s", err)
		}
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	var clientPublicKey *rsa.PublicKey

	// STEP 1: Exchange public keys if the client has not been authenticated
	if _, err := os.Stat("./client_public.pem"); os.IsNotExist(err) {
		log.Printf("Client public key does not exist. Exchanging public keys...")
		clientPublicKey, err = exchangeKeys(conn)
		if err != nil {
			log.Fatalf("Error exchanging public keys: %s", err)
		}
	} else {
		log.Printf("Read client key from file.")
		clientPublicKey, err = utils.ReadPublicKeyFromFile("./client_public.pem")
		if err != nil {
			log.Fatalf("Error reading client public key: %s", err)
		}
	}

	// STEP 2: Authenticate the client
	if !authenticateClient(conn, clientPublicKey) {
		log.Fatalf("Client authentication failed.")
	}

	// STEP 3: Exchange message
	err := exchangeMessage(conn)
	if err != nil {
		log.Fatalf("Error exchanging message: %s", err)
	}
}

func exchangeKeys(conn net.Conn) (*rsa.PublicKey, error) {
	// Marshal server's public key to the client
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

	// Export client's public key to file
	err = utils.SavePublicKeyToFile(clientPublicKey, "./client_public.pem")
	if err != nil {
		log.Printf("Error exporting client public key: %s", err)
		return nil, err
	}

	return clientPublicKey, nil
}

func authenticateClient(conn net.Conn, clientPublicKey *rsa.PublicKey) bool {
	log.Printf("Authenticating client...")
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
	log.Printf("Received and decrypted session key: %s", string(decryptedSessionKey))

	// Encrypt and send the message to the client
	message := "Hello from server!"
	encryptedMessage := utils.EncryptWithSessionKey([]byte(message), []byte(decryptedSessionKey))
	_, err = conn.Write(encryptedMessage)
	if err != nil {
		log.Printf("Error sending message: %s", err)
		return err
	}
	log.Printf("Sent encrypted message: %s", string(encryptedMessage))

	// Receive and decrypt the message from the client
	encryptedMessage, err = utils.ReceiveMessage(conn)
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
	// ========= START SERVER =========
	listener, _ := net.Listen("tcp", ":8888")
	defer listener.Close()

	log.Printf("Server is listening on port 8888")

	for {
		conn, _ := listener.Accept()
		log.Printf("Client connected from %s", conn.RemoteAddr().String())
		go handleClient(conn)
	}
}
