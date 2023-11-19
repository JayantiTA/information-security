package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net"
	"os"
	"time"

	"github.com/JayantiTA/information-security/bonus/utils"
)

var clientPrivateKey *rsa.PrivateKey
var clientPublicKey *rsa.PublicKey

const (
	authSuccess = "Authentication successful!"
)

func init() {
	// Generate client's public and private keys if they don't exist
	// Read client's public and private keys if they exist
	if _, err := os.Stat("./client_public.pem"); os.IsNotExist(err) {
		clientPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Error generating client private key: %s", err)
		}

		err = utils.SavePrivateKeyToFile(clientPrivateKey, "./client_private.pem")
		if err != nil {
			log.Fatalf("Error exporting private key: %s", err)
		}

		clientPublicKey = &clientPrivateKey.PublicKey
		err = utils.SavePublicKeyToFile(clientPublicKey, "./client_public.pem")
		if err != nil {
			log.Fatalf("Error exporting public key: %s", err)
		}
	} else {
		log.Printf("Read client key from file.")
		clientPrivateKey, err = utils.ReadPrivateKeyFromFile("./client_private.pem")
		if err != nil {
			log.Fatalf("Error reading client private key: %s", err)
		}

		clientPublicKey, err = utils.ReadPublicKeyFromFile("./client_public.pem")
		if err != nil {
			log.Fatalf("Error reading client public key: %s", err)
		}
	}
}

func exchangeKeys(conn net.Conn) (*rsa.PublicKey, error) {
	// Receive server's public key
	serverPublicKey, err := utils.ReceivePublicKey(conn)
	if err != nil {
		log.Printf("Error receiving server's public key: %s", err)
		return nil, err
	}

	// Export server's public key to file
	err = utils.SavePublicKeyToFile(serverPublicKey, "./server_public.pem")
	if err != nil {
		log.Printf("Error exporting server's public key: %s", err)
		return nil, err
	}

	// Send client's public key to the server
	err = utils.SendPublicKey(conn, clientPublicKey)
	if err != nil {
		log.Printf("Error sending client's public key: %s", err)
		return nil, err
	}

	return serverPublicKey, nil
}

func encryptAndSign(message string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (string, error) {
	// Encrypt the message with AES
	encryptedMessage, err := utils.EncryptToBase64String(message, publicKey)
	if err != nil {
		log.Printf("Error encrypting message: %s", err)
		return "", err
	}

	// Sign the encrypted message with the private key
	signature, err := utils.Sign(encryptedMessage, privateKey)
	if err != nil {
		log.Printf("Error signing message: %s", err)
		return "", err
	}

	// Combine the encrypted message and signature
	return encryptedMessage + "|" + signature, nil
}

func authenticateServer(conn net.Conn, serverPublicKey *rsa.PublicKey) bool {
	// Receive the challenge from the server
	challenge, err := utils.ReceiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving challenge: %s", err)
		return false
	}

	// Decrypt the challenge and print it
	decryptedChallenge, err := utils.Decrypt(challenge, clientPrivateKey)
	if err != nil {
		log.Printf("Error decrypting challenge: %s", err)
		return false
	}
	log.Printf("Received challenge: %s", decryptedChallenge)

	// Sign the challenge and send the response to the server
	response, err := encryptAndSign(authSuccess, serverPublicKey, clientPrivateKey)
	if err != nil {
		log.Printf("Error encrypting and signing message: %s", err)
		return false
	}

	// Send the response to the server
	_, err = conn.Write([]byte(response))
	if err != nil {
		log.Printf("Error sending response: %s", err)
		return false
	}

	return true
}

func exchangeMessage(conn net.Conn, serverPublicKey *rsa.PublicKey) error {
	sessionKey := "random session key from group 1"

	// // Encrypt the session key with the server's public key
	encryptedSessionKey, err := utils.Encrypt(sessionKey, serverPublicKey)
	if err != nil {
		log.Printf("Error encrypting session key: %s", err)
		return err
	}

	// Send the encrypted message to the server
	_, err = conn.Write(encryptedSessionKey)
	if err != nil {
		log.Printf("Error sending session key: %s", err)
		return err
	}
	log.Printf("Sent session key: %s", sessionKey)

	// Pause for 1 second to simulate delay
	time.Sleep(1 * time.Second)

	serverResponse, err := utils.ReceiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving server response: %s", err)
		return err
	}

	// Decrypt the server response
	decryptedServerResponse := utils.DecryptWithSessionKey(serverResponse, []byte(sessionKey))
	if err != nil {
		log.Printf("Error decrypting server response: %s", err)
		return err
	}
	log.Printf("Received server response: %s", decryptedServerResponse)

	// Encrypt and send a message to the server
	message := "Hello, Server! This is a secret message."
	ciphertextWithSessionKey := utils.EncryptWithSessionKey([]byte(message), []byte(sessionKey))

	// Send the encrypted message to the server
	_, err = conn.Write([]byte(ciphertextWithSessionKey))
	if err != nil {
		log.Printf("Error sending message with session key: %s", err)
		return err
	}

	log.Printf("Sent encrypted message: %s", message)
	return nil
}

func main() {
	serverAddr := "localhost:8888"

	var serverPublicKey *rsa.PublicKey

	// Connect to the server
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Error connecting to server: %s", err)
	}
	defer conn.Close()

	// STEP 1: Exchange public keys if the client has not been authenticated
	if _, err := os.Stat("./server_public.pem"); os.IsNotExist(err) {
		serverPublicKey, err = exchangeKeys(conn)
		if err != nil {
			log.Fatalf("Error exchanging public keys: %s", err)
		}
	} else {
		serverPublicKey, err = utils.ReadPublicKeyFromFile("./server_public.pem")
		if err != nil {
			log.Fatalf("Error reading server public key: %s", err)
		}
	}

	// STEP 2: Authenticate with the server
	if !authenticateServer(conn, serverPublicKey) {
		log.Fatalf("Server authentication failed.")
	}

	// STEP 3: Exchange messages with the server
	err = exchangeMessage(conn, serverPublicKey)
	if err != nil {
		log.Fatalf("Error exchanging message: %s", err)
	}
}
