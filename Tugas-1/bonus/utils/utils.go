package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net"
)

func Decrypt(ciphertextBytes []byte, privateKey *rsa.PrivateKey) (string, error) {
	label := []byte("")
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertextBytes, label)
	if err != nil {
		log.Printf("Error decrypting message: %s", err)
		return "", err
	}

	return string(plaintext), nil
}

func DecryptFromBase64String(ciphertext string, privateKey *rsa.PrivateKey) (string, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		log.Printf("Error decoding message: %s", err)
		return "", err
	}

	plaintext, err := Decrypt(ciphertextBytes, privateKey)
	if err != nil {
		log.Printf("Error decrypting message: %s", err)
		return "", err
	}

	return string(plaintext), nil
}

func DecryptWithSessionKey(ciphertext, key []byte) []byte {
	decryptedMessage := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		decryptedMessage[i] = ciphertext[i] ^ key[i%len(key)]
	}
	return decryptedMessage
}

func Encrypt(plaintext string, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(plaintext), label)
	if err != nil {
		log.Printf("Error encrypting message: %s", err)
		return nil, err
	}

	return ciphertext, nil
}

func EncryptToBase64String(plaintext string, publicKey *rsa.PublicKey) (string, error) {
	ciphertext, err := Encrypt(plaintext, publicKey)
	if err != nil {
		log.Printf("Error encrypting message: %s", err)
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func EncryptWithSessionKey(plaintext, key []byte) []byte {
	encryptedMessage := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		encryptedMessage[i] = plaintext[i] ^ key[i%len(key)]
	}
	return encryptedMessage
}

func ReceiveMessage(conn net.Conn) ([]byte, error) {
	messageBytes := make([]byte, 2048)
	n, err := conn.Read(messageBytes)
	if err != nil {
		log.Printf("Error receiving message: %s", err)
		return nil, err
	}
	return messageBytes[:n], nil
}

func SendPublicKey(conn net.Conn, publicKey *rsa.PublicKey) error {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)

	_, err := conn.Write(publicKeyBytes)
	if err != nil {
		log.Printf("Error sending public key: %s", err)
		return err
	}

	return nil
}

func ReceivePublicKey(conn net.Conn) (*rsa.PublicKey, error) {
	publicKeyBytes, err := ReceiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving public key: %s", err)
		return nil, err
	}

	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err != nil {
		log.Printf("Error parsing public key: %s", err)
		return nil, err
	}

	return publicKey, nil
}

func Sign(message string, privateKey *rsa.PrivateKey) (string, error) {
	// Decode the message from base64
	decodedMessage, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		log.Printf("Error decoding message: %s", err)
		return "", err
	}

	// Sign the message with the private key
	hashed := sha256.Sum256(decodedMessage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Printf("Error signing message: %s", err)
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func Verify(message string, signature string, publicKey *rsa.PublicKey) error {
	// Decode the message from base64
	decodedMessage, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		log.Printf("Error decoding message: %s", err)
		return err
	}

	// Decode the signature from base64
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		log.Printf("Error decoding signature: %s", err)
		return err
	}

	// Verify the signature
	hashed := sha256.Sum256(decodedMessage)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		log.Printf("Error verifying signature: %s", err)
		return err
	}

	return nil
}
