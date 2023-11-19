package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
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

func ReadPrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		log.Printf("Error parsing PEM block containing the private key in %s", filePath)
		return nil, fmt.Errorf("failed to parse PEM block containing the private key in %s", filePath)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("Error parsing private key: %s", err)
		return nil, err
	}

	return privateKey, nil
}

func ReadPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	publicKeyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		log.Printf("Error parsing PEM block containing the public key in %s", filePath)
		return nil, fmt.Errorf("failed to parse PEM block containing the public key in %s", filePath)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("Error parsing public key: %s", err)
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
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

func SavePrivateKeyToFile(privateKey *rsa.PrivateKey, filePath string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(filePath)
	if err != nil {
		log.Printf("Error creating file: %s", err)
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &privateKeyPEM)
	if err != nil {
		log.Printf("Error encoding private key: %s", err)
		return err
	}

	log.Printf("Private key exported to %s", filePath)
	return nil
}

func SavePublicKeyToFile(publicKey *rsa.PublicKey, filePath string) error {
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
		log.Printf("Error creating file: %s", err)
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &publicKeyPEM)
	if err != nil {
		log.Printf("Error encoding public key: %s", err)
		return err
	}

	log.Printf("Public key exported to %s", filePath)
	return nil
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
