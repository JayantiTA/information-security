package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func DecryptAES(ciphertext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a buffer to hold the decrypted plaintext
	plaintext := make([]byte, len(ciphertext))

	// Decrypt each block separately in ECB mode
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:], ciphertext[i:])
	}

	// Remove PKCS7 padding
	plaintext, err = unpad(plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func DecryptAESAndUntransform(ciphertext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Ensure the ciphertext length is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length must be a multiple of the block size")
	}

	// Create a buffer to hold the decrypted plaintext
	decrypted := make([]byte, len(ciphertext))

	// Decrypt each block separately in ECB mode
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(decrypted[i:], ciphertext[i:])
	}

	decrypted, err = unpad(decrypted)
	if err != nil {
		return "", err
	}

	// Apply the custom untransformation to the decrypted plaintext
	originalPlaintext := transformNonce(decrypted)

	return string(originalPlaintext), nil
}

func DecryptMessage(key *rsa.PrivateKey, encrypted string) (string, error) {
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

func EncryptAES(plaintext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad the plaintext to be a multiple of the block size
	plaintextBytes := []byte(plaintext)
	paddedPlaintext := pad(plaintextBytes, aes.BlockSize)

	// Create a buffer to hold the ciphertext
	ciphertext := make([]byte, len(paddedPlaintext))

	// Encrypt each block separately in ECB mode
	for i := 0; i < len(paddedPlaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:], paddedPlaintext[i:])
	}

	return ciphertext, nil
}

func EncryptAESAndTransform(plaintext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintextBytes := []byte(plaintext)

	// Apply the custom transformation to the plaintext
	transformedPlaintext := transformNonce(plaintextBytes)
	paddedPlaintext := pad(transformedPlaintext, aes.BlockSize)

	// Ensure the transformed plaintext length is a multiple of the block size
	if len(paddedPlaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("transformed plaintext length must be a multiple of the block size")
	}

	// Create a buffer to hold the ciphertext
	ciphertext := make([]byte, len(paddedPlaintext))

	// Encrypt each block separately in ECB mode
	for i := 0; i < len(paddedPlaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:], paddedPlaintext[i:])
	}

	return ciphertext, nil
}

func EncryptMessage(key *rsa.PublicKey, message string) (string, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(message))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
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

func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
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

// pad adds PKCS7 padding to the given data.
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func transformNonce(nonce []byte) []byte {
	// Invert each byte back to the original value
	for i := range nonce {
		nonce[i] = ^nonce[i]
	}
	return nonce
}

// unpad removes PKCS7 padding from the given data.
func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	padding := int(data[len(data)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	return data[:len(data)-padding], nil
}
