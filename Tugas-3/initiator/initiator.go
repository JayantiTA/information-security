package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/rpc"
	"strings"
	"tugas3/utils"
)

const (
	privateKeyAFile = "private_key_A.pem"
)

var sessionKey []byte

type KDCRequest struct {
	FromID string
	ToID   string
	Nonce  []byte
}

type KDCResponse struct {
	EncryptedInfoToA string
	EncryptedInfoToB string
}

func main() {
	privateKeyA, err := utils.LoadPrivateKey(privateKeyAFile)
	if err != nil {
		log.Fatalf("Failed to load A's private key: %s", err)
	}

	kdcAddress := "127.0.0.1:1234"

	client, err := rpc.Dial("tcp", kdcAddress)
	if err != nil {
		log.Fatalf("Dialing: %s", err)
	}
	fmt.Printf("Initiator connected to server at %s\n\n", kdcAddress)

	// Langkah 1: Mengirim permintaan ke KDC untuk kunci sesi
	requestToKDC := KDCRequest{
		FromID: "IDA",
		ToID:   "IDB",
		Nonce:  generateNonce(),
	}
	fmt.Printf("[STEP 1] Mengirim permintaan ke KDC: \nFromID: %s\nToID: %s\nNonce: %s\n\n", requestToKDC.FromID, requestToKDC.ToID, base64.StdEncoding.EncodeToString(requestToKDC.Nonce))

	// Mengirim permintaan ke KDC
	var responseFromKDC KDCResponse
	err = client.Call("KDC.RequestSessionKey", requestToKDC, &responseFromKDC)
	if err != nil {
		log.Fatalf("KDC error: %s", err)
	}

	client.Close()

	// Langkah 2: Mendekripsi respons dari KDC

	// Decrypt the encrypted information
	decryptedInfoToA, err := utils.DecryptMessage(privateKeyA, responseFromKDC.EncryptedInfoToA)
	if err != nil {
		log.Fatalf("Failed to decrypt EncryptedInfoToA: %s", err)
	}
	sessionKey, err = base64.StdEncoding.DecodeString(strings.Split(decryptedInfoToA, " || ")[0])
	if err != nil {
		log.Fatalf("Failed to decode session key: %s", err)
	}
	fmt.Printf("[STEP 2] Decrypted Info to A: %s\n", decryptedInfoToA)

	// Langkah 3: Mengirim kunci sesi terenkripsi dan identifier A ke B
	responderAddress := "127.0.0.1:1235"

	client, err = rpc.Dial("tcp", responderAddress)
	if err != nil {
		log.Fatalf("Dialing: %s", err)
	}
	fmt.Printf("Initiator connected to responder at %s\n\n", responderAddress)

	// Simulate sending the encrypted session key and A's identifier to B
	encryptedInfoToB := responseFromKDC.EncryptedInfoToB
	fmt.Printf("[STEP 3] Mengirim kunci sesi terenkripsi dan identifier A ke B: %s\n\n", encryptedInfoToB)

	var responseFromB []byte
	err = client.Call("Responder.ReceiveSessionKey", encryptedInfoToB, &responseFromB)
	if err != nil {
		log.Fatalf("Responder error: %s", err)
	}

	decryptedMessageFromB, err := utils.DecryptAES(responseFromB, sessionKey)
	if err != nil {
		log.Fatalf("Failed to decrypt message from B: %s", err)
	}
	fmt.Printf("[STEP 4] Nonce 2 terenkripsi dari B: %s\n\n", decryptedMessageFromB)

	// Langkah 5: Mengirim pesan terenkripsi ke B

	// Simulate sending the encrypted message to B with transformed nonce
	// encryptedMessageToB, err := utils.EncryptAESAndTransform("Hi Responder! I have read your message", sessionKey)
	// if err != nil {
	// 	log.Fatalf("Failed to encrypt message to B: %s", err)
	// }

	// Simulate sending the Nonce 2 transformed and encrypted with session key to B
	encryptedNonce2, err := utils.EncryptAESAndTransform(decryptedMessageFromB, sessionKey)
	if err != nil {
		log.Fatalf("Failed to encrypt nonce 2: %s", err)
	}
	fmt.Printf("[STEP 5] Mengirim Nonce 2 terenkripsi (Ks) yang sudah ditransformasi ke B: %s\n\n", base64.StdEncoding.EncodeToString(encryptedNonce2))

	var responseFromB2 []byte
	err = client.Call("Responder.ReceiveMessage", encryptedNonce2, &responseFromB2)
	if err != nil {
		log.Fatalf("Responder error: %s", err)
	}

	decryptedMessageFromB2, err := utils.DecryptAES(responseFromB2, sessionKey)
	if err != nil {
		log.Fatalf("Failed to decrypt message from B: %s", err)
	}
	fmt.Printf("Pesan terenkripsi dari B: %s\n", decryptedMessageFromB2)
}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}
