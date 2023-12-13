package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/rpc"
	"strings"
	"tugas3Bonus/utils"
)

const (
	privateKeyAFile = "private_key_A.pem"
)

var sessionKey []byte

type BRequest struct {
	FromID string
	Nonce1 []byte
}

type BResponse struct {
	EncryptedInfoToA string
}

func main() {
	privateKeyA, err := utils.LoadPrivateKey(privateKeyAFile)
	if err != nil {
		log.Fatalf("failed to load A's private key: %s", err)
	}

	responderAddress := "127.0.0.1:1234"

	client, err := rpc.Dial("tcp", responderAddress)
	if err != nil {
		log.Fatalf("failed to dial responder: %s", err)
	}
	defer client.Close()

	fmt.Printf("Connected to responder at %s\n\n", responderAddress)

	requestToB := BRequest{
		FromID: "IDA",
		Nonce1: generateNonce(),
	}
	fmt.Printf("[STEP 1] Mengirim permintaan ke Responder: \nFromID: %s\nNonce1: %s\n\n", requestToB.FromID, base64.StdEncoding.EncodeToString(requestToB.Nonce1))

	var responseFromB BResponse
	err = client.Call("Responder.RespondToA", requestToB, &responseFromB)
	if err != nil {
		log.Fatalf("failed to call responder: %s", err)
	}

	decryptedInfoFromB, err := utils.DecryptMessage(privateKeyA, responseFromB.EncryptedInfoToA)
	if err != nil {
		log.Fatalf("failed to decrypt info from B: %s", err)
	}
	components := strings.Split(decryptedInfoFromB, " || ")
	sessionKey, err = base64.StdEncoding.DecodeString(components[0])
	if err != nil {
		log.Fatalf("failed to decode session key: %s", err)
	}

	// fmt.Printf("[STEP 3] Menerima respon dari Responder: \nEncryptedInfoToA: %s\n\n", decryptedInfoFromB)
	fmt.Printf("[STEP 3] Menerima respon dari Responder: \n")
	fmt.Printf("Kunci sesi yang dihasilkan (Ks): %s\n", base64.StdEncoding.EncodeToString(sessionKey))
	fmt.Printf("ID A: %s\n", components[1])
	fmt.Printf("ID B: %s\n", components[2])
	fmt.Printf("Nonce1: %s\n", components[3])
	fmt.Printf("Nonce2: %s\n\n", components[4])

	// fmt.Printf("[STEP 3] Menerima respon dari Responder: \nEncryptedInfoToA: %s\n\n", responseFromB.EncryptedInfoFromB)
	encryptedMessageToB, err := utils.EncryptAESAndTransform(components[4], sessionKey)
	if err != nil {
		log.Fatalf("Failed to encrypt message to B: %s", err)
	}
	fmt.Printf("[STEP 3] Mengirim Nonce2 yang sudah ditransformasi dan terenkripsi dengan Ks ke Responder: \n%s\n\n", base64.StdEncoding.EncodeToString(encryptedMessageToB))

	var responseFromB2 []byte
	err = client.Call("Responder.ReceiveMessage", encryptedMessageToB, &responseFromB2)
	if err != nil {
		log.Fatalf("failed to call responder: %s", err)
	}

}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}
