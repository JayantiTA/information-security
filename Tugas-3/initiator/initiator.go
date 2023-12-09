package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net/rpc"
)

type KDCRequest struct {
	FromID  string
	ToID    string
	Nonce   []byte
	Session *rsa.PublicKey
}

type KDCResponse struct {
	SessionKey       []byte
	EncryptedInfoToB string
}

func main() {
	privateKeyA, _ := rsa.GenerateKey(rand.Reader, 2048)

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
		Session: &privateKeyA.PublicKey,
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
	// fmt.Printf("Respons terdekripsi dari KDC: %+v\n\n", responseFromKDC)
	fmt.Printf("Menerima respon dari KDC: \nSessionKey: %s\nEncryptedInfoToB: %s\n\n", base64.StdEncoding.EncodeToString(responseFromKDC.SessionKey), responseFromKDC.EncryptedInfoToB)

	// Ekstrak kunci sesi, IDA, dan meneruskan ke B
	// fmt.Printf("Meneruskan kunci sesi terenkripsi dan identifikasi A ke B: \nSessionKey: %s\n, EncryptedInfoToB: %s\n\n", base64.StdEncoding.EncodeToString(responseFromKDC.SessionKey), responseFromKDC.EncryptedInfoToB)
}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}
