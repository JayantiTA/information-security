package main

import (
	"crypto/rand"
	"crypto/rsa"
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
	SessionKey []byte
	EncryptedInfoToB string
}

func main() {
	privateKeyA, _ := rsa.GenerateKey(rand.Reader, 2048)

	fmt.Println("Initiator A memulai koneksi...")

	client, err := rpc.Dial("tcp", "127.0.0.1:1234")
	if err != nil {
		log.Fatal("Dialing:", err)
	}

	// Langkah 1: Mengirim permintaan ke KDC untuk kunci sesi
	requestToKDC := KDCRequest{
		FromID:  "IDA",
		ToID:    "IDB",
		Nonce:   generateNonce(),
		Session: &privateKeyA.PublicKey,
	}
	fmt.Printf("Mengirim permintaan ke KDC: %+v\n", requestToKDC)

	// Mengirim permintaan ke KDC
	var responseFromKDC KDCResponse
	err = client.Call("KDC.RequestSessionKey", requestToKDC, &responseFromKDC)
	if err != nil {
		log.Fatal("KDC error:", err)
	}

	// Langkah 2: Mendekripsi respons dari KDC
	fmt.Printf("Respons terdekripsi dari KDC: %+v\n", responseFromKDC)

	// Ekstrak kunci sesi, IDA, dan meneruskan ke B
	fmt.Printf("Meneruskan kunci sesi terenkripsi dan identifikasi A ke B: %+v\n", responseFromKDC)
}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}
