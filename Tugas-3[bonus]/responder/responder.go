package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"tugas3Bonus/utils"
)

const publicKeyAFile = "../utils/keys/public_key_A.pem"

var publicKeyA *rsa.PublicKey

var sessionKey []byte

type Responder struct {
	MasterPrivateKey *rsa.PrivateKey
}

type Request struct {
	FromID string
	Nonce1 []byte
}

type Response struct {
	EncryptedInfoToA string
}

func (r *Responder) RespondToA(request Request, response *Response) error {
	fmt.Printf("[STEP 2] Menerima permintaan dari Initiator: \nFromID: %s\nNonce1: %s\n\n", request.FromID, base64.StdEncoding.EncodeToString(request.Nonce1))

	if request.FromID != "IDA" {
		log.Fatalf("failed to verify initiator: %s", request.FromID)
	}

	sessionKey = generateSessionKey()
	encodedSessionKey := base64.StdEncoding.EncodeToString(sessionKey)
	request.Nonce1 = transformNonce(request.Nonce1)
	Nonce2 := generateNonce()
	IDB := "IDB"

	// messageToA := fmt.Sprintf("%s || %s", encodedSessionKey, base64.StdEncoding.EncodeToString(request.Nonce1))
	messageToA := fmt.Sprintf("%s || %s || %s || %s || %s", encodedSessionKey, request.FromID, IDB, base64.StdEncoding.EncodeToString(request.Nonce1), base64.StdEncoding.EncodeToString(Nonce2))

	encryptedInfoToA, err := utils.EncryptMessage(publicKeyA, messageToA)
	if err != nil {
		log.Fatalf("failed to encrypt message to A: %s", err)
	}

	responseToA := Response{
		EncryptedInfoToA: encryptedInfoToA,
	}

	*response = responseToA

	fmt.Printf("[STEP 2] Mengirim balasan-enkripsi ke Initiator: \n%s\n\n", responseToA.EncryptedInfoToA)

	fmt.Printf("[STEP 2] Mengirim Data berikut ke Initiator:\n")
	fmt.Printf("Kunci sesi yang dihasilkan (Ks): %s\n", encodedSessionKey)
	fmt.Printf("ID A: %s\n", request.FromID)
	fmt.Printf("ID B: %s\n", IDB)
	fmt.Printf("Nonce1 yang diubah (N1'): %s\n", base64.StdEncoding.EncodeToString(request.Nonce1))
	fmt.Printf("Nonce2 (N2): %s\n\n", base64.StdEncoding.EncodeToString(Nonce2))

	return nil
}

func (r *Responder) ReceiveMessage(message []byte, response *[]byte) error {
	decryptedMessage, err := utils.DecryptAESAndUntransform(message, sessionKey)
	if err != nil {
		log.Fatalf("failed to decrypt message from Initiator: %s", err)
	}

	// fmt.Printf("[STEP 4] Dekripsi pesan dari Initiator: \n%s\n\n", decryptedMessage)
	fmt.Printf("[STEP 4] Menerima Nonce2 dari Initiator: \n")
	fmt.Printf("Data asli Nonce2 yang diterima: %s\n", base64.StdEncoding.EncodeToString(message))
	fmt.Printf("Data Nonce2 setelah proses dekripsi dan untransformasi: %s\n", decryptedMessage)

	// Send the ok message back to the initiator
	encryptedRes, err := utils.EncryptAES("OK pesan initiator diterima", sessionKey)
	if err != nil {
		fmt.Printf("Failed to encrypt response message: %s\n\n", err)
		return err
	}

	*response = encryptedRes

	return nil
}

func loadPublicKeys() *rsa.PublicKey {
	publicKeyA, err := utils.LoadPublicKey(publicKeyAFile)
	if err != nil {
		log.Fatal("Error loading A's public key:", err)
	}

	return publicKeyA
}

func main() {
	publicKeyA = loadPublicKeys()

	responder := new(Responder)
	responder.MasterPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	rpc.Register(responder)

	port := ":1234"

	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatal("Listen error:", err)
	}

	fmt.Printf("Listening on port %s\n\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("failed to accept connection: %s", err)
		}

		clientAddr := conn.RemoteAddr()
		fmt.Printf("Accepted connection from %s\n\n", clientAddr)

		go rpc.ServeConn(conn)
	}
}

func generateSessionKey() []byte {
	sessionKey := make([]byte, 16)
	rand.Read(sessionKey)
	return sessionKey
}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}

func transformNonce(nonce []byte) []byte {
	// Invert each byte back to the original value
	for i := range nonce {
		nonce[i] = ^nonce[i]
	}
	return nonce
}
