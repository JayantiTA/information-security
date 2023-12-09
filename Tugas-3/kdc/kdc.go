package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"tugas3/utils"
)

const (
	publicKeyAFile = "../keys/public_key_A.pem"
	publicKeyBFile = "../keys/public_key_B.pem"
)

var (
	publicKeyA *rsa.PublicKey
	publicKeyB *rsa.PublicKey
)

type KDC struct {
	MasterPrivateKey *rsa.PrivateKey
}

type Request struct {
	FromID string
	ToID   string
	Nonce  []byte
}

type Response struct {
	EncryptedInfoToA string
	EncryptedInfoToB string
}

func (k *KDC) RequestSessionKey(req Request, res *Response) error {
	fmt.Printf("Menerima permintaan dari %s: %s || %s || %s\n\n", req.FromID, req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))

	// Check if the sender's ID and nonce are valid (additional checks can be added)
	if req.FromID != "IDA" {
		return fmt.Errorf("invalid sender ID")
	}

	sessionKey := generateSessionKey()
	encodedSessionKey := base64.StdEncoding.EncodeToString(sessionKey)
	fmt.Printf("[STEP 2] Kunci sesi yang dihasilkan (Ks): %s\n\n", encodedSessionKey)

	messageToA := fmt.Sprintf("%s || %s || %s || %s", encodedSessionKey, req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))
	messageToB := fmt.Sprintf("%s || %s", encodedSessionKey, req.FromID)

	encryptedInfoToA, err := utils.EncryptMessage(publicKeyA, messageToA)
	if err != nil {
		fmt.Printf("Failed to encrypt message to A: %s\n\n", err)
		return err
	}

	encryptedInfoToB, err := utils.EncryptMessage(publicKeyB, messageToB)
	if err != nil {
		fmt.Printf("Failed to encrypt message to B: %s\n\n", err)
		return err
	}

	responseToA := Response{
		EncryptedInfoToA: encryptedInfoToA,
		EncryptedInfoToB: encryptedInfoToB,
	}

	// Langkah 3: Mengirim respons ke A
	*res = responseToA

	return nil
}

func loadPublicKeys() (*rsa.PublicKey, *rsa.PublicKey) {
	publicKeyA, err := utils.LoadPublicKey(publicKeyAFile)
	if err != nil {
		log.Fatal("Error loading A's public key:", err)
	}

	publicKeyB, err := utils.LoadPublicKey(publicKeyBFile)
	if err != nil {
		log.Fatal("Error loading B's public key:", err)
	}

	return publicKeyA, publicKeyB
}

func main() {
	publicKeyA, publicKeyB = loadPublicKeys()

	kdc := new(KDC)
	kdc.MasterPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	rpc.Register(kdc)

	port := ":1234"

	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatal("Listen error:", err)
	}

	fmt.Printf("Listening on port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Accept error:", err)
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
