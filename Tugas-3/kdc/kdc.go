package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/rpc"
)

type KDC struct {
	MasterPrivateKey *rsa.PrivateKey
}

type Request struct {
	FromID  string
	ToID    string
	Nonce   []byte
	Session *rsa.PublicKey
}

type Response struct {
	SessionKey       []byte
	EncryptedInfoToA string
}

func generateNonceKdc() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
}

func (k *KDC) RequestSessionKey(req Request, res *Response) error {
	fmt.Printf("Menerima permintaan dari %s: %s || %s || %s\n\n", req.FromID, req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))

	// Check if the sender's ID and nonce are valid (additional checks can be added)
	if req.FromID != "IDA" {
		return fmt.Errorf("invalid sender ID")
	}

	nonce := generateNonceKdc()
	fmt.Printf("Nonce yang dihasilkan (N1): %s\n\n", base64.StdEncoding.EncodeToString(nonce))

	sessionKey := generateSessionKey()

	// Langkah 2: Menanggapi A dengan pesan terenkripsi
	encryptedSessionKeyToA := encryptMessage(req.Session, fmt.Sprintf("%s || %s", base64.StdEncoding.EncodeToString(sessionKey), req.FromID))

	responseToA := Response{
		SessionKey:       []byte(encryptedSessionKeyToA),
		EncryptedInfoToA: encryptMessage(req.Session, fmt.Sprintf("%s || %s || %s || %s", base64.StdEncoding.EncodeToString(sessionKey), req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))),
	}

	fmt.Printf("Menanggapi %s: \nSessionKey: %s\nEncryptedInfoToB: %s\n\n", req.FromID, base64.StdEncoding.EncodeToString(responseToA.SessionKey), responseToA.EncryptedInfoToA)

	// Langkah 3: Meneruskan kunci sesi terenkripsi dan identifier A ke B
	res.SessionKey = responseToA.SessionKey
	res.EncryptedInfoToA = encryptMessage(k.MasterPrivateKey.Public().(*rsa.PublicKey), fmt.Sprintf("%s || %s", base64.StdEncoding.EncodeToString(sessionKey), req.FromID))

	return nil
}

func generateSessionKey() []byte {
	sessionKey := make([]byte, 16)
	rand.Read(sessionKey)
	return sessionKey
}

func encryptMessage(key *rsa.PublicKey, message string) string {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(message))
	if err != nil {
		log.Fatal("Error encrypting message:", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}

func main() {
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
		fmt.Printf("Accepted connection from %s\n", clientAddr)

		go rpc.ServeConn(conn)
	}
}
