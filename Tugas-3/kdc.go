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
	SessionKey []byte
	EncryptedInfoToB string
}

func (k *KDC) RequestSessionKey(req Request, res *Response) error {
	fmt.Printf("Menerima permintaan dari %s: %s || %s || %s\n", req.FromID, req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))

	nonce := generateNonce()
	fmt.Printf("Nonce yang dihasilkan (N1): %s\n", base64.StdEncoding.EncodeToString(nonce))

	sessionKey := generateSessionKey()

	// Langkah 2: Menanggapi A dengan pesan terenkripsi
	responseToA := Response{
		SessionKey: sessionKey,
		EncryptedInfoToB: encryptMessage(k.MasterPrivateKey.Public().(*rsa.PublicKey), fmt.Sprintf("%s || %s", base64.StdEncoding.EncodeToString(sessionKey), req.FromID)),
	}

	fmt.Printf("Menanggapi %s: %+v\n", req.FromID, responseToA)

	// Langkah 3: Meneruskan kunci sesi terenkripsi dan identifier A ke B
	res.SessionKey = sessionKey
	res.EncryptedInfoToB = encryptMessage(k.MasterPrivateKey.Public().(*rsa.PublicKey), fmt.Sprintf("%s || %s", base64.StdEncoding.EncodeToString(sessionKey), req.FromID))

	return nil
}

func generateNonce() []byte {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	return nonce
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

	listener, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal("Listen error:", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Accept error:", err)
		}
		go rpc.ServeConn(conn)
	}
}
