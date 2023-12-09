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

func (k *KDC) RequestSessionKey(req Request, res *Response) error {
	fmt.Printf("Menerima permintaan dari %s: %s || %s || %s\n\n", req.FromID, req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))

	// Check if the sender's ID and nonce are valid (additional checks can be added)
	if req.FromID != "IDA" {
		return fmt.Errorf("invalid sender ID")
	}

	sessionKey := generateSessionKey()
	fmt.Printf("Kunci sesi yang dihasilkan (Ks): %s\n\n", base64.StdEncoding.EncodeToString(sessionKey))

	encryptedSessionKeyToA := encryptMessage(req.Session, base64.StdEncoding.EncodeToString(sessionKey))

	responseToA := Response{
		SessionKey:       []byte(encryptedSessionKeyToA),
		EncryptedInfoToA: encryptMessage(req.Session, fmt.Sprintf("%s || %s || %s || %s", base64.StdEncoding.EncodeToString(sessionKey), req.FromID, req.ToID, base64.StdEncoding.EncodeToString(req.Nonce))),
	}

	fmt.Printf("Menanggapi %s: \nSessionKey: %s\n\nEncryptedInfoToA: %s\n\n", req.FromID, base64.StdEncoding.EncodeToString(responseToA.SessionKey), responseToA.EncryptedInfoToA)

	// Langkah 3: Mengirim respons ke A
	res.SessionKey = responseToA.SessionKey
	res.EncryptedInfoToA = responseToA.EncryptedInfoToA

	return nil
}

// func loadPublicKey(filename string) (*rsa.PublicKey, error) {
// 	file, err := os.ReadFile(filename)
// 	if err != nil {
// 		return nil, err
// 	}

// 	block, _ := pem.Decode(file)
// 	if block == nil {
// 		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
// 	}

// 	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return key, nil
// }

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
