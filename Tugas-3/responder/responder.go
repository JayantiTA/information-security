package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"strings"
	"tugas3/utils"
)

const (
	privateKeyBFile = "private_key_B.pem"
)

var (
	sessionKey  []byte
	privateKeyB *rsa.PrivateKey
)

type Responder struct {
	MasterPrivateKey *rsa.PrivateKey
}

func (r *Responder) ReceiveSessionKey(req string, res *[]byte) error {
	decryptedInfoToB, err := utils.DecryptMessage(privateKeyB, req)
	if err != nil {
		fmt.Printf("Failed to decrypt message from A: %s\n\n", err)
		return err
	}
	fmt.Printf("Menerima pesan dari kdc yang diteruskan oleh A: %s\n\n", decryptedInfoToB)

	// Split the message into its components
	components := strings.Split(decryptedInfoToB, " || ")
	// Check if the sender's ID and nonce are valid (additional checks can be added)
	if components[1] != "IDA" {
		return fmt.Errorf("invalid sender ID")
	}
	sessionKey, err = base64.StdEncoding.DecodeString(components[0])
	if err != nil {
		fmt.Printf("Failed to decode session key: %s\n\n", err)
		return err
	}

	fmt.Printf("[STEP 3] Kunci sesi yang diterima (Ks): %s\n\n", components[0])

	// Send the ok message back to the initiator
	resMessage := "OK1 session key diterima"
	encryptedRes, err := utils.EncryptAES(resMessage, sessionKey)
	if err != nil {
		fmt.Printf("Failed to encrypt response message: %s\n\n", err)
		return err
	}

	fmt.Printf("[STEP 4] Mengirim pesan terenkripsi ke A: %s\n\n", resMessage)
	*res = encryptedRes

	return nil
}

func (r *Responder) ReceiveMessage(req []byte, res *[]byte) error {
	decryptedMessageFromA, err := utils.DecryptAESAndUntransform(req, sessionKey)
	if err != nil {
		fmt.Printf("Failed to decrypt message from A: %s\n\n", err)
		return err
	}

	fmt.Printf("Menerima pesan terenkripsi yang telah diuntransformasi dari A: %s\n\n", string(decryptedMessageFromA))

	// Send the ok message back to the initiator
	encryptedRes, err := utils.EncryptAES("OK2 pesan initiator diterima", sessionKey)
	if err != nil {
		fmt.Printf("Failed to encrypt response message: %s\n\n", err)
		return err
	}

	*res = encryptedRes

	return nil
}

func main() {
	var err error
	privateKeyB, err = utils.LoadPrivateKey(privateKeyBFile)
	if err != nil {
		log.Fatalf("Failed to load B's private key: %s", err)
	}

	responder := new(Responder)
	responder.MasterPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	rpc.Register(responder)

	port := ":1235"

	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Listen error: %s", err)
	}

	fmt.Printf("Listening on port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("Accept error: %s", err)
		}

		clientAddr := conn.RemoteAddr()
		fmt.Printf("Accepted connection from %s\n\n", clientAddr)

		go rpc.ServeConn(conn)
	}
}
