package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/gansidui/gotcp/examples/echo"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// Fungsi untuk membaca kunci publik dari file
func readPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	publicKeyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key in %s", filePath)
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey.(*rsa.PublicKey), nil
}

// Fungsi untuk mengenkripsi pesan dengan kunci sesi
func encryptWithSessionKey(plaintext, key []byte) []byte {
	encryptedMessage := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		encryptedMessage[i] = plaintext[i] ^ key[i%len(key)]
	}
	return encryptedMessage
}

func main() {
	// Membaca kunci publik server dari file
	serverPublicKey, err := readPublicKeyFromFile("../server/server_public.key")
	if err != nil {
		fmt.Println("Error reading server public key:", err)
		return
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)

	echoProtocol := &echo.EchoProtocol{}

	sessionkey := []byte("client_session_key_1818")
	message := []byte{1}

	// encrypt session key
	encryptedSessionKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, serverPublicKey, []byte(sessionkey), nil)
	if err != nil {
		fmt.Println("Error encrypting session key:", err)
		return
	}
	message = append(message, encryptedSessionKey...)

	// cetak ke layar step 1
	fmt.Printf("\n==== Step 1 ====\n")
	fmt.Println("Client: kirim pesan ke server, berisikan session key yang sudah dienkrip dengan server_public.key")
	fmt.Printf("Ciphertext:\n%v\n", base64.StdEncoding.EncodeToString(encryptedSessionKey))

	// handshake 1
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err := echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		// cetak ke layar step 3
		fmt.Printf("\n==== Step 3 ====\n")
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	// =====================================================
	secretmsg := []byte("Hello, Server! Apa kabar?")
	message = []byte{2}

	// encrypt secret message with session key
	encryptedMessage := encryptWithSessionKey([]byte(secretmsg), []byte(sessionkey))
	message = append(message, encryptedMessage...)

	// cetak ke layar step 4
	fmt.Printf("\n==== Step 4 ====\n")
	fmt.Println("Client: Mengirim pesan yang dienkripsi dengan kunci sesi...")
	fmt.Printf("Encrypted Message:\n%v\n", base64.StdEncoding.EncodeToString(encryptedMessage))

	// handshake 2
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err = echoProtocol.ReadPacket(conn)
	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		// cetak ke layar step 6
		fmt.Printf("\n==== Step 6 ====\n")
		fmt.Printf("Server reply:[%v] [%v]\n\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	conn.Close()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
