package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"fmt"
	"log"
	"net"

	"github.com/gansidui/gotcp/examples/echo"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// Fungsi untuk membaca kunci privat dari file
func readPrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key in %s", filePath)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
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

func GenerateSignature(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("Error to generate signature: %s", err)
	}
	return signature, nil
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)

	echoProtocol := &echo.EchoProtocol{}

	// Membaca kunci private public dari file
	clientPrivateKey, err := readPrivateKeyFromFile("client_private.key")
	if err != nil {
		fmt.Println("Error reading client private key:", err)
		return
	}

	// Membaca kunci publik server dari file
	serverPublicKey, err := readPublicKeyFromFile("../server/server_public.key")
	if err != nil {
		fmt.Println("Error reading server public key:", err)
		return
	}

	message := []byte{1}
	id1 := []byte("alice1")
	n1 := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	data := append(id1, n1...)

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, serverPublicKey, data)

	message = append(message, encryptedData...)

	// cetak ke layar step 1
	fmt.Printf("\n==== Step 1 ====\n")
	fmt.Println("Client: kirim pesan ke server, berisikan id1 yang sudah dienkrip dengan server_public.key")
	fmt.Printf("Ciphertext:\n%v\n", base64.StdEncoding.EncodeToString(encryptedData))
	
	// handshake 1
	conn.Write(echo.NewEchoPacket(message, false).Serialize())
	p, err := echoProtocol.ReadPacket(conn)

	fmt.Println(err)

	n2 := []byte{}

	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		
		decryptedData, _ := rsa.DecryptPKCS1v15(rand.Reader, clientPrivateKey, echoPacket.GetBody())
		fmt.Printf("\n==== Step 3 ====\n")
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), decryptedData)
		n2 = decryptedData[8:]
		fmt.Println("Nonce 2:", n2)
	}

	message = []byte{2}

	encryptedData, _ = rsa.EncryptPKCS1v15(rand.Reader, serverPublicKey, n2)

	message = append(message, encryptedData...)

	// cetak ke layar step 4
	fmt.Printf("\n==== Step 4 ====\n")
	fmt.Println("Client: kirim pesan ke server, berisikan Nonce 2 yang sudah dienkrip dengan server_public.key")
	fmt.Printf("Ciphertext:\n%v\n", base64.StdEncoding.EncodeToString(encryptedData))
	
	// handshake 2
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err = echoProtocol.ReadPacket(conn)

	if err == nil {
		echoPacket := p.(*echo.EchoPacket)

		// cetak ke layar step 6
		fmt.Printf("\n==== Step 6 ====\n")
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	message = []byte{3}
	secretKey := []byte{16, 17, 18, 19, 20, 21, 22, 23}
	encryptedData, _ = rsa.EncryptPKCS1v15(rand.Reader, serverPublicKey, secretKey)

	message = append(message, encryptedData...)

	// cetak ke layar step 7
	fmt.Printf("\n==== Step 7 ====\n")
	fmt.Println("Client: kirim pesan ke server, berisikan secret key yang sudah dienkrip dengan server_public.key")
	fmt.Printf("Ciphertext:\n%v\n", base64.StdEncoding.EncodeToString(encryptedData))
	
	// handshake 3
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err = echoProtocol.ReadPacket(conn)

	if err == nil {
		echoPacket := p.(*echo.EchoPacket)

		// cetak ke layar step 9
		fmt.Printf("\n==== Step 9 ====\n")
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	message = []byte{4}


	signature, err := GenerateSignature(secretKey, clientPrivateKey)

	message = append(message, signature...)

	// cetak ke layar step 10
	fmt.Printf("\n==== Step 1 ====\n")
	fmt.Println("Client: kirim pesan ke server, berisikan signature yang sudah dienkrip dengan client_private.key")
	fmt.Printf("Ciphertext:\n%v\n", base64.StdEncoding.EncodeToString(signature))
	
	// handshake 2
	conn.Write(echo.NewEchoPacket([]byte(message), false).Serialize())
	p, err = echoProtocol.ReadPacket(conn)

	if err == nil {
		echoPacket := p.(*echo.EchoPacket)
		// cetak ke layar step 12
		fmt.Printf("\n==== Step 12 ====\n")
		fmt.Printf("Server reply:[%v] [%v]\n", echoPacket.GetLength(), string(echoPacket.GetBody()))
	}

	conn.Close()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
