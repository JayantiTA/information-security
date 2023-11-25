package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"bytes"
	"log"
	"net"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

var serverPrivateKey *rsa.PrivateKey
var clientPublicKey *rsa.PublicKey
var secretKey []byte
var n1 []byte
var n2 []byte

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Callback struct{}

func (this *Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

func (this *Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)
	body := echoPacket.GetBody()

	if body[0] == 1 {
		// Membaca kunci privat server dari file
		serverPrivateKey, err := readPrivateKeyFromFile("server_private.key")
		if err != nil {
			fmt.Println("Error reading server private key:", err)
			return false
		}
		getBody := echoPacket.GetBody()[1:]

		decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, serverPrivateKey, getBody)
		check(err)
		
		fmt.Println("data :", decryptedData)

		n1 = decryptedData[2:]
		n2 = []byte{8, 9, 10, 11, 12, 13, 14, 15}

		decryptedData = append(n1, n2...)

		fmt.Println(decryptedData)

		encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, clientPublicKey, decryptedData)
		
		check(err)
		fmt.Println(encryptedData)

		paket := echo.NewEchoPacket([]byte(encryptedData), false)
		c.AsyncWritePacket(paket, time.Second)
	} else if body[0] == 2 {
		// Membaca kunci privat server dari file
		serverPrivateKey, err := readPrivateKeyFromFile("server_private.key")
		if err != nil {
			fmt.Println("Error reading server private key:", err)
			return false
		}
		getBody := echoPacket.GetBody()[1:]

		decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, serverPrivateKey, getBody)
		check(err)
		
		fmt.Println("data :", decryptedData)

		if !bytes.Equal(decryptedData, n2) {
			c.Close()
			return true
		}

		paket := echo.NewEchoPacket([]byte("OK1"), false)
		c.AsyncWritePacket(paket, time.Second)
	} else if body[0] == 3 {
		// Membaca kunci privat server dari file
		serverPrivateKey, err := readPrivateKeyFromFile("server_private.key")
		if err != nil {
			fmt.Println("Error reading server private key:", err)
			return false
		}
		getBody := echoPacket.GetBody()[1:]

		secretKey, err := rsa.DecryptPKCS1v15(rand.Reader, serverPrivateKey, getBody)
		check(err)

		fmt.Println("Secret Key:", secretKey)

		paket := echo.NewEchoPacket([]byte("OK2"), false)
		c.AsyncWritePacket(paket, time.Second)
	} else if body[0] == 4 {
		getBody := echoPacket.GetBody()[1:]

		hashed := sha256.Sum256(secretKey)
		err := rsa.VerifyPKCS1v15(clientPublicKey, crypto.SHA256, hashed[:], getBody)

		if err != nil {
			fmt.Println("Error when verifying signature")
			c.Close()
			return true
		}

		paket := echo.NewEchoPacket([]byte("OK3"), false)
		c.AsyncWritePacket(paket, time.Second)
	}
	return true
}

func (this *Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
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

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	//privateKey, _ = helper.ImportPrivateKey("Server/key.rsa")
	//clientPubKey, _ = helper.ImportPublicKey("Client/key.rsa.pub")
	
	serverPrivateKey, _ = readPrivateKeyFromFile("server_private.key")
	clientPublicKey, _ = readPublicKeyFromFile("../client/client_public.key")

	// creates a tcp listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	// creates a server
	config := &gotcp.Config{
		PacketSendChanLimit:    20,
		PacketReceiveChanLimit: 20,
	}

	srv := gotcp.NewServer(config, &Callback{}, &echo.EchoProtocol{})

	// starts service
	go srv.Start(listener, time.Second)
	fmt.Println("listening:", listener.Addr())

	// catchs system signal
	chSig := make(chan os.Signal)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal: ", <-chSig)

	// stops service
	srv.Stop()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
