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
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

var sessionkey []byte

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type Callback struct{}

func (cb *Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

func (cb *Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
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

		// decrypt session key dengan private key server
		decryptedSessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivateKey, getBody, nil)
		check(err)

		sessionkey = decryptedSessionKey

		// cetak ke layar step 2
		fmt.Printf("\n==== Step 2 ====\n")
		fmt.Printf("Session Key encrypted:[%v] \n%v\n", echoPacket.GetLength(), base64.StdEncoding.EncodeToString(echoPacket.GetBody()[1:]))

		// print session key
		fmt.Printf("\nSession key from client: [%v]\n", string(decryptedSessionKey))

		// reply
		paket := echo.NewEchoPacket([]byte("OK1"), false)
		c.AsyncWritePacket(paket, time.Second)

	} else if body[0] == 2 {
		// decrypt secret message
		getBody := echoPacket.GetBody()[1:]
		decryptedMessage := decryptWithSessionKey(getBody, sessionkey)

		// cetak ke layar step 5
		fmt.Printf("\n==== Step 5 ====\n")
		fmt.Printf("OnMessage:[%v] \n%v\n", echoPacket.GetLength(), base64.StdEncoding.EncodeToString(echoPacket.GetBody()[1:]))

		// print secret message
		fmt.Printf("\nSecret message: [%v]\n\n", string(decryptedMessage))

		// reply
		paket := echo.NewEchoPacket([]byte("OK2"), false)
		c.AsyncWritePacket(paket, time.Second)
	}

	return true
}

func (cb *Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

// Fungsi untuk mengekspor kunci publik ke dalam file
func exportPublicKeyToFile(publicKey *rsa.PublicKey, filePath string) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyPEM := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &publicKeyPEM)
	if err != nil {
		return err
	}

	fmt.Println("\nPublic key exported to", filePath)
	return nil
}

// Fungsi untuk mengekspor kunci privat ke dalam file
func exportPrivateKeyToFile(privateKey *rsa.PrivateKey, filePath string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &privateKeyPEM)
	if err != nil {
		return err
	}

	fmt.Println("Private key exported to", filePath)
	return nil
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

// Fungsi untuk mendekripsi pesan dengan kunci sesi
func decryptWithSessionKey(ciphertext, key []byte) []byte {
	decryptedMessage := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		decryptedMessage[i] = ciphertext[i] ^ key[i%len(key)]
	}
	return decryptedMessage
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Generate kunci privat dan kunci publik server
	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating server private key:", err)
		return
	}

	serverPublicKey := &serverPrivateKey.PublicKey

	// Export kunci publik server ke dalam file
	exportPublicKeyToFile(serverPublicKey, "server_public.key")

	// Export kunci privat server ke dalam file
	exportPrivateKeyToFile(serverPrivateKey, "server_private.key")

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
