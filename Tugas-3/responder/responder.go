package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	privateKeyB, _ := rsa.GenerateKey(rand.Reader, 2048)

	fmt.Println("Responder B menunggu koneksi...")

	// Mensimulasikan menerima kunci sesi terenkripsi dan identifier A dari A
	encryptedInfoFromA := "EncryptedSessionKeyFromA || IDA"
	fmt.Printf("Menerima kunci sesi terenkripsi dan identifier A dari A: %s\n", encryptedInfoFromA)

	// Langkah 4: Mendekripsi informasi yang diterima menggunakan kunci privat B
	decryptedInfo, err := rsa.DecryptPKCS1v15(rand.Reader, privateKeyB, decodeBase64(encryptedInfoFromA))
	if err != nil {
		log.Fatal("Error decrypting information from A:", err)
	}
	fmt.Println("Informasi terdekripsi dari A:", string(decryptedInfo))

}

func decodeBase64(encoded string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal("Error decoding base64:", err)
	}
	return decoded
}
