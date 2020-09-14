package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"net"
	"netsecProject/utils/AES/aesUtils"
	"netsecProject/utils/DH/dh"
	"os"
)

const LINE = "----------------------------"
const NAME = "netsec.project.it"

func main() {

	k := dh.Key{P: big.NewInt(0), X: big.NewInt(0), G: big.NewInt(0)}
	var PubVal, sharedKey, ReceivedVal = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	var keyLen, signLen, aesLen int
	var sndBuf, toBeSigned, clientPlaintext, clientCiphertext []byte
	plaintext := []byte(NAME)
	aesKey := make([]byte, 16)
	aesIV := make([]byte, 16)
	rcvBuf := make([]byte, 512)
	byteVal := make([]byte, 128)

	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide port number")
		return
	}

	PORT := ":" + arguments[1]
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	rsaKey := importKey("privkey.pem")
	for {
		fmt.Println("WAITING FOR A CLIENT...")

		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		// pubRes = g^(x_s) mod p
		// New exponential generated at every connection
		k.GenerateKey()
		PubVal.Exp(k.G, k.X, k.P)
		fmt.Println(LINE)
		fmt.Println("The modulus is\n", k.P)
		fmt.Println(LINE)
		fmt.Println("The generator is\n", k.G)
		fmt.Println(LINE)
		fmt.Println("Public exp is\n", PubVal)
		fmt.Println(LINE)

		_, err = c.Read(rcvBuf)
		if err != nil {
			log.Fatal(err)
		}
		keyLen = (int(rcvBuf[0]))
		byteVal = rcvBuf[1 : keyLen+1]
		ReceivedVal.SetBytes(byteVal)

		// Calculate the shared key
		// (g^(x_c))^(x_s)
		sharedKey.Exp(ReceivedVal, k.X, k.P)
		fmt.Println("Shared key:\n", sharedKey)
		fmt.Println(LINE)

		// Generate the RSA signature
		toBeSigned = append(toBeSigned, ReceivedVal.Bytes()...)
		toBeSigned = append(toBeSigned, PubVal.Bytes()...)
		hashed := sha256.Sum256(toBeSigned)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
		signLen = len(signature)

		// Encrypt server name with AES-CBC
		aesKey = sharedKey.Bytes()[len(sharedKey.Bytes())-16:]
		ciphertext, err := aesUtils.Encrypt(aesKey, aesIV, plaintext)

		// Generate the byte stream to be sent
		sndBuf = append(sndBuf, byte(len(PubVal.Bytes())))
		sndBuf = append(sndBuf, PubVal.Bytes()...)
		sndBuf = append(sndBuf, byte(signLen))
		sndBuf = append(sndBuf, signature...)
		sndBuf = append(sndBuf, byte(len(ciphertext)))
		sndBuf = append(sndBuf, ciphertext...)

		_, err = c.Write(sndBuf)
		if err != nil {
			log.Fatal(err)
		}

		// Read the client AES
		_, err = c.Read(rcvBuf)
		if err != nil {
			log.Fatal(err)
		}
		aesLen = int(rcvBuf[0])
		clientCiphertext = rcvBuf[1 : 1+aesLen]
		clientPlaintext, _ = aesUtils.Decrypt(aesKey, aesIV, clientCiphertext)
		fmt.Println("Client ID ", string(clientPlaintext))

		// reset the buffers
		sndBuf = nil
		toBeSigned = nil
		continue
	}

}
