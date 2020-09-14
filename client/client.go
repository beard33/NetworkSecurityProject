package main

import (
	"crypto"
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
const NAME = "alice@studenti.unipr.it"

func main() {

	var PubVal, sharedKey, ReceivedVal = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	var sndBuf, toBeVerified, serverPlaintext, serverCiphertext []byte
	var keyLen, signLen, aesLen int
	plaintext := []byte(NAME)
	aesKey := make([]byte, 16)
	aesIV := make([]byte, 16)
	rcvBuf := make([]byte, 512)
	k := dh.Key{P: big.NewInt(0), X: big.NewInt(0), G: big.NewInt(0)}
	byteVal := make([]byte, 128)

	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	k.GenerateKey()
	serverKey := importPubKey("pubkey.pem")
	// pubRes = g^(x_c) mod p
	PubVal.Exp(k.G, k.X, k.P)

	fmt.Println(LINE)
	fmt.Println("The modulus is\n", k.P)
	fmt.Println(LINE)
	fmt.Println("The generator is\n", k.G)
	fmt.Println(LINE)
	fmt.Println("Public exp is\n", PubVal)
	fmt.Println(LINE)

	// Create the buf to be sent
	sndBuf = append(sndBuf, byte(len(PubVal.Bytes())))
	sndBuf = append(sndBuf, PubVal.Bytes()...)

	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		log.Fatal(err)
	}

	_, err = c.Write(sndBuf)
	if err != nil {
		log.Fatal(err)
	}
	sndBuf = nil

	// Receive server public exponential, signature and AES
	_, err = c.Read(rcvBuf)
	if err != nil {
		log.Fatal(err)
	}
	keyLen = (int(rcvBuf[0]))
	byteVal = rcvBuf[1 : keyLen+1]
	ReceivedVal.SetBytes(byteVal)

	// Calculate the shared key
	// (g^(x_s))^(x_c)
	sharedKey.Exp(ReceivedVal, k.X, k.P)
	fmt.Println("shared key:\n", sharedKey)
	fmt.Println(LINE)

	// Verify the RSA signature
	signLen = int(rcvBuf[keyLen+1])
	signature := rcvBuf[keyLen+2 : keyLen+2+signLen]
	toBeVerified = append(toBeVerified, PubVal.Bytes()...)
	toBeVerified = append(toBeVerified, ReceivedVal.Bytes()...)
	hashed := sha256.Sum256(toBeVerified)

	err = rsa.VerifyPKCS1v15(serverKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		log.Fatal("ERROR in signature:", err)
	} else {
		fmt.Println("SERVER SIGNATURE VERIFIED")
		fmt.Println(LINE)
	}

	// Decrypt the server AES
	aesKey = sharedKey.Bytes()[len(sharedKey.Bytes())-16:]
	aesLen = int(rcvBuf[keyLen+signLen+2])
	serverCiphertext = rcvBuf[keyLen+signLen+3 : keyLen+signLen+3+aesLen]
	serverPlaintext, _ = aesUtils.Decrypt(aesKey, aesIV, serverCiphertext)
	fmt.Println("Server ID: ", string(serverPlaintext))

	// Encrypt client ID
	ciphertext, err := aesUtils.Encrypt(aesKey, aesIV, plaintext)
	sndBuf = append(sndBuf, byte(len(ciphertext)))
	sndBuf = append(sndBuf, ciphertext...)
	_, err = c.Write(sndBuf)
	if err != nil {
		log.Fatal(err)
	}

}
