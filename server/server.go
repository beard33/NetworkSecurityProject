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
	"netsecProject/utils/DH/dh"
	"os"
)

const line = "----------------------------"

func main() {

	k := dh.Key{P: big.NewInt(0), X: big.NewInt(0), G: big.NewInt(0)}
	var PubVal, sharedKey, ReceivedVal = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	var keyLen, signLen int
	var sndBuf []byte
	var toBeSigned []byte
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
		fmt.Println(line)
		fmt.Println("The modulus is\n", k.P)
		fmt.Println(line)
		fmt.Println("The generator is\n", k.G)
		fmt.Println(line)
		fmt.Println("Public exp is\n", PubVal)
		fmt.Println(line)

		_, err = c.Read(rcvBuf)
		if err != nil {
			log.Fatal(err)
		}
		keyLen = (int(rcvBuf[0]))
		byteVal = rcvBuf[1 : keyLen+1]
		ReceivedVal.SetBytes(byteVal)
		sharedKey.Exp(ReceivedVal, k.X, k.P)

		fmt.Println("Shared key:\n", sharedKey)
		fmt.Println(line)

		// Generate the signature
		toBeSigned = append(toBeSigned, ReceivedVal.Bytes()...)
		toBeSigned = append(toBeSigned, PubVal.Bytes()...)
		hashed := sha256.Sum256(toBeSigned)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
		signLen = len(signature)

		// Generate the byte stream to be sent
		sndBuf = append(sndBuf, byte(len(PubVal.Bytes())))
		sndBuf = append(sndBuf, PubVal.Bytes()...)
		sndBuf = append(sndBuf, byte(signLen))
		sndBuf = append(sndBuf, signature...)

		_, err = c.Write(sndBuf)
		if err != nil {
			log.Fatal(err)
			return
		}

		// reset the buffers
		sndBuf = nil
		toBeSigned = nil
		continue
	}

}
