package main

import (
	"crypto"
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

	var PubVal, SharedKey, ReceivedVal = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	var sndBuf, toBeVerified []byte
	var keyLen, signLen int
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

	fmt.Println(line)
	fmt.Println("The modulus is\n", k.P)
	fmt.Println(line)
	fmt.Println("The generator is\n", k.G)
	fmt.Println(line)
	fmt.Println("Public exp is\n", PubVal)
	fmt.Println(line)

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

	// Receive server public exponential and signature
	_, err = c.Read(rcvBuf)
	if err != nil {
		log.Fatal(err)
	}
	keyLen = (int(rcvBuf[0]))
	byteVal = rcvBuf[1 : keyLen+1]
	ReceivedVal.SetBytes(byteVal)
	SharedKey.Exp(ReceivedVal, k.X, k.P)

	fmt.Println("Shared key:\n", SharedKey)
	fmt.Println(line)

	// Verify the signature
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
		fmt.Println(line)
	}
}
