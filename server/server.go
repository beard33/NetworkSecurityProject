package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"net"
	"netsecProject/utils/DH/dh"
	"os"
)

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
		fmt.Println(err)
		return
	}
	defer l.Close()

	k.GenerateKey()
	rsaKey := importKey("privkey.pem")
	for {
		fmt.Println("WAITING FOR A CLIENT...")

		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}

		// pubRes = g^(x_s) mod p
		PubVal.Exp(k.G, k.X, k.P)
		fmt.Println("----------------------------")
		fmt.Println("The modulus is\n", k.P)
		fmt.Println("----------------------------")
		fmt.Println("The generator is\n", k.G)
		fmt.Println("----------------------------")
		fmt.Println("Computed exp is\n", PubVal)
		fmt.Println("----------------------------")

		_, err = c.Read(rcvBuf)
		keyLen = (int(rcvBuf[0]) * 255) + int(rcvBuf[1])
		byteVal = rcvBuf[2 : keyLen+2]
		ReceivedVal.SetBytes(byteVal)
		sharedKey.Exp(ReceivedVal, k.X, k.P)

		fmt.Println("Shared key:\n", sharedKey)
		fmt.Println("----------------------------")

		toBeSigned = append(toBeSigned, ReceivedVal.Bytes()...)
		toBeSigned = append(toBeSigned, PubVal.Bytes()...)
		hashed := sha256.Sum256(toBeSigned)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
		signLen = len(signature)
		sndBuf = append(sndBuf, byte(len(PubVal.Bytes())/255))
		sndBuf = append(sndBuf, byte(len(PubVal.Bytes())%255))
		sndBuf = append(sndBuf, PubVal.Bytes()...)
		sndBuf = append(sndBuf, byte(signLen))
		sndBuf = append(sndBuf, signature...)

		_, err = c.Write(sndBuf)
		if err != nil {
			fmt.Println(err)
			return
		}
		sndBuf = nil
		toBeSigned = nil
		continue
	}

}
