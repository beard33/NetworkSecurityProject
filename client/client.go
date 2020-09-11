package main

import (
	"fmt"
	"math/big"
	"net"
	"netsecProject/utils/DH/dh"
	"os"
)

func main() {

	var PubVal, SharedKey, ReceivedVal = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	var sndBuf []byte
	var keyLen int
	rcvBuf := make([]byte, 512)
	k := dh.Key{P: big.NewInt(0), X: big.NewInt(0), G: big.NewInt(0)}
	byteVal := make([]byte, 128)

	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	k.GenerateKey()
	// pubRes = g^(x_c) mod p
	PubVal.Exp(k.G, k.X, k.P)
	fmt.Println("----------------------------")
	fmt.Println("The modulus is\n", k.P)
	fmt.Println("----------------------------")
	fmt.Println("The generator is\n", k.G)
	fmt.Println("----------------------------")
	fmt.Println("Computed exp is\n", PubVal)
	fmt.Println("----------------------------")

	sndBuf = append(sndBuf, byte(len(PubVal.Bytes())/255))
	sndBuf = append(sndBuf, byte(len(PubVal.Bytes())%255))
	sndBuf = append(sndBuf, PubVal.Bytes()...)

	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = c.Write(sndBuf)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Receive server public exponential
	_, err = c.Read(rcvBuf)
	keyLen = (int(rcvBuf[0]) * 255) + int(rcvBuf[1])
	byteVal = rcvBuf[2 : keyLen+2]
	ReceivedVal.SetBytes(byteVal)
	SharedKey.Exp(ReceivedVal, k.X, k.P)
	fmt.Println("Shared key:\n", SharedKey)
	fmt.Println("----------------------------")

}
