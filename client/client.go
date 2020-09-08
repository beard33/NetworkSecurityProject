package main

import (
	"fmt"
	"math/big"
	"net"
	"netsecProject/utils/dh"
	"os"
)

func main() {

	p := dh.GetP()
	g := big.NewInt(2)
	key := big.NewInt(0)
	sPubVal := big.NewInt(0)
	exp := dh.GenerateExponent()
	pubRes := big.NewInt(0)
	byteVal := make([]byte, 128)

	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	// pubRes = g^(x_c) mod p
	pubRes.Exp(g, exp, p)
	fmt.Println("----------------------------")
	fmt.Println("The modulus is\n", p)
	fmt.Println("----------------------------")
	fmt.Println("The generator is\n", g)
	fmt.Println("----------------------------")
	fmt.Println("Computed exp is\n", pubRes)
	fmt.Println("----------------------------")

	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = c.Write(pubRes.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// Receive server public exponential
	_, err = c.Read(byteVal)
	sPubVal.SetBytes(byteVal)
	key.Exp(sPubVal, exp, p)
	fmt.Println("Generated key:\n", key)
	fmt.Println("----------------------------")

	_, err = c.Write(pubRes.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
	/*
		for {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print(">> ")
			text, _ := reader.ReadString('\n')
			fmt.Fprintf(c, text+"\n")

			message, _ := bufio.NewReader(c).ReadString('\n')
			fmt.Print("->: " + message)
			if strings.TrimSpace(string(text)) == "STOP" {
				fmt.Println("TCP client exiting...")
				return
			}
		}
	*/
}
