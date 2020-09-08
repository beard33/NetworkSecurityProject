package main

import (
	"fmt"
	"math/big"
	"net"
	"netsecProject/utils/dh"
	"os"
)

func main() {
	cPubVal, pubRes, key := big.NewInt(0), big.NewInt(0), big.NewInt(0)
	g := big.NewInt(2)
	p := dh.GetP()
	exp := dh.GenerateExponent()
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

	c, err := l.Accept()
	if err != nil {
		fmt.Println(err)
		return
	}

	count := 0

	// pubRes = g^(x_s) mod p
	pubRes.Exp(g, exp, p)
	fmt.Println("----------------------------")
	fmt.Println("The modulus is\n", p)
	fmt.Println("----------------------------")
	fmt.Println("The generator is\n", g)
	fmt.Println("----------------------------")
	fmt.Println("Computed exp is\n", pubRes)
	fmt.Println("----------------------------")

	for {
		if count == 1 {
			break
		}
		_, err = c.Read(byteVal)
		cPubVal.SetBytes(byteVal)
		key.Exp(cPubVal, exp, p)
		fmt.Println("Generated key:\n", key)
		fmt.Println("----------------------------")

		_, err = c.Write(pubRes.Bytes())
		if err != nil {
			fmt.Println(err)
			return
		}
		count++
		/*
			netData, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				fmt.Println(err)
				return
			}
			if strings.TrimSpace(string(netData)) == "STOP" {
				fmt.Println("Exiting TCP server!")
				return
			}

			fmt.Print("-> ", string(netData))
			t := time.Now()
			myTime := t.Format(time.RFC3339) + "\n"
			c.Write([]byte(myTime))
		*/
	}

}
