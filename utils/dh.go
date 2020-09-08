package dh

import (
	"crypto/rand"
	"math/big"
)

var p = new(big.Int)
var xC = new(big.Int)
var g = 2

// GetP return the order of the modulo
func GetP() *big.Int {
	p.SetString("171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303", 10)
	return p
}

// GenerateExponent generates a new random value between [1..p] is generated at every run
// It generates a rand between 0 and p-2, returning the generated number + 1, so it is
// between [1..p-1]
func GenerateExponent() *big.Int {
	lim := big.NewInt(2)
	gen, err := rand.Int(rand.Reader, big.NewInt(0).Sub(GetP(), lim))
	if err != nil {
		panic("Error in generating the exponent")
	}

	return xC.Add(gen, big.NewInt(1))
}
