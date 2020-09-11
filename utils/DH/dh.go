package dh

import (
	"crypto/rand"
	"math/big"
)

type Key struct {
	P *big.Int
	X *big.Int
	G *big.Int
}

func (k Key) GenerateKey() {
	k.P.SetString("171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303", 10)
	lim := big.NewInt(2)
	gen, err := rand.Int(rand.Reader, big.NewInt(0).Sub(k.P, lim))
	if err != nil {
		panic("Error in generating the exponent")
	}
	k.X.Add(gen, big.NewInt(1))
	k.G.SetString("2", 10)
}