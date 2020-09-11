package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func importPubKey(file string) *rsa.PublicKey {
	keyBytes, _ := ioutil.ReadFile(file)
	block, _ := pem.Decode(keyBytes)
	key, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return key.(*rsa.PublicKey)
}
