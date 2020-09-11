package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func importKey(file string) *rsa.PrivateKey {
	keyBytes, _ := ioutil.ReadFile(file)
	block, _ := pem.Decode(keyBytes)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}
