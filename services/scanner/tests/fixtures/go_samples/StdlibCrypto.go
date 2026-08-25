package main

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rsa"
	"crypto/tls"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	md5.Sum(nil)
	aes.NewGCM(nil)
	tls.VersionTLS10
	rsa.GenerateKey(nil, 1024)
	bcrypt.GenerateFromPassword(nil, 10)
	chacha20poly1305.New(nil)
}
