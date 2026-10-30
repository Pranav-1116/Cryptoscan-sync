package crypto

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rsa"
	"crypto/tls"
	"math/rand"
)

func legacy() {
	_ = md5.Sum(nil)
	_, _ = aes.NewCipher(make([]byte, 16))
	_ = tls.VersionTLS10
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
}
