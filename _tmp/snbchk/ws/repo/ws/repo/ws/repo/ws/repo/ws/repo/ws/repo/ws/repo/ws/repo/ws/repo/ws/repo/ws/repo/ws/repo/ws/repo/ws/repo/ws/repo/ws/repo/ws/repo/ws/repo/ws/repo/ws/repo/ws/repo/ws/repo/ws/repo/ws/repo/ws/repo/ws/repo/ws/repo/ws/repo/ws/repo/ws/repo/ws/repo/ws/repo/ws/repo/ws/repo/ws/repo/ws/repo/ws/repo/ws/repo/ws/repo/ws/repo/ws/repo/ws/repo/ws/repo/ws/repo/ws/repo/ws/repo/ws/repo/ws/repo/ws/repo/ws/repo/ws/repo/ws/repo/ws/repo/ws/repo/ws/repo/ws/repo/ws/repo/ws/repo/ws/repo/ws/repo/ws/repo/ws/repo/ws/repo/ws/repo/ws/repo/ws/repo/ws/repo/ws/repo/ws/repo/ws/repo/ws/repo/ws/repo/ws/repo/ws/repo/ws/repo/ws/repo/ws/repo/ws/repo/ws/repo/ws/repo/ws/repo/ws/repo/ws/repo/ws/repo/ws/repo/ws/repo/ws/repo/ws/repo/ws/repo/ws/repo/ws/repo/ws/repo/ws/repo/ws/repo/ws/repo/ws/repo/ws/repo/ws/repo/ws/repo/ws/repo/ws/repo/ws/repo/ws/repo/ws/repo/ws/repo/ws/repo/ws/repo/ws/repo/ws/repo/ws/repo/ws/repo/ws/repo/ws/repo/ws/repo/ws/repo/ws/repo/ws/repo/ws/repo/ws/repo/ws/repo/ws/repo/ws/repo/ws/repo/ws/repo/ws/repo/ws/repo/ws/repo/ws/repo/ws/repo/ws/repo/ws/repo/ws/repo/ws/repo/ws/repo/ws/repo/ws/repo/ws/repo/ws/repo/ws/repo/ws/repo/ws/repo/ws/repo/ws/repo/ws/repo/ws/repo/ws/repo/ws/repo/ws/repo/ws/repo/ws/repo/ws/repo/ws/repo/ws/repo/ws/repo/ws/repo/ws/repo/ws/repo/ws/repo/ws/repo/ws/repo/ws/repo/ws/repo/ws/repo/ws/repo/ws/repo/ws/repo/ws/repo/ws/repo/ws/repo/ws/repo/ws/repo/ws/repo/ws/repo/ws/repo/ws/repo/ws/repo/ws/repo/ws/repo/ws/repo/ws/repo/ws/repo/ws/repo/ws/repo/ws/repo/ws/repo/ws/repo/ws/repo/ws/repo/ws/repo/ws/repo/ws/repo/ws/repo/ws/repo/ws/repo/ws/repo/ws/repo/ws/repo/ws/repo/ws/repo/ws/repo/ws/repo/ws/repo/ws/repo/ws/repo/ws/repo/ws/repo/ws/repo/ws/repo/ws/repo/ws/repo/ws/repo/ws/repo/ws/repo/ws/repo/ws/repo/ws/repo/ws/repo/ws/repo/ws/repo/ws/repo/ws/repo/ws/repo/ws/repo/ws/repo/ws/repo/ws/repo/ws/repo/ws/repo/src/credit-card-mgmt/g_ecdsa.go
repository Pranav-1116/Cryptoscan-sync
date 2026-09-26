package main
import ("crypto/ecdsa"; "crypto/elliptic"; "crypto/rand")
var k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
