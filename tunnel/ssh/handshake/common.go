package handshake

import (
	"crypto/rand"
	log "github.com/sirupsen/logrus"
	"io"
)

func readRand(b *[]byte) {
	io.ReadFull(rand.Reader, *b)
}
func Init(pri, pub string) {
	priK, pubK, err := loadKeyPair(pri, pub)
	if err != nil {
		log.Fatal(err)
	}
	AuthInfo = &authInfo{
		PrivateKey: priK,
		PublicKey:  pubK,
	}
	initSeed()
	TokenPool = &tokenPool{
		Tokens: make(map[uint32]*token),
	}
}
