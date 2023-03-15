package handshake

import (
	"crypto/rand"
	"io"
)

func readRand(b *[]byte) {
	io.ReadFull(rand.Reader, *b)
}
