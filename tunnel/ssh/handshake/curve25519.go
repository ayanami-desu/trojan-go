package handshake

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"io"
)

func generateKey() (pri, pub [32]byte, err error) {
	_, err = io.ReadFull(rand.Reader, pri[:])
	if err != nil {
		return
	}

	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64

	curve25519.ScalarBaseMult(&pub, &pri)
	return
}

func generateSharedSecret(pri, pub []byte) ([]byte, error) {
	return curve25519.X25519(pri, pub)
}

func writeString(w io.Writer, s []byte) {
	var lengthBytes [4]byte
	lengthBytes[0] = byte(len(s) >> 24)
	lengthBytes[1] = byte(len(s) >> 16)
	lengthBytes[2] = byte(len(s) >> 8)
	lengthBytes[3] = byte(len(s))
	w.Write(lengthBytes[:])
	w.Write(s)
}

func loadKeyPair(pri, pub string) (priK, pubK []byte, err error) {
	if len(pri) == 0 {
		err = fmt.Errorf("must have a valid private key")
		return
	}
	if len(pub) == 0 {
		err = fmt.Errorf("must have a valid public key")
		return
	}
	pubK, err = base64.StdEncoding.DecodeString(pub)
	if err != nil {
		err = fmt.Errorf("使用base64解码公钥字符串失败")
		return
	}
	priK, err = base64.StdEncoding.DecodeString(pri)
	if err != nil {
		err = fmt.Errorf("使用base64解码私钥字符串失败")
		return
	}
	return
}
