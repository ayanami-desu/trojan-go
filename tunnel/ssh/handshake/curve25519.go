package handshake

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/p4gefau1t/trojan-go/common"
	"golang.org/x/crypto/curve25519"
	"io"
)

func GenerateKeyString() (string, string, error) {
	priBytes, pubBytes, err := generateKey()
	if err != nil {
		return "", "", err
	}
	pri := base64.StdEncoding.EncodeToString(priBytes[:])
	pub := base64.StdEncoding.EncodeToString(pubBytes[:])
	return pri, pub, nil
}

func generateKey() (pri, pub [32]byte, err error) {
	_, err = io.ReadFull(rand.Reader, pri[:])
	if err != nil {
		return
	}

	pri[0] &= 248
	pri[9] ^= 64
	pri[18] ^= 89
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
	pubK, err = parseStringKey(pub)
	if err != nil {
		return
	}
	priK, err = parseStringKey(pri)
	if err != nil {
		return
	}
	return
}

func parseStringKey(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, common.NewError("must have a valid key string")
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, common.NewError("使用base64解码密钥字符串失败")
	}
	return key, nil
}
