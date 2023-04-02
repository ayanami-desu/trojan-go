package handshake

import (
	"crypto"
	"crypto/ed25519"
)

func makePubInvalidMsg(clientMsg []byte) []byte {
	h := crypto.SHA256.New()
	writeString(h, clientMsg)
	serverMsg := newRandomData(16)
	serverMsg[15] = byte(255)
	writeString(h, serverMsg)
	H := h.Sum(nil)
	sig := ed25519.Sign(AuthInfo.PrivateKey, H)
	serverMsg = append(serverMsg, sig...)
	return serverMsg
}
func verifyServerMsg(info, msg []byte) bool {
	sig := msg[16:]
	h := crypto.SHA256.New()
	writeString(h, info)
	writeString(h, msg[:16])
	H := h.Sum(nil)
	return ed25519.Verify(AuthInfo.PublicKey, H, sig)
}
