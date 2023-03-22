package handshake

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	"io"
	"net"
	"time"
)

func rhServerFastPacket(conn net.Conn, cInfo *selfAuthInfo) (secret []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(readTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	nonce := make([]byte, nonceLen)
	_, err = io.ReadFull(conn, nonce)
	if err != nil {
		return
	}

	buf := make([]byte, 2048)
	_, err = io.ReadFull(conn, buf[:3])
	if err != nil {
		return
	}
	randomLen := int(binary.LittleEndian.Uint16(buf[1:3]))
	if randomLen > maxRandomDataSize {
		err = fmt.Errorf("收到的服务端握手包长度(%v)超过限制", randomLen)
		return
	}
	dataLength := serverPacketHeadSize + randomLen + ephPubKeyLen + sessionIdLen

	_, err = io.ReadFull(conn, buf[3:dataLength])
	if err != nil {
		return
	}
	sigAndOther := make([]byte, sigLen+1)
	_, err = io.ReadFull(conn, sigAndOther)
	if err != nil {
		return
	}
	sig := sigAndOther[:sigLen]
	h := crypto.SHA256.New()
	writeString(h, cInfo.SessionId)
	writeString(h, cInfo.EphPub[:])
	writeString(h, cInfo.Entropy)
	H := h.Sum(nil)
	if !ed25519.Verify(AuthInfo.PublicKey, H, sig) {
		err = fmt.Errorf("服务端签名验证未通过")
		return nil, err
	}
	encryptedTokenLen := int(sigAndOther[sigLen])
	encryptedToken := make([]byte, encryptedTokenLen)
	_, err = io.ReadFull(conn, encryptedToken)
	if err != nil {
		return
	}
	entropyLen := int(buf[0])
	paddingLen := (int(binary.LittleEndian.Uint16(buf[1:3])) - entropyLen) / 2
	offset := 3 + paddingLen + sessionIdLen

	var ephPubS [32]byte
	copy(ephPubS[:], buf[offset:offset+ephPubKeyLen])

	secret, err = generateSharedSecret(cInfo.EphPri, ephPubS)
	if err != nil {
		err = common.NewError("error in generating shared secret").Base(err)
		return
	}
	decryptedToken, err := decrypt(encryptedToken, secret)
	if err != nil {
		return
	}
	err = TokenPool.add(secret, decryptedToken)
	if err != nil {
		return
	}
	return
}
