package handshake

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

func Client(conn net.Conn, authInfo *AuthInfo) (*Conn, error) {
	payload, cInfo := makeClientPacketOne(authInfo.SessionId)

	_, err := conn.Write(payload)
	if err != nil {
		return nil, err
	}
	buf, err := readServerPacketOne(conn)
	if err != nil {
		return nil, err
	}
	H, secret, err := handleServerPacketOne(buf, cInfo)
	sig := ed25519.Sign(authInfo.PrivateKey, H)
	if err := replyWithSig(conn, sig); err != nil {
		return nil, err
	}
	serverSig, err := readSig(conn)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(authInfo.PublicKey, H, serverSig) {
		err = fmt.Errorf("服务端签名验证未通过")
		return nil, err
	}

	return &Conn{
		Conn:      conn,
		SessionId: authInfo.SessionId,
		SharedKey: secret,
		isClient:  true,
		recvBuf:   make([]byte, MaxPayloadSize),
	}, nil
}
func makeClientPacketOne(id []byte) (totalData []byte, info *selfAuthInfo) {
	entropyLen := intRange(MinPaddingLen, MaxPaddingLen)
	paddingLen := intRange(MinPaddingLen, MaxPaddingLen)
	padding1 := make([]byte, paddingLen)
	sessionId := make([]byte, 4)
	if len(id) == 0 {
		readRand(&sessionId)
	} else {
		copy(sessionId, id[:])
	}
	padding2 := make([]byte, paddingLen)
	entropy := make([]byte, entropyLen)
	totalData = make([]byte, NonceLen)
	readRand(&totalData)
	readRand(&padding1)
	readRand(&entropy)
	readRand(&padding2)
	ephPri, ephPub, err := generateKey()
	if err != nil {
		log.Fatalf("failed to generate ephemeral key pair: %v", err)
	}
	info = &selfAuthInfo{
		Entropy:   entropy,
		SessionId: sessionId,
		EphPub:    ephPub,
		EphPri:    ephPri,
	}
	dataLen := make([]byte, 3)
	dataLen[0] = byte(entropyLen)
	binary.LittleEndian.PutUint16(dataLen[1:3], uint16(2*paddingLen+entropyLen))
	totalData = append(totalData, dataLen...)
	totalData = append(totalData, padding1...)
	totalData = append(totalData, sessionId...)
	totalData = append(totalData, ephPub[:]...)
	totalData = append(totalData, entropy...)
	totalData = append(totalData, padding2...)

	return
}
func readServerPacketOne(conn net.Conn) (buf []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(ReadTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	nonce := make([]byte, NonceLen)
	_, err = io.ReadFull(conn, nonce)
	if err != nil {
		return
	}

	buf = make([]byte, 1024)
	_, err = io.ReadFull(conn, buf[:3])
	if err != nil {
		return
	}

	dataLength := 3 + int(binary.LittleEndian.Uint16(buf[1:3])) + EphPubKeyLen + SessionIdLen
	if dataLength > MaxServerPacketOneSize {
		err = fmt.Errorf("收到的服务端握手包长度(%v)超过限制", dataLength)
		return
	}
	_, err = io.ReadFull(conn, buf[3:dataLength])
	return
}
func handleServerPacketOne(buf []byte, cInfo *selfAuthInfo) (H, secret []byte, err error) {
	entropyLen := int(buf[0])
	paddingLen := (int(binary.LittleEndian.Uint16(buf[1:3])) - entropyLen) / 2
	offset := 3 + paddingLen
	SessionId := buf[offset : offset+SessionIdLen]
	offset += SessionIdLen
	var ephPubS [32]byte
	copy(ephPubS[:], buf[offset:offset+EphPubKeyLen])
	offset += EphPubKeyLen
	entropy := buf[offset : offset+entropyLen]
	//offset = offset + entropyLen + paddingLen
	//serverSig = buf[offset : offset+SigLen]
	sInfo := &otherAuthInfo{
		Entropy:   entropy,
		SessionId: SessionId,
		EphPub:    ephPubS,
	}
	secret, err = generateSharedSecret(cInfo.EphPri, sInfo.EphPub)
	if err != nil {
		log.Warnf("error in generating shared secret: %v", err)
		return
	}
	h := crypto.SHA256.New()
	writeString(h, cInfo.SessionId)
	writeString(h, cInfo.EphPub[:])
	writeString(h, cInfo.Entropy)
	writeString(h, sInfo.SessionId)
	writeString(h, sInfo.EphPub[:])
	writeString(h, sInfo.Entropy)
	writeString(h, secret)
	H = h.Sum(nil)
	return
}
func replyWithSig(conn net.Conn, sig []byte) (err error) {
	paddingLen := intRange(128, 256)
	padding := make([]byte, paddingLen)
	readRand(&padding)
	reply := make([]byte, NonceLen)
	reply = append(reply, sig...)
	reply = append(reply, byte(paddingLen))
	reply = append(reply, padding...)
	_, err = conn.Write(reply)
	if err != nil {
		return
	}
	return
}
