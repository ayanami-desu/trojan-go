package handshake

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
)

func makeClientPacketOne() (totalData []byte, info *selfAuthInfo) {
	id := auth.SessionId
	entropyLen := common.IntRange(minPaddingLen, maxPaddingLen)
	paddingLen := common.IntRange(minPaddingLen, maxPaddingLen)
	padding1 := newRandomData(paddingLen)
	entropy := newRandomData(entropyLen)
	sessionId := make([]byte, 4)
	if len(id) == 0 {
		readRand(&sessionId)
	} else {
		copy(sessionId, id)
	}
	padding2 := newRandomData(paddingLen)
	totalData = newRandomData(nonceLen)
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
	dataLen := make([]byte, 4)
	dataLen[0] = byte(entropyLen)
	binary.LittleEndian.PutUint16(dataLen[1:3], uint16(2*paddingLen+entropyLen))
	dataLen[3] = byte(common.Intn(256))
	xorBytes(dataLen, totalData[1])
	totalData = append(totalData, dataLen...)
	totalData = append(totalData, padding1...)
	totalData = append(totalData, sessionId...)
	totalData = append(totalData, ephPub[:]...)
	totalData = append(totalData, entropy...)
	totalData = append(totalData, padding2...)

	return
}
func readServerPacketOne(conn net.Conn) (buf []byte, err error) {
	nonce := make([]byte, nonceLen)
	_, err = io.ReadFull(conn, nonce)
	if err != nil {
		return
	}

	buf = make([]byte, 1024)
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
	return
}
func handleServerPacketOne(buf []byte, cInfo *selfAuthInfo) (H, secret []byte, err error) {
	entropyLen := int(buf[0])
	paddingLen := (int(binary.LittleEndian.Uint16(buf[1:3])) - entropyLen) / 2
	offset := 3 + paddingLen
	SessionId := buf[offset : offset+sessionIdLen]
	offset += sessionIdLen
	var ephPubS [32]byte
	copy(ephPubS[:], buf[offset:offset+ephPubKeyLen])
	offset += ephPubKeyLen
	entropy := buf[offset : offset+entropyLen]
	sInfo := &otherAuthInfo{
		Entropy:   entropy,
		SessionId: SessionId,
		EphPub:    ephPubS,
	}
	secret, err = generateSharedSecret(cInfo.EphPri[:], sInfo.EphPub[:])
	if err != nil {
		err = common.NewError("error in generating shared secret").Base(err)
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

func readServerReply(conn net.Conn) (sig []byte, err error) {
	nonce := make([]byte, nonceLen)
	_, err = io.ReadFull(conn, nonce)
	if err != nil {
		return
	}
	sigAndPaddingLen := make([]byte, sigLen+1)
	_, err = io.ReadFull(conn, sigAndPaddingLen)
	if err != nil {
		return
	}
	paddingLen := int(sigAndPaddingLen[sigLen])
	padding := make([]byte, paddingLen)
	_, err = io.ReadFull(conn, padding)
	if err != nil {
		return
	}
	sig = sigAndPaddingLen[:sigLen]
	return
}
func replyServer(conn net.Conn, sig []byte) (err error) {
	paddingLen := common.IntRange(128, 256)
	padding := newRandomData(paddingLen)
	reply := newRandomData(nonceLen)
	reply = append(reply, sig...)
	reply = append(reply, byte(paddingLen))
	reply = append(reply, padding...)
	_, err = conn.Write(reply)
	if err != nil {
		return
	}
	return
}
