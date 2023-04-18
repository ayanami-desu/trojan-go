package handshake

import (
	"crypto"
	"encoding/binary"
	"github.com/p4gefau1t/trojan-go/common"
	"io"
	"net"
)

func makeServerPacketOne(sInfo *selfAuthInfo) (totalData []byte) {
	paddingLen := common.IntRange(minPaddingLen, maxPaddingLen)
	entropyLen := common.IntRange(minPaddingLen, maxPaddingLen)
	padding1 := newRandomData(paddingLen)
	sessionId := newRandomData(sessionIdLen)
	entropy := newRandomData(entropyLen)
	padding2 := newRandomData(paddingLen)
	totalData = newRandomData(nonceLen)
	//补全serverInfo
	sInfo.Entropy = entropy
	sInfo.SessionId = sessionId

	dataLen := make([]byte, 3)
	dataLen[0] = byte(entropyLen)
	binary.LittleEndian.PutUint16(dataLen[1:3], uint16(2*paddingLen+entropyLen))
	totalData = append(totalData, dataLen...)
	totalData = append(totalData, padding1...)
	totalData = append(totalData, sessionId...)
	totalData = append(totalData, sInfo.EphPub[:]...)
	totalData = append(totalData, entropy...)
	totalData = append(totalData, padding2...)
	return
}
func generateHash(sInfo *selfAuthInfo, cInfo *otherAuthInfo) (H []byte) {
	//生成签名
	h := crypto.SHA256.New()
	writeString(h, cInfo.SessionId)
	writeString(h, cInfo.EphPub[:])
	writeString(h, cInfo.Entropy)
	writeString(h, sInfo.SessionId)
	writeString(h, sInfo.EphPub[:])
	writeString(h, sInfo.Entropy)
	writeString(h, sInfo.SharedKey)
	H = h.Sum(nil)
	return
}
func readClientReply(conn net.Conn) (sig []byte, err error) {
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
	paddingLen := int(sigAndPaddingLen[64])
	padding := make([]byte, paddingLen)
	_, err = io.ReadFull(conn, padding)
	if err != nil {
		return
	}
	sig = sigAndPaddingLen[:sigLen]
	return
}
func replyClient(conn net.Conn, sig, key []byte) (err error) {
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
