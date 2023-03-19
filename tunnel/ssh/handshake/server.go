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

func Server(conn net.Conn, keys *AuthInfo) (*Conn, error) {
	clientInfo, err := readClientPacket(conn)
	if err != nil {
		return nil, common.NewError("failed to read client packet ").Base(err)
	}
	sInfo, cInfo, err := handleClientPacket(clientInfo)
	if err != nil {
		return nil, err
	}
	totalData := makeServerPacketOne(sInfo)
	_, err = conn.Write(totalData)
	if err != nil {
		return nil, common.NewError("failed return packet to client").Base(err)
	}
	clientSig, err := readSig(conn)
	if err != nil {
		return nil, common.NewError("failed read client sig").Base(err)
	}
	H := generateHash(sInfo, cInfo)
	if !ed25519.Verify(keys.PublicKey, H, clientSig) {
		return nil, fmt.Errorf("客户端签名验证未通过")
	}
	sig := ed25519.Sign(keys.PrivateKey, H)
	if err := replyWithSig(conn, sig); err != nil {
		return nil, common.NewError("server failed to reply sig").Base(err)
	}

	return &Conn{
		Conn:      conn,
		SessionId: cInfo.SessionId,
		SharedKey: sInfo.SharedKey,
		isClient:  false,
		recvBuf:   make([]byte, MaxPayloadSize),
	}, nil
}
func readClientPacket(conn net.Conn) (buf []byte, err error) {
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
		err = fmt.Errorf("read length from connection fail: %v", err)
		return
	}
	dataLength := 3 + int(binary.LittleEndian.Uint16(buf[1:3])) + EphPubKeyLen + SessionIdLen
	if dataLength > MaxClientPacketOneSize {
		err = fmt.Errorf("客户端第一握手包长度超过限制")
		return
	}
	_, err = io.ReadFull(conn, buf[3:dataLength])
	if err != nil {
		err = fmt.Errorf("read left content from connection fail: %v", err)
		return
	}
	return
}
func handleClientPacket(buf []byte) (sInfo *selfAuthInfo, cInfo *otherAuthInfo, err error) {
	entropyLen := int(buf[0])
	paddingLen := (int(binary.LittleEndian.Uint16(buf[1:3])) - entropyLen) / 2
	offset := 3 + paddingLen
	SessionId := buf[offset : offset+SessionIdLen]
	offset += SessionIdLen
	var ephPubC [32]byte
	copy(ephPubC[:], buf[offset:offset+EphPubKeyLen])
	//开始验证目标公钥
	ephPriS, ephPubS, err := generateKey()
	if err != nil {
		err = common.NewError("failed to generate ephemeral key pair").Base(err)
		return
	}
	var secret []byte
	secret, err = generateSharedSecret(ephPriS, ephPubC)
	if err != nil {
		err = common.NewError("error in generating shared secret").Base(err)
		return
	}
	sInfo = &selfAuthInfo{
		EphPri:    ephPriS,
		EphPub:    ephPubS,
		SharedKey: secret,
	}
	offset += EphPubKeyLen
	entropy := buf[offset : offset+entropyLen]
	cInfo = &otherAuthInfo{
		Entropy:   entropy,
		SessionId: SessionId,
		EphPub:    ephPubC,
	}
	return
}
func makeServerPacketOne(sInfo *selfAuthInfo) (totalData []byte) {
	paddingLen := intRange(MinPaddingLen, MaxPaddingLen)
	entropyLen := intRange(MinPaddingLen, MaxPaddingLen)
	padding1 := make([]byte, paddingLen)
	sessionId := make([]byte, SessionIdLen)
	entropy := make([]byte, entropyLen)
	padding2 := make([]byte, paddingLen)
	totalData = make([]byte, NonceLen)
	readRand(&totalData)
	readRand(&padding1)
	readRand(&sessionId)
	readRand(&entropy)
	readRand(&padding2)
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
	//生成签名
	//h := crypto.SHA256.New()
	//writeString(h, cInfo.SessionId)
	//writeString(h, cInfo.EphPub[:])
	//writeString(h, cInfo.Entropy)
	//writeString(h, sInfo.SessionId)
	//writeString(h, sInfo.EphPub[:])
	//writeString(h, sInfo.Entropy)
	//writeString(h, sInfo.SharedKey)
	//H = h.Sum(nil)
	//sig := ed25519.Sign(keys.PrivateKey, H)
	//totalData = append(totalData, sig...)
	//return
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
func readSig(conn net.Conn) (sig []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(ReadTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	nonce := make([]byte, NonceLen)
	_, err = io.ReadFull(conn, nonce)
	if err != nil {
		return
	}
	sigAndPaddingLen := make([]byte, SigLen+1)
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
	sig = sigAndPaddingLen[:64]
	return
}
