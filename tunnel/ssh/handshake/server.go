package handshake

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

func Server(conn net.Conn) (*Conn, error) {
	conn.SetReadDeadline(time.Now().Add(readTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	nonce := make([]byte, nonceLen)
	_, err := io.ReadFull(conn, nonce)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	_, err = io.ReadFull(conn, buf[:4])
	if err != nil {
		err = fmt.Errorf("read length from connection fail: %v", err)
		return nil, err
	}
	// 偶数则标志0rtt握手
	if int(buf[3])%2 == 0 {
		return handleFastlyHs(conn)
	}
	randomLen := int(binary.LittleEndian.Uint16(buf[1:3]))
	if randomLen > maxRandomDataSize {
		err = fmt.Errorf("收到的服务端握手包长度(%v)超过限制", randomLen)
		return nil, err
	}
	dataLength := clientPacketHeadSize + randomLen + ephPubKeyLen + sessionIdLen
	_, err = io.ReadFull(conn, buf[4:dataLength])
	if err != nil {
		err = fmt.Errorf("read left content from connection fail: %v", err)
		return nil, err
	}
	entropyLen := int(buf[0])
	paddingLen := (int(binary.LittleEndian.Uint16(buf[1:3])) - entropyLen) / 2
	offset := 4 + paddingLen
	SessionId := buf[offset : offset+sessionIdLen]
	offset += sessionIdLen
	var ephPubC [32]byte
	copy(ephPubC[:], buf[offset:offset+ephPubKeyLen])
	//开始验证目标公钥
	ephPriS, ephPubS, err := generateKey()
	if err != nil {
		err = common.NewError("failed to generate ephemeral key pair").Base(err)
		return nil, err
	}
	var secret []byte
	secret, err = generateSharedSecret(ephPriS[:], ephPubC[:])
	if err != nil {
		err = common.NewError("error in generating shared secret").Base(err)
		return nil, err
	}
	sInfo := &selfAuthInfo{
		EphPri:    ephPriS,
		EphPub:    ephPubS,
		SharedKey: secret,
	}
	offset += ephPubKeyLen
	entropy := buf[offset : offset+entropyLen]
	cInfo := &otherAuthInfo{
		Entropy:   entropy,
		SessionId: SessionId,
		EphPub:    ephPubC,
	}

	totalData := makeServerPacketOne(sInfo)
	_, err = conn.Write(totalData)
	if err != nil {
		return nil, common.NewError("failed return packet to client").Base(err)
	}
	clientSig, err := readClientReply(conn)
	if err != nil {
		return nil, common.NewError("failed read client sig").Base(err)
	}
	H := generateHash(sInfo, cInfo)
	if !ed25519.Verify(AuthInfo.PublicKey, H, clientSig) {
		return nil, fmt.Errorf("客户端签名验证未通过")
	}
	sig := ed25519.Sign(AuthInfo.PrivateKey, H)

	if err := replyClient(conn, sig, sInfo.SharedKey); err != nil {
		return nil, common.NewError("server failed to reply sig").Base(err)
	}
	return &Conn{
		Conn:      conn,
		SessionId: cInfo.SessionId,
		sharedKey: sInfo.SharedKey,
		isClient:  false,
		recvBuf:   make([]byte, maxPayloadSize),
	}, nil
}
func handleFastlyHs(conn net.Conn) (*Conn, error) {
	//此前已读取16字节
	pubData := make([]byte, sigLen)
	_, err := io.ReadFull(conn, pubData)
	if err != nil {
		return nil, err
	}
	pubC := pubData[:ephPubKeyLen]
	sessionId := pubData[ephPubKeyLen : ephPubKeyLen+sessionIdLen]
	pri, err := TokenPool.pickPri()
	if err != nil {
		msg := makePubInvalidMsg(pubData)
		if _, err := conn.Write(msg); err != nil {
			log.Errorf("向服务端返回公钥错误信息时出错: %v", err)
		}
		return nil, err
	}
	secret, err := generateSharedSecret(pri, pubC)
	if err != nil {
		return nil, err
	}
	return &Conn{
		SessionId:   sessionId,
		Conn:        conn,
		ephShareKey: secret,
		ephPri:      pri,
		pubReceived: pubC,
		recvBuf:     make([]byte, maxPayloadSize),
	}, nil
}
func makeServerPacketOne(sInfo *selfAuthInfo) (totalData []byte) {
	paddingLen := intRange(minPaddingLen, maxPaddingLen)
	entropyLen := intRange(minPaddingLen, maxPaddingLen)
	padding1 := make([]byte, paddingLen)
	sessionId := make([]byte, sessionIdLen)
	entropy := make([]byte, entropyLen)
	padding2 := make([]byte, paddingLen)
	totalData = make([]byte, nonceLen)
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
	paddingLen := intRange(128, 256)
	padding := make([]byte, paddingLen)
	readRand(&padding)
	reply := make([]byte, nonceLen)
	readRand(&reply)
	pub := TokenPool.pickOrCreatePub()
	encryptedPub, err := encrypte(pub, key)
	if err != nil {
		return
	}
	reply = append(reply, sig...)
	reply = append(reply, byte(paddingLen))
	reply = append(reply, padding...)
	reply = append(reply, encryptedPub...)
	_, err = conn.Write(reply)
	if err != nil {
		return
	}
	return
}
