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

func Client(conn net.Conn) (*Conn, error) {
	if c, err := TokenPool.pick(); err == nil {
		return fastlyHs(conn, c)
	}
	payload, cInfo := makeClientPacketOne(AuthInfo.SessionId, nil)
	_, err := conn.Write(payload)
	if err != nil {
		return nil, common.NewError("failed to send packet").Base(err)
	}
	buf, err := readServerPacketOne(conn)
	if err != nil {
		return nil, common.NewError("failed to read server packet").Base(err)
	}
	H, secret, err := handleServerPacketOne(buf, cInfo)
	sig := ed25519.Sign(AuthInfo.PrivateKey, H)
	if err := replyServer(conn, sig); err != nil {
		return nil, common.NewError("client failed to reply sig").Base(err)
	}
	serverSig, decryptedToken, err := readServerReply(conn, secret)
	if err != nil {
		return nil, common.NewError("client failed to read server sig").Base(err)
	}
	if !ed25519.Verify(AuthInfo.PublicKey, H, serverSig) {
		err = fmt.Errorf("服务端签名验证未通过")
		return nil, err
	}
	TokenPool.add(secret, decryptedToken)
	return &Conn{
		Conn:      conn,
		SessionId: AuthInfo.SessionId,
		SharedKey: secret,
		isClient:  true,
		recvBuf:   make([]byte, MaxPayloadSize),
	}, nil
}
func fastlyHs(conn net.Conn, token []byte) (*Conn, error) {
	payload, info := makeClientPacketOne(AuthInfo.SessionId, token)
	_, err := conn.Write(payload)
	if err != nil {
		return nil, common.NewError("failed to send packet").Base(err)
	}
	secret, err := rhServerFastPacket(conn, info)
	if err != nil {
		return nil, err
	}
	return &Conn{
		Conn:      conn,
		SessionId: info.SessionId,
		SharedKey: secret,
		isClient:  true,
		recvBuf:   make([]byte, MaxPayloadSize),
	}, nil
}

func makeClientPacketOne(id, token []byte) (totalData []byte, info *selfAuthInfo) {
	fastly := true
	if len(token) == 0 {
		fastly = false
	}
	var entropy []byte
	var entropyLen int
	if fastly {
		entropyLen = len(token)
		entropy = token
		//entropy = make([]byte, entropyLen)
		//copy(entropy, token)
	} else {
		entropyLen = intRange(MinPaddingLen, MaxPaddingLen)
		entropy = make([]byte, entropyLen)
		readRand(&entropy)
	}
	paddingLen := intRange(MinPaddingLen, MaxPaddingLen)
	log.Debugf("paddingLen is %d", paddingLen)
	padding1 := make([]byte, paddingLen)
	sessionId := make([]byte, 4)
	if len(id) == 0 {
		readRand(&sessionId)
	} else {
		copy(sessionId, id)
	}
	padding2 := make([]byte, paddingLen)
	totalData = make([]byte, NonceLen)
	readRand(&totalData)
	readRand(&padding1)
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
	dataLen := make([]byte, 4)
	dataLen[0] = byte(entropyLen)
	binary.LittleEndian.PutUint16(dataLen[1:3], uint16(2*paddingLen+entropyLen))
	if fastly {
		dataLen[3] = byte(2 * intn(128)) //偶数
	} else {
		dataLen[3] = byte(2*intn(128) - 1) //奇数
	}
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
	if dataLength > MaxPacketOneSize {
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
	sInfo := &otherAuthInfo{
		Entropy:   entropy,
		SessionId: SessionId,
		EphPub:    ephPubS,
	}
	secret, err = generateSharedSecret(cInfo.EphPri, sInfo.EphPub)
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

func readServerReply(conn net.Conn, key []byte) (sig, token []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(ReadTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	nonce := make([]byte, NonceLen)
	_, err = io.ReadFull(conn, nonce)
	if err != nil {
		return
	}
	sigAndDataLen := make([]byte, SigLen+2)
	_, err = io.ReadFull(conn, sigAndDataLen)
	if err != nil {
		return
	}
	paddingLen := int(sigAndDataLen[SigLen])
	tokenLen := int(sigAndDataLen[SigLen+1])
	padding := make([]byte, paddingLen)
	_, err = io.ReadFull(conn, padding)
	if err != nil {
		return
	}
	encryptedToken := make([]byte, tokenLen)
	_, err = io.ReadFull(conn, encryptedToken)
	if err != nil {
		return
	}
	token, err = decrypt(encryptedToken, key)
	if err != nil {
		return
	}
	sig = sigAndDataLen[:SigLen]
	return
}
func replyServer(conn net.Conn, sig []byte) (err error) {
	paddingLen := intRange(128, 256)
	padding := make([]byte, paddingLen)
	readRand(&padding)
	reply := make([]byte, NonceLen)
	readRand(&reply)
	reply = append(reply, sig...)
	reply = append(reply, byte(paddingLen))
	reply = append(reply, padding...)
	_, err = conn.Write(reply)
	if err != nil {
		return
	}
	return
}
