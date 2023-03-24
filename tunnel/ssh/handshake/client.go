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
	conn.SetReadDeadline(time.Now().Add(readTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	if c, err := TokenPool.pickPub(); err == nil {
		return fastlyHs(conn, c)
	}
	payload, cInfo := makeClientPacketOne(AuthInfo.SessionId)
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
	serverSig, decryptedPub, err := readServerReply(conn, secret)
	if err != nil {
		return nil, common.NewError("client failed to read server sig").Base(err)
	}
	if !ed25519.Verify(AuthInfo.PublicKey, H, serverSig) {
		err = fmt.Errorf("服务端签名验证未通过")
		return nil, err
	}
	//清空之前储存的服务端公钥
	//TokenPool.clear()
	if err := TokenPool.add(decryptedPub); err != nil {
		return nil, err
	}
	return &Conn{
		Conn:      conn,
		SessionId: AuthInfo.SessionId,
		sharedKey: secret,
		isClient:  true,
		recvBuf:   make([]byte, maxPayloadSize),
	}, nil
}
func fastlyHs(conn net.Conn, pubS []byte) (*Conn, error) {
	nonce := make([]byte, sigLen+16)
	readRand(&nonce)
	nonce[15] = byte(2 * intn(128)) //偶数
	pri, pub, err := generateKey()
	if err != nil {
		return nil, err
	}
	copy(nonce[16:16+ephPubKeyLen], pub[:])
	secret, err := generateSharedSecret(pri[:], pubS)
	_, err = conn.Write(nonce)
	if err != nil {
		return nil, fmt.Errorf("client failed to send pub: %w", err)
	}
	return &Conn{
		Conn:        conn,
		ephShareKey: secret,
		ephPri:      pri[:],
		pubToSend:   nonce[16:],
		isClient:    true,
		recvBuf:     make([]byte, maxPayloadSize),
	}, nil
}

func makeClientPacketOne(id []byte) (totalData []byte, info *selfAuthInfo) {
	entropyLen := intRange(minPaddingLen, maxPaddingLen)
	paddingLen := intRange(minPaddingLen, maxPaddingLen)
	padding1 := make([]byte, paddingLen)
	entropy := make([]byte, entropyLen)
	sessionId := make([]byte, 4)
	if len(id) == 0 {
		readRand(&sessionId)
	} else {
		copy(sessionId, id)
	}
	padding2 := make([]byte, paddingLen)
	totalData = make([]byte, nonceLen)
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
	dataLen := make([]byte, 4)
	dataLen[0] = byte(entropyLen)
	binary.LittleEndian.PutUint16(dataLen[1:3], uint16(2*paddingLen+entropyLen))
	dataLen[3] = byte(2*intn(128) - 1) //奇数
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

func readServerReply(conn net.Conn, key []byte) (sig, pub []byte, err error) {
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
	encryptedPub := make([]byte, ephPubKeyLen+authTagSize)
	_, err = io.ReadFull(conn, encryptedPub)
	if err != nil {
		return
	}
	pub, err = decrypt(encryptedPub, key)
	if err != nil {
		return
	}
	sig = sigAndPaddingLen[:sigLen]
	return
}
func replyServer(conn net.Conn, sig []byte) (err error) {
	paddingLen := intRange(128, 256)
	padding := make([]byte, paddingLen)
	readRand(&padding)
	reply := make([]byte, nonceLen)
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
