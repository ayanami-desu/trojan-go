package handshake

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	"io"
	"net"
	"time"
)

type twoRtt struct {
	*authInfo
}

func (c *twoRtt) HandShake(conn net.Conn) (net.Conn, error) {
	conn.SetReadDeadline(time.Now().Add(readTimeOut))
	defer conn.SetReadDeadline(time.Time{})
	payload, cInfo := makeClientPacketOne()
	_, err := conn.Write(payload)
	if err != nil {
		return nil, common.NewError("failed to send packet").Base(err)
	}
	buf, err := readServerPacketOne(conn)
	if err != nil {
		return nil, common.NewError("failed to read server packet").Base(err)
	}
	H, secret, err := handleServerPacketOne(buf, cInfo)
	sig := ed25519.Sign(c.PrivateKey, H)
	if err := replyServer(conn, sig); err != nil {
		return nil, common.NewError("client failed to reply sig").Base(err)
	}
	serverSig, err := readServerReply(conn)
	if err != nil {
		return nil, common.NewError("client failed to read server sig").Base(err)
	}
	if !ed25519.Verify(c.PublicKey, H, serverSig) {
		err = fmt.Errorf("服务端签名验证未通过")
		return nil, err
	}
	return &Conn{
		Conn:      conn,
		SessionId: cInfo.SessionId,
		sharedKey: secret,
		isClient:  true,
		recvBuf:   make([]byte, maxPayloadSize),
	}, nil
}

func (c *twoRtt) HandleHandShake(conn net.Conn) (net.Conn, error) {
	conn.SetReadDeadline(time.Now().Add(readTimeOut))
	defer conn.SetReadDeadline(time.Time{})

	nonce := make([]byte, nonceLen)
	_, err := io.ReadFull(conn, nonce)
	if err != nil {
		err = fmt.Errorf("failed to read nonce: %w", err)
		return nil, err
	}

	buf := make([]byte, 1024)
	_, err = io.ReadFull(conn, buf[:4])
	if err != nil {
		err = fmt.Errorf("failed to read dataLength: %w", err)
		return nil, err
	}
	//还原数据段长度
	copy(buf[:4], xorBytes(buf[:4], nonce[1]))
	randomLen := int(binary.LittleEndian.Uint16(buf[1:3]))
	if randomLen > maxRandomDataSize {
		err = fmt.Errorf("收到的服务端握手包长度(%d)超过限制", randomLen)
		readAfterError(conn)
		return nil, err
	}
	dataLength := clientPacketHeadSize + randomLen + ephPubKeyLen + sessionIdLen
	_, err = io.ReadFull(conn, buf[4:dataLength])
	if err != nil {
		err = fmt.Errorf("failed to read left content: %w", err)
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
		readAfterError(conn)
		return nil, err
	}
	var secret []byte
	secret, err = generateSharedSecret(ephPriS[:], ephPubC[:])
	if err != nil {
		err = common.NewError("error in generating shared secret").Base(err)
		readAfterError(conn)
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
	if !ed25519.Verify(auth.PublicKey, H, clientSig) {
		readAfterError(conn)
		return nil, fmt.Errorf("客户端签名验证未通过")
	}
	sig := ed25519.Sign(auth.PrivateKey, H)

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
