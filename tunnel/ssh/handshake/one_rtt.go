package handshake

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type oneRtt struct {
	*authInfo
}

func (c *oneRtt) HandShake(conn net.Conn) (net.Conn, error) {
	nonceDataLen := common.IntRange(128, 512)
	nonceData := newRandomData(nonceDataLen)
	pubIdx := common.Intn(nonceDataLen - ephPubKeyLen)
	ephPri, ephPub, err := generateKey()
	if err != nil {
		log.Fatalf("failed to generate ephemeral key pair: %v", err)
	}
	copy(nonceData[pubIdx:pubIdx+ephPubKeyLen], ephPub[:])
	entropy := common.RandomString(32)
	headers := newHttpRequestHeader()
	headers.Set("Index", strconv.Itoa(pubIdx))
	req := &http.Request{
		Host:   "www.88996644.com",
		Method: "POST",
		Body:   io.NopCloser(bytes.NewReader(nonceData)),
		URL: &url.URL{
			Scheme: "http",
			Host:   "www.88996644.com",
			Path:   fmt.Sprintf("/file?token=%s", entropy),
		},
		ProtoMajor:    1,
		Header:        headers,
		ContentLength: int64(nonceDataLen),
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		return nil, err
	}
	pubSIdx, err := strconv.Atoi(resp.Header.Get("Index"))
	if err != nil {
		return nil, err
	}
	serverDataLen := int64(1)
	if resp.ContentLength > 0 {
		serverDataLen = resp.ContentLength
	}
	serverData := make([]byte, serverDataLen)
	_, err = io.ReadFull(resp.Body, serverData)
	if err != nil {
		return nil, err
	}
	pubS := serverData[pubSIdx : pubSIdx+ephPubKeyLen]
	secret, err := generateSharedSecret(ephPri[:], pubS)
	if err != nil {
		err = common.NewError("error in generating shared secret").Base(err)
		return nil, err
	}
	serverSig := serverData[pubSIdx+ephPubKeyLen : pubSIdx+ephPubKeyLen+sigLen]
	h := crypto.SHA256.New()
	writeString(h, ephPub[:])
	writeString(h, []byte(entropy))
	writeString(h, []byte{byte(pubIdx)})
	writeString(h, pubS)
	writeString(h, []byte{byte(pubSIdx)})
	H := h.Sum(nil)
	if !ed25519.Verify(c.PublicKey, H, serverSig) {
		return nil, common.NewError("服务端签名验证未通过")
	}
	sig := ed25519.Sign(c.PrivateKey, H)
	if _, err := conn.Write(sig); err != nil {
		return nil, err
	}
	return &Conn{
		Conn:      conn,
		sharedKey: secret,
		isClient:  true,
		recvBuf:   make([]byte, maxPayloadSize),
	}, nil
}

func (c *oneRtt) HandleHandShake(conn net.Conn) (net.Conn, error) {
	r := bufio.NewReader(conn)
	req, err := http.ReadRequest(r)
	if err != nil {
		//TODO 如何处理不是Http的请求
		return nil, common.NewError("not a http request")
	}
	_, entropy, _ := strings.Cut(req.URL.String(), "=")
	pubCIdx, err := strconv.Atoi(req.Header.Get("Index"))
	if err != nil {
		afterHttpErr(conn)
		return nil, err
	}
	clientDataLen := int64(1)
	if req.ContentLength > 0 {
		clientDataLen = req.ContentLength
	}
	clientData := make([]byte, clientDataLen)
	_, err = io.ReadFull(req.Body, clientData)
	if err != nil {
		return nil, err
	}
	pubC := clientData[pubCIdx : pubCIdx+ephPubKeyLen]
	ephPri, ephPub, err := generateKey()
	if err != nil {
		log.Fatalf("failed to generate ephemeral key pair: %v", err)
	}
	secret, err := generateSharedSecret(ephPri[:], pubC)
	if err != nil {
		afterHttpErr(conn)
		return nil, common.NewError("error in generating shared secret").Base(err)
	}
	h := crypto.SHA256.New()
	writeString(h, pubC)
	writeString(h, []byte(entropy))
	writeString(h, []byte{byte(pubCIdx)})
	writeString(h, ephPub[:])
	nonceDataLen := common.IntRange(256, 512)
	nonceData := newRandomData(nonceDataLen)
	pubSIdx := common.Intn(nonceDataLen - sigLen - ephPubKeyLen)
	writeString(h, []byte{byte(pubSIdx)})
	H := h.Sum(nil)
	sig := ed25519.Sign(c.PrivateKey, H)
	copy(nonceData[pubSIdx:pubSIdx+ephPubKeyLen], ephPub[:])
	copy(nonceData[pubSIdx+ephPubKeyLen:pubSIdx+ephPubKeyLen+sigLen], sig)
	headers := newHttpResponseHeader()
	headers.Set("Index", strconv.Itoa(pubSIdx))
	resp := &http.Response{
		StatusCode:    200,
		Header:        headers,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(nonceData)),
		ContentLength: int64(nonceDataLen),
	}
	if err := resp.Write(conn); err != nil {
		return nil, err
	}
	clientSig := make([]byte, sigLen)
	_, err = io.ReadFull(conn, clientSig)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(c.PublicKey, H, clientSig) {
		afterHttpErr(conn)
		return nil, common.NewError("服务端签名验证未通过")
	}
	return &Conn{
		Conn:      conn,
		sharedKey: secret,
		recvBuf:   make([]byte, maxPayloadSize),
	}, nil
}

func afterHttpErr(conn net.Conn) {
	defer conn.Close()
	resp := &http.Response{
		StatusCode: 404,
		Header:     make(http.Header),
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(bytes.NewReader([]byte("404 not found"))),
	}
	resp.Write(conn)
}

func newHttpRequestHeader() http.Header {
	h := make(http.Header)
	h.Set("Accept-Encoding", "gzip, deflate")
	h.Set("Connection", "keep-alive")
	h.Set("Pragma", "no-cache")
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36")
	return h
}

func newHttpResponseHeader() http.Header {
	h := make(http.Header)
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Connection", "keep-alive")
	h.Set("Pragma", "no-cache")
	return h
}
