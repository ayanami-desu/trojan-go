package handshake

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh/cipher"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

type Conn struct {
	net.Conn
	SessionId  []byte
	isClient   bool
	SharedKey  []byte
	sendMutex  sync.Mutex // mutex used when write data to the connection
	recvMutex  sync.Mutex // mutex used when read data from the connection
	recv       cipher.BlockCipher
	send       cipher.BlockCipher
	recvBuf    []byte // data received from network but not read by caller
	recvBufPtr []byte // reading position of received data
}

var maxPaddingSize = 256 + fixedInt(256)

func (s *Conn) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *Conn) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *Conn) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

func (s *Conn) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

func (s *Conn) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}
func (s *Conn) Read(b []byte) (n int, err error) {
	s.recvMutex.Lock()
	defer s.recvMutex.Unlock()
	n, err = s.readInternal(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// EOF must be reported back to caller as is.
			return n, io.EOF
		}
		return n, err
	}
	return n, nil
}
func (s *Conn) readInternal(b []byte) (n int, err error) {
	if len(s.recvBufPtr) > 0 {
		n = copy(b, s.recvBufPtr)
		s.recvBufPtr = s.recvBufPtr[n:]
		return n, nil
	}
	//}
	// Read encrypted payload length.
	readLen := 2 + cipher.DefaultOverhead
	if s.recv == nil {
		// For the first Read, also include nonce.
		readLen += cipher.DefaultNonceSize
	}
	encryptedLen := make([]byte, readLen)
	if _, err := io.ReadFull(s.Conn, encryptedLen); err != nil {
		return 0, fmt.Errorf("read %d bytes failed when reading encryptedLen: %w", readLen, err)
	}
	var decryptedLen []byte

	if s.recv == nil {
		s.recv, err = cipher.NewAESGCMBlockCipher(s.SharedKey)
		if err != nil {
			log.Fatalf("创建读加密块失败: %w", err)
		}
	}

	decryptedLen, err = s.recv.Decrypt(encryptedLen)
	if err != nil {
		return 0, fmt.Errorf("decrypt() failed: %w", err)
	}
	readLen = int(binary.LittleEndian.Uint16(decryptedLen))
	if readLen > MaxPayloadSize {
		return 0, fmt.Errorf("收到的包长度超过限制")
	}
	readLen += cipher.DefaultOverhead

	// Read encrypted payload.
	encryptedPayload := make([]byte, readLen)
	if _, err := io.ReadFull(s.Conn, encryptedPayload); err != nil {
		return 0, fmt.Errorf("read %d bytes failed when reading encryptedPayload: %w", readLen, err)
	}
	decryptedPayload, err := s.recv.Decrypt(encryptedPayload)
	if err != nil {
		return 0, fmt.Errorf("decrypt() failed: %w", err)
	}
	// Extract useful payload from decrypted payload.
	if len(decryptedPayload) < PayloadOverhead {
		return 0, fmt.Errorf("解密数据段长度短于4")
	}
	usefulSize := int(binary.LittleEndian.Uint16(decryptedPayload))
	totalSize := int(binary.LittleEndian.Uint16(decryptedPayload[2:]))
	if usefulSize > totalSize || totalSize+PayloadOverhead != len(decryptedPayload) {
		return 0, fmt.Errorf("协议错误")
	}

	// When b is large enough, receive data into b directly.
	if len(b) >= usefulSize {
		return copy(b, decryptedPayload[PayloadOverhead:PayloadOverhead+usefulSize]), nil
	}

	// When b is not large enough, first copy to recvbuf then copy to b.
	// If needed, resize recvBuf to guarantee a sufficient space.
	if cap(s.recvBuf) < usefulSize {
		s.recvBuf = make([]byte, usefulSize)
	}
	s.recvBuf = s.recvBuf[:usefulSize]
	copy(s.recvBuf, decryptedPayload[PayloadOverhead:PayloadOverhead+usefulSize])
	n = copy(b, s.recvBuf)
	s.recvBufPtr = s.recvBuf[n:]
	return n, nil
}

func (s *Conn) Write(b []byte) (n int, err error) {
	s.sendMutex.Lock()
	defer s.sendMutex.Unlock()
	n = len(b)
	if len(b) <= maxWriteChunkSize {
		return s.writeChunk(b)
	}
	for len(b) > 0 {
		sizeToSend := intRange(baseWriteChunkSize, maxWriteChunkSize)
		if sizeToSend > len(b) {
			sizeToSend = len(b)
		}
		if _, err = s.writeChunk(b[:sizeToSend]); err != nil {
			return 0, err
		}
		b = b[sizeToSend:]
	}
	return n, nil
}
func (s *Conn) writeChunk(b []byte) (n int, err error) {
	if len(b) > maxWriteChunkSize {
		return 0, fmt.Errorf("要写入的包长度超过%v", maxWriteChunkSize)
	}

	// Construct the payload with padding.
	paddingSizeLimit := MaxPayloadSize - PayloadOverhead - len(b)
	if paddingSizeLimit > maxPaddingSize {
		paddingSizeLimit = maxPaddingSize
	}
	paddingSize := intn(paddingSizeLimit)
	payload := make([]byte, PayloadOverhead+len(b)+paddingSize)
	binary.LittleEndian.PutUint16(payload, uint16(len(b)))
	binary.LittleEndian.PutUint16(payload[2:], uint16(len(b)+paddingSize))
	copy(payload[PayloadOverhead:], b)
	if paddingSize > 0 {
		crand.Read(payload[PayloadOverhead+len(b):])
	}

	// Create send block cipher if needed.
	if s.send == nil {
		if s.isClient {
			s.send, err = cipher.NewAESGCMBlockCipher(s.SharedKey)
			if err != nil {
				log.Fatalf("创建写加密块失败: %w", err)
			}
		} else {
			if s.recv != nil {
				s.send = s.recv.Clone()
				s.send.SetImplicitNonceMode(false) // clear implicit nonce
				s.send.SetImplicitNonceMode(true)
			} else {
				//TODO 为什么服务端侧会先写？
				log.Warnf("收发加密块均为空")
				s.send, err = cipher.NewAESGCMBlockCipher(s.SharedKey)
				if err != nil {
					log.Fatalf("创建写加密块失败: %w", err)
				}
			}
		}
	}

	// Create encrypted payload length.
	plaintextLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(plaintextLen, uint16(len(payload)))
	encryptedLen, err := s.send.Encrypt(plaintextLen)
	if err != nil {
		return 0, fmt.Errorf("encrypt() failed: %w", err)
	}

	// Create encrypted payload.
	encryptedPayload, err := s.send.Encrypt(payload)
	if err != nil {
		return 0, fmt.Errorf("encrypted() failed: %w", err)
	}

	// Send encrypted payload length + encrypted payload.
	dataToSend := append(encryptedLen, encryptedPayload...)
	if _, err := io.WriteString(s.Conn, string(dataToSend)); err != nil {
		return 0, fmt.Errorf("io.WriteString() failed: %w", err)
	}

	return len(b), nil
}
func (s *Conn) Close() error {
	return s.Conn.Close()
}
