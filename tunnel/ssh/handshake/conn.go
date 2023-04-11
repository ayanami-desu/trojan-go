package handshake

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh/cipher"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

type Conn struct {
	net.Conn
	SessionId   []byte
	isClient    bool
	changeKey   bool
	sharedKey   []byte
	ephShareKey []byte
	pubToSend   []byte
	pubReceived []byte
	hkData      []byte
	// ephPri 客户端生成的私钥
	ephPri     []byte
	sendMutex  sync.Mutex // mutex used when write data to the connection
	recvMutex  sync.Mutex // mutex used when read data from the connection
	recv       cipher.BlockCipher
	send       cipher.BlockCipher
	recvBuf    []byte // data received from network but not read by caller
	recvBufPtr []byte // reading position of received data
}

var maxPaddingSize = 256 + common.FixedInt(256)

func (c *Conn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
func (c *Conn) Read(b []byte) (n int, err error) {
	c.recvMutex.Lock()
	defer c.recvMutex.Unlock()
	n, err = c.readInternal(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// EOF must be reported back to caller as is.
			return n, io.EOF
		}
		return n, err
	}
	return n, nil
}
func (c *Conn) readInternal(b []byte) (n int, err error) {
	if len(c.recvBufPtr) > 0 {
		n = copy(b, c.recvBufPtr)
		c.recvBufPtr = c.recvBufPtr[n:]
		return n, nil
	}
	//}
	// Read encrypted payload length.
	readLen := 2 + cipher.DefaultOverhead
	if c.recv == nil || c.changeKey {
		// For the first Read, also include nonce.
		readLen += cipher.DefaultNonceSize
	}

	if c.recv == nil {
		if len(c.sharedKey) != 0 {
			c.recv, err = cipher.NewAESGCMBlockCipher(c.sharedKey)
			if err != nil {
				log.Fatalf("创建读加密块失败: %v", err)
			}
		} else {
			if c.isClient {
				// 客户端进行0rtt握手, 读取服务端临时公钥
				pubData := make([]byte, sigLen+16)
				n, err = io.ReadFull(c.Conn, pubData)
				if err != nil {
					return 0, err
				}
				if pubData[15] == byte(255) {
					TokenPool.clear()
					if verifyServerMsg(c.pubToSend, pubData) {
						return 0, fmt.Errorf("使用的服务端临时公钥已过期")
					} else {
						return 0, fmt.Errorf("无法认证服务端身份, 但什么也做不了")
					}
				}
				pubC := pubData[16 : 16+ephPubKeyLen]
				// 这是最终的共享密钥
				secret, err := generateSharedSecret(c.ephPri, pubC)
				if err != nil {
					return 0, err
				}
				c.sharedKey = secret
				c.changeKey = true
			} else {
				//服务端处理0rtt握手, 读取客户端临时公钥
				c.recv, err = cipher.NewAESGCMBlockCipher(c.ephShareKey)
				if err != nil {
					log.Fatalf("创建读加密块失败: %v", err)
				}
			}
		}
	}
	if c.changeKey {
		c.recv, err = cipher.NewAESGCMBlockCipher(c.sharedKey)
		if err != nil {
			log.Fatalf("创建读加密块失败: %v", err)
		}
		c.changeKey = false
	}

	encryptedLen := make([]byte, readLen)
	if _, err := io.ReadFull(c.Conn, encryptedLen); err != nil {
		return 0, fmt.Errorf("read %d bytes failed when reading encryptedLen: %w", readLen, err)
	}

	var decryptedLen []byte
	decryptedLen, err = c.recv.Decrypt(encryptedLen)
	if err != nil {
		return 0, fmt.Errorf("decrypted len failed: %w", err)
	}
	readLen = int(binary.LittleEndian.Uint16(decryptedLen))
	if readLen > maxPayloadSize {
		return 0, fmt.Errorf("收到的包长度超过限制")
	}
	readLen += cipher.DefaultOverhead

	// Read encrypted payload.
	encryptedPayload := make([]byte, readLen)
	if _, err := io.ReadFull(c.Conn, encryptedPayload); err != nil {
		return 0, fmt.Errorf("read %d bytes failed when reading encryptedPayload: %w", readLen, err)
	}
	decryptedPayload, err := c.recv.Decrypt(encryptedPayload)
	if err != nil {
		return 0, fmt.Errorf("decrypted payload failed: %w", err)
	}
	// Extract useful payload from decrypted payload.
	if len(decryptedPayload) < payloadOverhead {
		return 0, fmt.Errorf("解密数据段长度短于4")
	}
	usefulSize := int(binary.LittleEndian.Uint16(decryptedPayload))
	totalSize := int(binary.LittleEndian.Uint16(decryptedPayload[2:]))
	if usefulSize > totalSize || totalSize+payloadOverhead != len(decryptedPayload) {
		return 0, fmt.Errorf("协议错误")
	}

	// When b is large enough, receive data into b directly.
	if len(b) >= usefulSize {
		return copy(b, decryptedPayload[payloadOverhead:payloadOverhead+usefulSize]), nil
	}

	// When b is not large enough, first copy to recvbuf then copy to b.
	// If needed, resize recvBuf to guarantee a sufficient space.
	if cap(c.recvBuf) < usefulSize {
		c.recvBuf = make([]byte, usefulSize)
	}
	c.recvBuf = c.recvBuf[:usefulSize]
	copy(c.recvBuf, decryptedPayload[payloadOverhead:payloadOverhead+usefulSize])
	n = copy(b, c.recvBuf)
	c.recvBufPtr = c.recvBuf[n:]
	log.Tracef("ssh conn read %d bytes from wire", n)
	return n, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()
	n = len(b)
	if len(b) <= maxWriteChunkSize {
		return c.writeChunk(b)
	}
	for len(b) > 0 {
		sizeToSend := common.IntRange(baseWriteChunkSize, maxWriteChunkSize)
		if sizeToSend > len(b) {
			sizeToSend = len(b)
		}
		if _, err = c.writeChunk(b[:sizeToSend]); err != nil {
			return 0, err
		}
		b = b[sizeToSend:]
	}
	return n, nil
}
func (c *Conn) writeChunk(b []byte) (n int, err error) {
	if len(b) > maxWriteChunkSize {
		return 0, fmt.Errorf("要写入的包长度超过%v", maxWriteChunkSize)
	}

	// Construct the payload with padding.
	paddingSizeLimit := maxPayloadSize - payloadOverhead - len(b)
	if paddingSizeLimit > maxPaddingSize {
		paddingSizeLimit = maxPaddingSize
	}
	paddingSize := common.Intn(paddingSizeLimit)
	payload := make([]byte, payloadOverhead+len(b)+paddingSize)
	binary.LittleEndian.PutUint16(payload, uint16(len(b)))
	binary.LittleEndian.PutUint16(payload[2:], uint16(len(b)+paddingSize))
	copy(payload[payloadOverhead:], b)
	if paddingSize > 0 {
		crand.Read(payload[payloadOverhead+len(b):])
	}

	// Create send block cipher if needed.
	if c.send == nil {
		if len(c.sharedKey) != 0 {
			c.send, err = cipher.NewAESGCMBlockCipher(c.sharedKey)
			if err != nil {
				log.Fatalf("创建写加密块失败: %v", err)
			}
		} else {
			if c.isClient {
				//客户端开始0rtt握手, 发送临时公钥
				c.send, err = cipher.NewAESGCMBlockCipher(c.ephShareKey)
				if err != nil {
					log.Fatalf("创建写加密块失败: %v", err)
				}
			} else {
				//服务端处理0rtt握手, 发送临时公钥
				pri, pub, err := generateKey()
				if err != nil {
					return 0, nil
				}
				// 这是最终的共享密钥
				secret, err := generateSharedSecret(pri[:], c.pubReceived)
				if err != nil {
					return 0, nil
				}
				nonce := newRandomData(sigLen + 16)
				copy(nonce[16:16+ephPubKeyLen], pub[:])
				c.hkData = nonce

				c.sharedKey = secret
				c.changeKey = true
			}
		}
	}
	if c.changeKey {
		c.send, err = cipher.NewAESGCMBlockCipher(c.sharedKey)
		if err != nil {
			log.Fatalf("创建写加密块失败: %v", err)
		}
		c.changeKey = false
	}
	// Create encrypted payload length.
	plaintextLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(plaintextLen, uint16(len(payload)))
	encryptedLen, err := c.send.Encrypt(plaintextLen)
	if err != nil {
		return 0, fmt.Errorf("encrypt() failed: %w", err)
	}
	if len(c.hkData) != 0 {
		encryptedLen = append(c.hkData, encryptedLen...)
		c.hkData = nil
	}
	// Create encrypted payload.
	encryptedPayload, err := c.send.Encrypt(payload)
	if err != nil {
		return 0, fmt.Errorf("encrypted() failed: %w", err)
	}

	// Send encrypted payload length + encrypted payload.
	dataToSend := append(encryptedLen, encryptedPayload...)

	if _, err := io.WriteString(c.Conn, string(dataToSend)); err != nil {
		return 0, fmt.Errorf("io.WriteString() failed: %w", err)
	}
	log.Tracef("ssh conn wrote %d bytes to wire", len(b))
	return len(b), nil
}
func (c *Conn) Close() error {
	return c.Conn.Close()
}
