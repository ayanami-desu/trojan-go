package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"sync"
)

type selfAuthInfo struct {
	Entropy   []byte
	SessionId []byte
	EphPub    [32]byte
	EphPri    [32]byte
	SharedKey []byte
}

type otherAuthInfo struct {
	Entropy   []byte
	SessionId []byte
	EphPub    [32]byte
	IsFastly  bool
}

type authInfo struct {
	PrivateKey   []byte
	PublicKey    []byte
	SessionId    []byte
	FastHkEnable bool
}
type tokenPool struct {
	mu     sync.Mutex
	Tokens map[uint32]*token
}
type token struct {
	Pri []byte
	Pub []byte
}

var (
	AuthInfo  *authInfo
	TokenPool *tokenPool
)

func (p *tokenPool) clear() {
	p.mu.Lock()
	p.Tokens = make(map[uint32]*token)
	p.mu.Unlock()
}
func (p *tokenPool) add(pub []byte) error {
	if len(pub) == 0 {
		return fmt.Errorf("pub can not be nil")
	}
	id := binary.LittleEndian.Uint32(pub[:4])
	p.mu.Lock()
	p.Tokens[id] = &token{
		Pub: pub,
	}
	p.mu.Unlock()
	return nil
}
func (p *tokenPool) create() uint32 {
	//调用此函数时应加锁
	pri, pub, err := generateKey()
	if err != nil {
		log.Fatal(err)
	}
	id := binary.LittleEndian.Uint32(pub[:4])
	p.Tokens[id] = &token{
		Pri: pri[:],
		Pub: pub[:],
	}
	return id
}
func (p *tokenPool) pickPub() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.Tokens {
		return v.Pub, nil
	}
	return nil, fmt.Errorf("no token exists")
}
func (p *tokenPool) pickOrCreatePub() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.Tokens {
		return v.Pub
	}
	id := p.create()
	return p.Tokens[id].Pub
}
func (p *tokenPool) pickPri() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.Tokens {
		return v.Pri, nil
	}
	return nil, fmt.Errorf("no pri key exists")
}

func encrypte(clearText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher() failed: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM() failed: %w", err)
	}
	if len(key) < aead.NonceSize() {
		return nil, fmt.Errorf("nonce size should be %v bytes", aead.NonceSize())
	}
	dst := aead.Seal(nil, key[:aead.NonceSize()], clearText, nil)
	return dst, nil
}
func decrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher() failed: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM() failed: %w", err)
	}
	if len(key) < aead.NonceSize() {
		return nil, fmt.Errorf("nonce size should be %v bytes", aead.NonceSize())
	}
	dst, err := aead.Open(nil, key[:aead.NonceSize()], cipherText, nil)
	if err != nil {
		return nil, err
	}
	return dst, nil
}
