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
	PrivateKey []byte
	PublicKey  []byte
	SessionId  []byte
}
type tokenPool struct {
	sync.Mutex
	Tokens map[uint32]*token
}
type token struct {
	Key     []byte
	Content []byte
}

var (
	AuthInfo  *authInfo
	TokenPool *tokenPool
)

func (p *tokenPool) getOrCreate(key []byte) ([]byte, error) {
	p.Lock()
	defer p.Unlock()
	if len(key) == 0 {
		return nil, fmt.Errorf("key can not be nil")
	}
	for _, v := range p.Tokens {
		return v.Content, nil
	}
	contentLen := intRange(128, 228) // 256 - NonceSize - authentication tag
	content := make([]byte, contentLen)
	readRand(&content)
	id := binary.LittleEndian.Uint32(content[:4])
	p.Tokens[id] = &token{
		Key:     key,
		Content: content,
	}
	return content, nil
}
func (p *tokenPool) add(key, content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("token content can not be nil")
	}
	id := binary.LittleEndian.Uint32(content[:4])
	p.Lock()
	p.Tokens[id] = &token{
		Key:     key,
		Content: content,
	}
	p.Unlock()
	return nil
}
func (p *tokenPool) remove(id uint32) {
	p.Lock()
	delete(p.Tokens, id)
	p.Unlock()
}
func (p *tokenPool) pick() ([]byte, error) {
	p.Lock()
	defer p.Unlock()
	for id, v := range p.Tokens {
		delete(p.Tokens, id)
		return v.Content, nil
	}
	return nil, fmt.Errorf("no token exists")
}
func (p *tokenPool) get(id uint32) ([]byte, error) {
	p.Lock()
	defer p.Unlock()
	if t, ok := p.Tokens[id]; ok {
		return t.Content, nil
	} else {
		return nil, fmt.Errorf("target %d token does not exist", id)
	}
}
func (p *tokenPool) tryGet(id uint32) bool {
	p.Lock()
	defer p.Unlock()
	if _, ok := p.Tokens[id]; ok {
		delete(p.Tokens, id)
		return ok
	} else {
		return !ok
	}
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
func Init(pri, pub string) {
	priK, pubK, err := loadKeyPair(pri, pub)
	if err != nil {
		log.Fatal(err)
	}
	AuthInfo = &authInfo{
		PrivateKey: priK,
		PublicKey:  pubK,
	}
	initSeed()
	TokenPool = &tokenPool{
		Tokens: make(map[uint32]*token),
	}
}
