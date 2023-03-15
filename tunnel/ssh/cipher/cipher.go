package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"sync"
)

//var (
//	_ BlockCipher = &AESGCMBlockCipher{}
//)

// AESGCMBlockCipher implements BlockCipher interface with AES-GCM algorithm.
type AESGCMBlockCipher struct {
	aead                cipher.AEAD
	enableImplicitNonce bool
	key                 []byte
	implicitNonce       []byte
	mu                  sync.Mutex
	//ctx                 BlockContext
}

// NewAESGCMBlockCipher creates a new cipher with the supplied key.
func NewAESGCMBlockCipher(key []byte) (*AESGCMBlockCipher, error) {
	if err := validateKeySize(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher() failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM() failed: %w", err)
	}

	c := &AESGCMBlockCipher{
		aead: aead,
		//enableImplicitNonce: false,
		enableImplicitNonce: true,
		key:                 key,
		implicitNonce:       nil,
	}

	return c, nil
}

// BlockSize returns the block size of cipher.
func (*AESGCMBlockCipher) BlockSize() int {
	return aes.BlockSize
}

// NonceSize returns the number of bytes used by nonce.
func (c *AESGCMBlockCipher) NonceSize() int {
	return c.aead.NonceSize()
}

func (c *AESGCMBlockCipher) Overhead() int {
	return c.aead.Overhead()
}

func (c *AESGCMBlockCipher) Encrypt(plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var nonce []byte
	var err error
	needSendNonce := true
	if c.enableImplicitNonce {
		if len(c.implicitNonce) == 0 {
			c.implicitNonce, err = c.newNonce()
			if err != nil {
				return nil, fmt.Errorf("newNonce() failed: %w", err)
			}
			// Must create a copy because nonce will be extended.
			nonce = make([]byte, len(c.implicitNonce))
			copy(nonce, c.implicitNonce)
		} else {
			c.increaseNonce()
			nonce = c.implicitNonce
			needSendNonce = false
		}
	} else {
		nonce, err = c.newNonce()
		if err != nil {
			return nil, fmt.Errorf("newNonce() failed: %w", err)
		}
	}

	dst := c.aead.Seal(nil, nonce, plaintext, nil)
	if needSendNonce {
		return append(nonce, dst...), nil
	}
	return dst, nil
}

func (c *AESGCMBlockCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var nonce []byte
	if c.enableImplicitNonce {
		if len(c.implicitNonce) == 0 {
			if len(ciphertext) < c.NonceSize() {
				return nil, fmt.Errorf("ciphertext is smaller than nonce size")
			}
			c.implicitNonce = make([]byte, c.NonceSize())
			copy(c.implicitNonce, ciphertext[:c.NonceSize()])
			ciphertext = ciphertext[c.NonceSize():]
		} else {
			c.increaseNonce()
		}
		nonce = c.implicitNonce
	} else {
		if len(ciphertext) < c.NonceSize() {
			return nil, fmt.Errorf("ciphertext is smaller than nonce size")
		}
		nonce = ciphertext[:c.NonceSize()]
		ciphertext = ciphertext[c.NonceSize():]
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cipher.AEAD.Open() failed: %w", err)
	}
	return plaintext, nil
}

func (c *AESGCMBlockCipher) Clone() BlockCipher {
	c.mu.Lock()
	defer c.mu.Unlock()
	newCipher, err := NewAESGCMBlockCipher(c.key)
	if err != nil {
		panic(err)
	}
	newCipher.enableImplicitNonce = c.enableImplicitNonce
	if len(c.implicitNonce) != 0 {
		newCipher.implicitNonce = make([]byte, len(c.implicitNonce))
		copy(newCipher.implicitNonce, c.implicitNonce)
	}
	//newCipher.ctx = c.ctx
	return newCipher
}

func (c *AESGCMBlockCipher) SetImplicitNonceMode(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enableImplicitNonce = enable
	if !enable {
		c.implicitNonce = nil
	}
}

func (c *AESGCMBlockCipher) IsStateless() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.enableImplicitNonce
}

//func (c *AESGCMBlockCipher) BlockContext() BlockContext {
//	return c.ctx
//}
//
//func (c *AESGCMBlockCipher) SetBlockContext(bc BlockContext) {
//	c.ctx = bc
//}

// newNonce generates a new nonce.
func (c *AESGCMBlockCipher) newNonce() ([]byte, error) {
	nonce := make([]byte, c.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func (c *AESGCMBlockCipher) increaseNonce() {
	if !c.enableImplicitNonce || len(c.implicitNonce) == 0 {
		panic("implicit nonce mode is not enabled")
	}
	for i := range c.implicitNonce {
		c.implicitNonce[i] += 1
		if c.implicitNonce[i] != 0 {
			break
		}
	}
}

// validateKeySize validates if key size is acceptable.
func validateKeySize(key []byte) error {
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return fmt.Errorf("AES key length is %d, want 16 or 24 or 32", keyLen)
	}
	return nil
}
