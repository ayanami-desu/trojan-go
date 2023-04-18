package handshake

import (
	"crypto/rand"
	"github.com/p4gefau1t/trojan-go/common"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

func newRandomData(length int) []byte {
	p := make([]byte, length)
	for {
		if _, err := rand.Read(p); err == nil {
			break
		}
	}
	return p
}

func readRand(p *[]byte) {
	for {
		if _, err := io.ReadFull(rand.Reader, *p); err == nil {
			break
		}
	}
}

func xorBytes(p []byte, key byte) []byte {
	for i, v := range p {
		p[i] = v ^ key
	}
	return p
}

// readAfterError continues to read some data from the TCP connection after
// an error happened due to possible attack.
func readAfterError(conn net.Conn) {
	// Set TCP read deadline to avoid being blocked forever.
	timeoutMillis := common.IntRange(1000, 5000)
	timeoutMillis += common.FixedInt(60000) // Maximum 60 seconds.
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMillis) * time.Millisecond))

	// Determine the read buffer size.
	bufSizeType := common.FixedInt(4)
	bufSize := 1 << (12 + bufSizeType) // 4, 8, 16, 32 KB
	buf := make([]byte, bufSize)

	// Determine the number of bytes to read.
	// Minimum 2 bytes, maximum 1280 bytes.
	min := common.IntRange(2, 1026)
	min += common.FixedInt(256)

	n, err := io.ReadAtLeast(conn, buf, min)
	if err != nil {
		log.Debugf("handshake [%v - %v] read after error failed to complete: %v", conn.LocalAddr(), conn.RemoteAddr(), err)
	} else {
		log.Debugf("handshake [%v - %v] read at least %d bytes after error", conn.LocalAddr(), conn.RemoteAddr(), n)
	}
}

type HkFunc interface {
	HandShake(conn net.Conn) (net.Conn, error)
	HandleHandShake(conn net.Conn) (net.Conn, error)
}

func Init(pri, pub string, rtt int) HkFunc {
	priK, pubK, err := loadKeyPair(pri, pub)
	if err != nil {
		log.Fatal(err)
	}
	auth = &authInfo{
		PrivateKey: priK,
		PublicKey:  pubK,
	}
	var hk HkFunc
	switch rtt {
	case OneRtt:
		hk = &oneRtt{auth}
	case TwoRtt:
		hk = &twoRtt{auth}
	default:
		log.Fatal("unknown handshake method")
	}
	return hk
}
