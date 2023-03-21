package handshake

import (
	"crypto/sha256"
	"encoding/binary"
	mrand "math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var once sync.Once

var hostFixedValue atomic.Value

// InitSeed initializes the random seed.
func initSeed() {
	once.Do(func() {
		mrand.Seed(time.Now().UnixNano())
	})
}

// Intn returns a random int from [0, n) with scale down distribution.
func intn(n int) int {
	return int(float64(mrand.Intn(n+1)) * scaleDown())
}

// Int63n returns a random int64 from [0, n) with scale down distribution.
func int63n(n int64) int64 {
	return int64(float64(mrand.Int63n(n+1)) * scaleDown())
}

// IntRange returns a random int from [m, n) with scale down distribution.
func intRange(m, n int) int {
	return m + intn(n-m)
}

// IntRange64 returns a random int64 from [m, n) with scale down distribution.
func intRange64(m, n int64) int64 {
	return m + int63n(n-m)
}

// RandTime returns a random time from [begin, end) with scale down distribution.
func randTime(begin, end time.Time) time.Time {
	beginNano := begin.UnixNano()
	endNano := end.UnixNano()
	randNano := intRange64(beginNano, endNano)
	randSec := randNano / 1000000000
	randNano = randNano % 1000000000
	return time.Unix(randSec, randNano)
}

// FixedInt returns an integer in [0, n) that always stays the same within one machine.
func fixedInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, ok := hostFixedValue.Load().(int)
	if !ok {
		name, err := os.Hostname()
		if err != nil {
			name = ""
		}
		b := sha256.Sum256([]byte(name))
		b[0] = b[0] & 0b01111111
		v = int(binary.BigEndian.Uint32(b[:4]))
		hostFixedValue.Store(v)
	}
	return v % n
}

// scaleDown returns a random number from [0.0, 1.0), where
// a smaller number has higher probability to occur compared to a bigger number.
func scaleDown() float64 {
	base := mrand.Float64()
	return base * base
}
