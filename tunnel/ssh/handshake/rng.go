package handshake

import (
	"crypto/sha256"
	"encoding/binary"
	"hash/maphash"
	"math"
	mrand "math/rand"
	"os"
	"sync"
	"sync/atomic"
)

var (
	once           sync.Once
	hostFixedValue atomic.Value
	r              *mrand.Rand
)

// InitSeed initializes the random seed.
func initSeed() {
	once.Do(func() {
		r = mrand.New(mrand.NewSource(int64(new(maphash.Hash).Sum64())))
	})
}

// Intn returns a random int from [0, n) with scale down distribution.
func intn(n int) int {
	return int(float64(r.Intn(n+1)) * scaleDown())
}

// IntRange returns a random int from [m, n) with scale down distribution.
func intRange(m, n int) int {
	return m + intn(n-m)
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
	base := r.Float64()
	return math.Sqrt(base * base * base)
}
