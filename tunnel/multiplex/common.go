package multiplex

import (
	"crypto/rand"
	log "github.com/sirupsen/logrus"
	"io"
	"time"
)

func cryptoRandRead(buf []byte) {
	randRead(rand.Reader, buf)
}

func randRead(randSource io.Reader, buf []byte) {
	_, err := randSource.Read(buf)
	if err == nil {
		return
	}
	waitDur := [10]time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond,
		100 * time.Millisecond, 300 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second,
		3 * time.Second, 5 * time.Second}
	for i := 0; i < 10; i++ {
		log.Errorf("Failed to get random bytes: %v. Retrying...", err)
		_, err = randSource.Read(buf)
		if err == nil {
			return
		}
		time.Sleep(waitDur[i])
	}
	log.Fatal("Cannot get random bytes after 10 retries")
}
