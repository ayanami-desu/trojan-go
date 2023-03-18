package handshake

import (
	"fmt"
	"testing"
)

func TestRng(t *testing.T) {
	rngWithoutInit(t)
	rngWithInit(t)
}
func rngWithoutInit(t *testing.T) {
	ls1 := generate()
	ls2 := generate()
	for i := 0; i < 10; i++ {
		if ls1[i] != ls2[i] {
			fmt.Printf("test 2 failed")
			t.Fail()
			break
		}
	}
}

func generate() []int {
	list := make([]int, 10)
	for i := 0; i < 10; i++ {
		list[i] = intRange(baseWriteChunkSize, maxWriteChunkSize)
	}
	return list
}
func rngWithInit(t *testing.T) {
	InitSeed()
	a, b := 0, intRange(baseWriteChunkSize, maxWriteChunkSize)
	for i := 0; i < 10; i++ {
		a = intRange(baseWriteChunkSize, maxWriteChunkSize)
		if a == b {
			fmt.Printf("test 2 failed")
			t.Fail()
			break
		}
		b = a
	}
}
