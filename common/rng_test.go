package common

import (
	"fmt"
	"testing"
)

const (
	down = 100
	up   = 10000
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
		list[i] = IntRange(down, up)
	}
	return list
}
func rngWithInit(t *testing.T) {
	InitSeed()
	a, b := 0, IntRange(down, up)
	for i := 0; i < 10; i++ {
		a = IntRange(down, up)
		if a == b {
			fmt.Printf("test 2 failed")
			t.Fail()
			break
		}
		b = a
	}
}
