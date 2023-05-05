package mux

import (
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/sagernet/smux"
	"time"
)

var (
	maxConnTime time.Duration
)

type smuxClientInfo struct {
	client         *smux.Session
	lastActiveTime time.Time
	createdTime    time.Time
	underlayConn   tunnel.Conn
}

func (s *smuxClientInfo) CanTakeStream() bool {
	flag := true
	if time.Since(s.createdTime) > maxConnTime {
		flag = false
	}
	return flag
}

func (s *smuxClientInfo) NumStreams() int {
	return s.client.NumStreams()
}

type abstractSession interface {
	CanTakeStream() bool
	NumStreams() int
}
