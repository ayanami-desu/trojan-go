package ssh

import (
	"github.com/p4gefau1t/trojan-go/tunnel"
	"net"
)

type Conn struct {
	net.Conn
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return nil
}

func (c *Conn) GetSessionId() []byte {
	panic("implement me")
}
