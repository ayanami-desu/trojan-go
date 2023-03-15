package ssh

import (
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/ssh/handshake"
)

type Conn struct {
	*handshake.Conn
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return nil
}
func (c *Conn) GetSessionId() []byte {
	return c.SessionId
}
