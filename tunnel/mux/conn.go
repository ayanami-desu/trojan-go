package mux

import (
	"github.com/p4gefau1t/trojan-go/tunnel"
	"io"
)

type Conn struct {
	rwc io.ReadWriteCloser
	tunnel.Conn
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.rwc.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.rwc.Write(p)
}

func (c *Conn) Close() error {
	return c.rwc.Close()
}
