package mux

import (
	"github.com/p4gefau1t/trojan-go/tunnel"
	"io"
)

type Conn struct {
	rwc io.ReadWriteCloser
	tunnel.Conn
	//buf []byte
}

func (c *Conn) Read(p []byte) (int, error) {
	//if len(c.buf) > 0 {
	//	n := copy(p, c.buf)
	//	c.buf = c.buf[n:]
	//	return n, nil
	//}
	return c.rwc.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	return c.rwc.Write(p)
}

func (c *Conn) Close() error {
	return c.rwc.Close()
}
