package http2

import (
	"context"
	"github.com/p4gefau1t/trojan-go/tunnel"
	icommon "github.com/p4gefau1t/trojan-go/tunnel/http2/common"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal/done"
	"io"
	"net"
	"net/http"
	"time"
)

type Conn struct {
	net.Conn
	metadata *tunnel.Metadata
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}
func parseHost(s string) (*tunnel.Metadata, error) {
	flag := s[0:1]
	var c tunnel.Command
	switch flag {
	case "c":
		c = tunnel.Command(1)
	case "a":
		c = tunnel.Command(3)
	default:
		log.Errorf("http2 server unknown command %s", flag)
	}
	addr, err := tunnel.NewAddressFromAddr("tcp", s[1:])
	if err != nil {
		return nil, err
	}
	return &tunnel.Metadata{
		Command: c,
		Address: addr,
	}, nil
}

type flushWriter struct {
	w io.Writer
	d *done.Instance
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	if fw.d.Done() {
		return 0, io.ErrClosedPipe
	}

	defer func() {
		if recover() != nil {
			fw.d.Close()
			err = io.ErrClosedPipe
		}
	}()

	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok && err == nil {
		f.Flush()
	}
	return
}

type waitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser
}

func (w *waitReadCloser) Set(rc io.ReadCloser) {
	w.ReadCloser = rc
	defer func() {
		if recover() != nil {
			rc.Close()
		}
	}()
	close(w.Wait)
}

func (w *waitReadCloser) Read(b []byte) (int, error) {
	if w.ReadCloser == nil {
		if <-w.Wait; w.ReadCloser == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return w.ReadCloser.Read(b)
}

func (w *waitReadCloser) Close() error {
	if w.ReadCloser != nil {
		return w.ReadCloser.Close()
	}
	defer func() {
		if recover() != nil && w.ReadCloser != nil {
			w.ReadCloser.Close()
		}
	}()
	close(w.Wait)
	return nil
}

type connection struct {
	reader  *buf.BufferedReader
	writer  buf.Writer
	done    *done.Instance
	onClose io.Closer
	local   net.Addr
	remote  net.Addr
}

func newConnection(r io.Reader, w io.Writer, c io.Closer) net.Conn {
	reader := &buf.BufferedReader{Reader: buf.NewReader(r)}
	writer := buf.NewWriter(w)
	return &connection{
		reader: reader,
		writer: writer,
		done:   done.New(),
	}
}

func (c *connection) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// ReadMultiBuffer implements buf.Reader.
func (c *connection) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return c.reader.ReadMultiBuffer()
}

// Write implements net.Conn.Write().
func (c *connection) Write(b []byte) (int, error) {
	if c.done.Done() {
		return 0, io.ErrClosedPipe
	}

	l := len(b)
	mb := make(buf.MultiBuffer, 0, l/buf.Size+1)
	mb = buf.MergeBytes(mb, b)
	return l, c.writer.WriteMultiBuffer(mb)
}

func (c *connection) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if c.done.Done() {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}

	return c.writer.WriteMultiBuffer(mb)
}

// Close implements net.Conn.Close().
func (c *connection) Close() error {
	icommon.Must(c.done.Close())
	icommon.Interrupt(c.reader)
	icommon.Close(c.writer)
	if c.onClose != nil {
		return c.onClose.Close()
	}
	return nil
}

// LocalAddr implements net.Conn.LocalAddr().
func (c *connection) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr implements net.Conn.RemoteAddr().
func (c *connection) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline implements net.Conn.SetDeadline().
func (c *connection) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline().
func (c *connection) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline().
func (c *connection) SetWriteDeadline(t time.Time) error {
	return nil
}

type listen struct {
	server tunnel.Server
	cancel context.CancelFunc
}

func (l *listen) Accept() (net.Conn, error) {
	return l.server.AcceptConn(nil)
}
func (l *listen) Close() error {
	l.cancel()
	return l.server.Close()
}
func (l *listen) Addr() net.Addr {
	return nil
}
