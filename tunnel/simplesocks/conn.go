package simplesocks

import (
	"bytes"
	"encoding/binary"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
)

const (
	MaxPacketSize = 1024 * 8
)

// Conn is a simplesocks connection
type Conn struct {
	tunnel.Conn
	metadata      *tunnel.Metadata
	metadataBuf   *bytes.Buffer
	isOutbound    bool
	headerWritten bool
	writeMetadata bool
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *Conn) Write(payload []byte) (int, error) {
	if c.isOutbound && !c.headerWritten && c.writeMetadata {
		c.metadataBuf.Write(payload)
		_, err := c.Conn.Write(c.metadataBuf.Bytes())
		if err != nil {
			return 0, common.NewError("failed to write simplesocks header").Base(err)
		}
		c.headerWritten = true
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}

func metadataToBytes(metadata *tunnel.Metadata) (*bytes.Buffer, error) {
	//buf := bytes.NewBuffer(make([]byte, 0, 4096))
	buf := new(bytes.Buffer)
	if err := metadata.WriteTo(buf); err != nil {
		return nil, common.NewError("failed to write metadata into buf").Base(err)
	}
	return buf, nil
}

type PacketConn struct {
	tunnel.Conn
}

func (c *PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	return c.ReadWithMetadata(payload)
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	address, err := tunnel.NewAddressFromAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	m := &tunnel.Metadata{
		Address: address,
	}
	return c.WriteWithMetadata(payload, m)
}

func (c *PacketConn) WriteWithMetadata(payload []byte, metadata *tunnel.Metadata) (int, error) {
	packet := make([]byte, 0, MaxPacketSize)
	w := bytes.NewBuffer(packet)
	metadata.Address.WriteTo(w)

	length := len(payload)
	lengthBuf := [2]byte{}
	crlf := [2]byte{0x0d, 0x0a}

	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	w.Write(lengthBuf[:])
	w.Write(crlf[:])
	w.Write(payload)

	_, err := c.Conn.Write(w.Bytes())

	log.Debugf("udp packet remote %v metadata %v size %d", c.RemoteAddr(), metadata, length)
	return len(payload), err
}

func (c *PacketConn) ReadWithMetadata(payload []byte) (int, *tunnel.Metadata, error) {
	addr := &tunnel.Address{
		NetworkType: "udp",
	}
	if err := addr.ReadFrom(c.Conn); err != nil {
		return 0, nil, common.NewError("failed to parse udp packet addr").Base(err)
	}
	lengthBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lengthBuf[:]); err != nil {
		return 0, nil, common.NewError("failed to read length")
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))

	crlf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, crlf[:]); err != nil {
		return 0, nil, common.NewError("failed to read crlf")
	}

	if len(payload) < length || length > MaxPacketSize {
		io.CopyN(io.Discard, c.Conn, int64(length)) // drain the rest of the packet
		return 0, nil, common.NewError("incoming packet size is too large")
	}

	if _, err := io.ReadFull(c.Conn, payload[:length]); err != nil {
		return 0, nil, common.NewError("failed to read payload")
	}

	log.Debugf("udp packet from %v metadata %s size %d", c.RemoteAddr(), addr.String(), length)
	return length, &tunnel.Metadata{
		Address: addr,
	}, nil
}
