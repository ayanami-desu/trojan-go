package socks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	log "github.com/sirupsen/logrus"
)

const (
	Connect   tunnel.Command = 1
	Associate tunnel.Command = 3
)

const (
	MaxPacketSize = 1024 * 8
)

type Server struct {
	connChan         chan tunnel.Conn
	packetChan       chan tunnel.PacketConn
	underlay         tunnel.Server
	localHost        string
	localPort        int
	UDPEnable        bool
	timeout          time.Duration
	listenPacketConn tunnel.PacketConn
	mapping          map[string]*PacketConn
	mappingLock      sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("socks server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case conn := <-s.packetChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("socks server closed")
	}
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) handshake(conn net.Conn) (*Conn, error) {
	version := [1]byte{}
	if _, err := conn.Read(version[:]); err != nil {
		return nil, common.NewError("failed to read socks version").Base(err)
	}
	if version[0] != 5 {
		return nil, common.NewError(fmt.Sprintf("invalid socks version %d", version[0]))
	}
	nmethods := [1]byte{}
	if _, err := conn.Read(nmethods[:]); err != nil {
		return nil, common.NewError("failed to read NMETHODS")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(nmethods[0])); err != nil {
		return nil, common.NewError("socks failed to read methods").Base(err)
	}
	if _, err := conn.Write([]byte{0x5, 0x0}); err != nil {
		return nil, common.NewError("failed to respond auth").Base(err)
	}

	buf := [3]byte{}
	if _, err := conn.Read(buf[:]); err != nil {
		return nil, common.NewError("failed to read command")
	}

	addr := new(tunnel.Address)
	if err := addr.ReadFrom(conn); err != nil {
		return nil, err
	}
	addr.NetworkType = "tcp"
	return &Conn{
		metadata: &tunnel.Metadata{
			Command: tunnel.Command(buf[1]),
			Address: addr,
		},
		Conn: conn,
	}, nil
}

func (s *Server) connect(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func (s *Server) associate(conn net.Conn, addr *tunnel.Address) error {
	buf := bytes.NewBuffer([]byte{0x05, 0x00, 0x00})
	common.Must(addr.WriteTo(buf))
	_, err := conn.Write(buf.Bytes())
	return err
}

func (s *Server) packetDispatchLoop() {
	for {
		buf := make([]byte, MaxPacketSize)
		n, src, err := s.listenPacketConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				log.Debugf("exiting")
				return
			default:
				continue
			}
		}
		log.Debugf("socks recv udp packet from %v", src)
		s.mappingLock.RLock()
		conn, found := s.mapping[src.String()]
		s.mappingLock.RUnlock()
		if !found {
			ctx, cancel := context.WithCancel(s.ctx)
			conn = &PacketConn{
				input:      make(chan *packetInfo, 128),
				output:     make(chan *packetInfo, 128),
				ctx:        ctx,
				cancel:     cancel,
				PacketConn: s.listenPacketConn,
				src:        src,
			}
			go func(conn *PacketConn) {
				defer conn.Close()
				for {
					select {
					case info := <-conn.output:
						buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
						buf.Write([]byte{0, 0, 0}) // RSV, FRAG
						common.Must(info.metadata.Address.WriteTo(buf))
						buf.Write(info.payload)
						_, err := s.listenPacketConn.WriteTo(buf.Bytes(), conn.src)
						if err != nil {
							log.Errorf("socks failed to respond packet to %v", src)
							return
						}
						log.Debugf("socks respond udp packet to %v metadata", info.metadata)
					case <-time.After(time.Second * 5):
						log.Infof("socks udp session timeout, closed")
						s.mappingLock.Lock()
						delete(s.mapping, src.String())
						s.mappingLock.Unlock()
						return
					case <-conn.ctx.Done():
						log.Infof("socks udp session closed")
						return
					}
				}
			}(conn)

			s.mappingLock.Lock()
			s.mapping[src.String()] = conn
			s.mappingLock.Unlock()

			s.packetChan <- conn
			log.Infof("socks new udp session from %v", src)
		}
		r := bytes.NewBuffer(buf[3:n])
		address := new(tunnel.Address)
		if err := address.ReadFrom(r); err != nil {
			log.Errorf(common.NewError("socks failed to parse incoming packet").Base(err).Error())
			continue
		}
		payload := make([]byte, MaxPacketSize)
		length, _ := r.Read(payload)
		select {
		case conn.input <- &packetInfo{
			metadata: &tunnel.Metadata{
				Address: address,
			},
			payload: payload[:length],
		}:
		default:
			log.Warnf("socks udp queue full")
		}
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			log.Errorf(common.NewError("socks accept err").Base(err).Error())
			return
		}
		go func(conn net.Conn) {
			newConn, err := s.handshake(conn)
			if err != nil {
				log.Errorf(common.NewError("socks failed to handshake with client").Base(err).Error())
				return
			}
			log.Infof("socks connection from %v metadata %v", conn.RemoteAddr(), newConn.metadata.String())
			switch newConn.metadata.Command {
			case Connect:
				if err := s.connect(newConn); err != nil {
					log.Errorf(common.NewError("socks failed to respond CONNECT").Base(err).Error())
					newConn.Close()
					return
				}
				s.connChan <- newConn
				return
			case Associate:
				defer newConn.Close()
				if !s.UDPEnable {
					return
				}
				associateAddr := tunnel.NewAddressFromHostPort("udp", s.localHost, s.localPort)
				if err := s.associate(newConn, associateAddr); err != nil {
					log.Errorf(common.NewError("socks failed to respond to associate request").Base(err).Error())
					return
				}
				buf := [16]byte{}
				newConn.Read(buf[:])
				log.Debugf("socks udp session ends")
			default:
				log.Errorf(common.NewError(fmt.Sprintf("unknown socks command %d", newConn.metadata.Command)).Error())
				newConn.Close()
			}
		}(conn)
	}
}

// NewServer create a socks server
func NewServer(ctx context.Context, underlay tunnel.Server) (tunnel.Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	listenPacketConn, err := underlay.AcceptPacket(&Tunnel{})
	if err != nil {
		return nil, common.NewError("socks failed to listen packet from underlying server")
	}
	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay:         underlay,
		ctx:              ctx,
		cancel:           cancel,
		connChan:         make(chan tunnel.Conn, 32),
		packetChan:       make(chan tunnel.PacketConn, 32),
		localHost:        cfg.LocalHost,
		localPort:        cfg.LocalPort,
		UDPEnable:        cfg.UDPEnable,
		timeout:          time.Duration(cfg.UDPTimeout) * time.Second,
		listenPacketConn: listenPacketConn,
		mapping:          make(map[string]*PacketConn),
	}
	go server.acceptLoop()
	go server.packetDispatchLoop()
	log.Debug("socks server created")
	return server, nil
}
