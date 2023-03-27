package http2

import (
	"context"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/tunnel"
	icommon "github.com/p4gefau1t/trojan-go/tunnel/http2/common"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/signal/done"
	nhttp2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	nhttp "net/http"
	"time"
)

type Server struct {
	ReadHeaderTimeout time.Duration
	listener          *listen
	//http2Server       *nhttp2.Server
	underlay tunnel.Server
	connChan chan tunnel.Conn
	ctx      context.Context
	cancel   context.CancelFunc
}

func (s *Server) serveHttp(writer nhttp.ResponseWriter, request *nhttp.Request) {
	metadata, err := parseHost(request.Host)
	if err != nil {
		log.Errorf("parse host to metadata failed %v", err)
		return
	}
	writer.WriteHeader(200)
	writer.Header().Set("Cache-Control", "no-store")
	if f, ok := writer.(nhttp.Flusher); ok {
		f.Flush()
	}
	doneD := done.New()
	conn := newConnection(request.Body,
		flushWriter{w: writer, d: doneD},
		icommon.ChainedClosable{doneD, request.Body},
	)
	s.connChan <- &Conn{
		Conn:     conn,
		metadata: metadata,
	}
	<-doneD.Wait()
}

//func (s *Server) acceptConnWorker() {
//	for {
//		conn, err := s.underlay.AcceptConn(&Tunnel{})
//		if err != nil {
//			log.Debug(err)
//			select {
//			case <-s.ctx.Done():
//				return
//			default:
//			}
//			continue
//		}
//		go func(conn tunnel.Conn) {
//			s.http2Server.ServeConn(conn, &nhttp2.ServeConnOpts{
//				Handler: nhttp.HandlerFunc(s.serveHttp),
//			})
//		}(conn)
//	}
//}

func (s *Server) acceptConnWorkerOne() {
	h2s := &nhttp2.Server{}

	handler := nhttp.HandlerFunc(s.serveHttp)

	server := &nhttp.Server{
		Handler:           h2c.NewHandler(handler, h2s),
		ReadHeaderTimeout: s.ReadHeaderTimeout,
	}
	if err := server.Serve(s.listener); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("http2 server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}
func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	l := &listen{
		server: underlay,
		cancel: cancel,
	}
	server := &Server{
		underlay: underlay,
		listener: l,
		//http2Server:       &nhttp2.Server{},
		ReadHeaderTimeout: time.Duration(cfg.Http2.TimeOut) * time.Second,
		connChan:          make(chan tunnel.Conn, 32),
		ctx:               ctx,
		cancel:            cancel,
	}
	go server.acceptConnWorkerOne()
	log.Debug("http2 server created")
	return server, nil
}
