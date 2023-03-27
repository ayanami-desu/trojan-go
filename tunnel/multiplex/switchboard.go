package multiplex

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type switchboardStrategy int

const (
	fixedConnMapping switchboardStrategy = iota
)

// switchboard represents the connection pool. It is responsible for managing
// transport-layer connections between client and server.
// It has several purposes: constantly receiving incoming data from all connections
// and pass them to Session.recvDataFromRemote(); accepting data through
// switchboard.send(), in which it selects a connection according to its
// switchboardStrategy and send the data off using that; and counting, as well as
// rate limiting, data received and sent through its Valve.
type switchboard struct {
	session *Session

	strategy switchboardStrategy

	conns      sync.Map
	connsCount uint32
	randPool   sync.Pool

	broken uint32
}

func makeSwitchboard(sesh *Session) *switchboard {
	var strategy switchboardStrategy

	strategy = fixedConnMapping

	sb := &switchboard{
		session:  sesh,
		strategy: strategy,
		randPool: sync.Pool{New: func() interface{} {
			return rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
		}},
	}
	return sb
}

var errBrokenSwitchboard = errors.New("the switchboard is broken")

func (sb *switchboard) addConn(conn net.Conn) {
	atomic.AddUint32(&sb.connsCount, 1)
	sb.conns.Store(conn, conn)
	go sb.deplex(conn)
}

// a pointer to assignedConn is passed here so that the switchboard can reassign it if that conn isn't usable
func (sb *switchboard) send(data []byte, assignedConn *net.Conn) (n int, err error) {
	if atomic.LoadUint32(&sb.broken) == 1 {
		return 0, errBrokenSwitchboard
	}

	var conn net.Conn
	conn = *assignedConn
	if conn == nil {
		conn, err = sb.pickRandConn()
		if err != nil {
			log.Tracef("failed to pick a connection:%v", err)
			sb.session.SetTerminalMsg("failed to pick a connection " + err.Error())
			sb.session.passiveClose()
			return 0, err
		}
		*assignedConn = conn
	}
	n, err = conn.Write(data)
	if err != nil {
		log.Tracef("failed to send to remote: %v", err)
		sb.session.SetTerminalMsg("failed to send to remote " + err.Error())
		sb.session.passiveClose()
		return n, err
	}

	return n, nil
}

// returns a random connId
func (sb *switchboard) pickRandConn() (net.Conn, error) {
	if atomic.LoadUint32(&sb.broken) == 1 {
		return nil, errBrokenSwitchboard
	}

	connsCount := atomic.LoadUint32(&sb.connsCount)
	if connsCount == 0 {
		return nil, errBrokenSwitchboard
	}

	randReader := sb.randPool.Get().(*rand.Rand)

	r := randReader.Intn(int(connsCount))
	sb.randPool.Put(randReader)

	var c int
	var ret net.Conn
	sb.conns.Range(func(_, conn interface{}) bool {
		if r == c {
			ret = conn.(net.Conn)
			return false
		}
		c++
		return true
	})

	return ret, nil
}

// actively triggered by session.Close()
func (sb *switchboard) closeAll() {
	if !atomic.CompareAndSwapUint32(&sb.broken, 0, 1) {
		return
	}
	sb.conns.Range(func(_, conn interface{}) bool {
		conn.(net.Conn).Close()
		sb.conns.Delete(conn)
		atomic.AddUint32(&sb.connsCount, ^uint32(0))
		return true
	})
}

// deplex function costantly reads from a TCP connection
func (sb *switchboard) deplex(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, sb.session.connReceiveBufferSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Debugf("a connection for session %v has closed: %v", sb.session.id, err)
			sb.session.SetTerminalMsg("a connection has dropped unexpectedly")
			sb.session.passiveClose()
			return
		}

		err = sb.session.recvDataFromRemote(buf[:n])
		if err != nil {
			log.Error(err)
		}
	}
}
