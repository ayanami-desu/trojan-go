package multiplex

import (
	"encoding/binary"
	"sync"
)

type SessionManage struct {
	sessionsM sync.RWMutex
	sessions  map[uint32]*Session
}

// CloseSession closes a session
func (u *SessionManage) CloseSession(sessionID uint32, reason string) {
	u.sessionsM.Lock()
	sesh, existing := u.sessions[sessionID]
	if existing {
		delete(u.sessions, sessionID)
		sesh.SetTerminalMsg(reason)
		sesh.Close()
	}
	u.sessionsM.Unlock()
}

// GetSession 若会话存在则返回，否则新建会话
func (u *SessionManage) GetSession(sessionID uint32, config SessionConfig) (sesh *Session, existing bool, err error) {
	u.sessionsM.Lock()
	defer u.sessionsM.Unlock()
	if sesh = u.sessions[sessionID]; sesh != nil {
		return sesh, true, nil
	} else {
		sesh = MakeSession(sessionID, config)
		u.sessions[sessionID] = sesh
		return sesh, false, nil
	}
}

// closeAllSessions closes all sessions of this active user
func (u *SessionManage) closeAllSessions(reason string) {
	u.sessionsM.Lock()
	for sessionID, sesh := range u.sessions {
		sesh.SetTerminalMsg(reason)
		sesh.Close()
		delete(u.sessions, sessionID)
	}
	u.sessionsM.Unlock()
}

// NumSession returns the number of active sessions
func (u *SessionManage) NumSession() int {
	u.sessionsM.RLock()
	defer u.sessionsM.RUnlock()
	return len(u.sessions)
}
func transSessionId(a []byte) uint32 {
	return binary.LittleEndian.Uint32(a)
}
