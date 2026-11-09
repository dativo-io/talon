package access

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session defaults.
const (
	DefaultSessionTTL  = 8 * time.Hour
	DefaultIdleTTL     = time.Hour
	DefaultMaxSessions = 32
	sessionIDBytes     = 32
)

// Session is one paired browser.
type Session struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

// Sessions is the in-memory, server-side session table. A console restart
// forgets every session (operators pair again); that is documented, not
// hidden. The table is bounded: the oldest session is evicted when full.
type Sessions struct {
	ttl, idle time.Duration
	max       int
	now       func() time.Time

	mu   sync.Mutex
	byID map[string]*Session
}

// NewSessions returns a table; zero values take the defaults.
func NewSessions(ttl, idle time.Duration, maxSessions int, now func() time.Time) *Sessions {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if idle <= 0 {
		idle = DefaultIdleTTL
	}
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Sessions{ttl: ttl, idle: idle, max: maxSessions, now: now, byID: map[string]*Session{}}
}

// Create mints a fresh opaque id. It never reuses a presented id (no
// fixation): the cookie is set from this value only.
func (s *Sessions) Create() (*Session, error) {
	raw := make([]byte, sessionIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	now := s.now()
	sess := &Session{ID: base64.RawURLEncoding.EncodeToString(raw), CreatedAt: now, ExpiresAt: now.Add(s.ttl), LastSeen: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	for len(s.byID) >= s.max {
		s.evictOldestLocked()
	}
	s.byID[sess.ID] = sess
	return sess, nil
}

// Validate reports whether id names a live session and touches it.
func (s *Sessions) Validate(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > s.idle {
		delete(s.byID, id)
		return nil, false
	}
	sess.LastSeen = now
	cp := *sess
	return &cp, true
}

// Revoke forgets id; revoking an unknown id is not an error.
func (s *Sessions) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// Len is the number of sessions held (for tests and the System page).
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	return len(s.byID)
}

func (s *Sessions) pruneLocked(now time.Time) {
	for id, sess := range s.byID {
		if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > s.idle {
			delete(s.byID, id)
		}
	}
}

func (s *Sessions) evictOldestLocked() {
	var oldest *Session
	for _, sess := range s.byID {
		if oldest == nil || sess.LastSeen.Before(oldest.LastSeen) {
			oldest = sess
		}
	}
	if oldest != nil {
		delete(s.byID, oldest.ID)
	}
}
