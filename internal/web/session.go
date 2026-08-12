package web

import (
	"sync"
	"time"
)

type sessionStore struct {
	mu   sync.RWMutex
	data map[string]sessionEntry
	ttl  time.Duration
}

type sessionEntry struct {
	userID    uint
	expiresAt time.Time
}

func newSessionStore(ttl time.Duration) *sessionStore {
	s := &sessionStore{
		data: make(map[string]sessionEntry),
		ttl:  ttl,
	}
	go s.reaper()
	return s
}

func (s *sessionStore) Put(token string, userID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[token] = sessionEntry{userID: userID, expiresAt: time.Now().Add(s.ttl)}
}

func (s *sessionStore) Get(token string) (uint, bool) {
	s.mu.RLock()
	e, ok := s.data[token]
	s.mu.RUnlock()

	if !ok {
		return 0, false
	}
	if time.Now().After(e.expiresAt) {
		s.Delete(token)
		return 0, false
	}
	return e.userID, true
}

func (s *sessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

func (s *sessionStore) DeleteByUser(userID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, e := range s.data {
		if e.userID == userID {
			delete(s.data, tok)
		}
	}
}

func (s *sessionStore) OnlineUsers() map[uint]bool {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[uint]bool, len(s.data))
	for _, e := range s.data {
		if now.Before(e.expiresAt) {
			out[e.userID] = true
		}
	}
	return out
}

func (s *sessionStore) reaper() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for tok, e := range s.data {
			if now.After(e.expiresAt) {
				delete(s.data, tok)
			}
		}
		s.mu.Unlock()
	}
}
