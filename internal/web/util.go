package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
)

var (
	errSelfApproval  = errors.New("self approval")
	errStateConflict = errors.New("state conflict")
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func itoa(u uint) string { return strconv.FormatUint(uint64(u), 10) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
