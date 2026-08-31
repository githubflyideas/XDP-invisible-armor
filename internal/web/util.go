package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
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

// selfActionDenied 判断 actor 是否试图对自己提交的请求执行需要四眼互斥的操作。
func selfActionDenied(actorID uint, requestedByID *uint) bool {
	return requestedByID != nil && *requestedByID == actorID
}

func (h *Handler) denySelfAction(c *gin.Context, actorID uint, actorLabel, entityType, entityID string) {
	_ = model.WriteAudit(h.db, &actorID, actorLabel, entityType, entityID,
		"self_approval_denied", "")
	c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "不能对自己提交的请求执行此操作(四眼原则)"})
}

