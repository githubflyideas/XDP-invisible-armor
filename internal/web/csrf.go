package web

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) requireCSRF(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return
	}

	tok, err := c.Cookie("sid")
	if err != nil {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "会话缺失,请重新登录"})
		c.Abort()
		return
	}
	want, ok := h.sessions.CSRFToken(tok)
	if !ok {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "会话缺失,请重新登录"})
		c.Abort()
		return
	}

	got := c.PostForm("csrf_token")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"msg": "CSRF 校验失败,请刷新页面重试"})
		c.Abort()
		return
	}
}
