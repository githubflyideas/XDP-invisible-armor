package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
)

const minPasswordLen = 8

func (h *Handler) usersList(c *gin.Context) {
	h.renderUsers(c, http.StatusOK, "", "")
}

func (h *Handler) renderUsers(c *gin.Context, code int, errMsg, okMsg string) {
	u := h.currentUser(c)
	var users []model.User
	h.db.Order("id asc").Find(&users)

	c.HTML(code, "users.html", gin.H{
		"u": u, "nav": policy.NavSections(u.Role),
		"users":  users,
		"online": h.sessions.OnlineUsers(),
		"err":    errMsg,
		"ok":     okMsg,
		"csrf":   h.csrfTokenFor(c),
	})
}

func (h *Handler) userCreate(c *gin.Context) {
	actor := h.currentUser(c)

	username := strings.TrimSpace(c.PostForm("username"))
	email := strings.TrimSpace(c.PostForm("email"))
	role := strings.TrimSpace(c.PostForm("role"))
	password := c.PostForm("password")

	if username == "" {
		h.renderUsers(c, http.StatusBadRequest, "用户名不能为空", "")
		return
	}
	if !validRole(role) {
		h.renderUsers(c, http.StatusBadRequest, "非法角色: "+role, "")
		return
	}
	if len(password) < minPasswordLen {
		h.renderUsers(c, http.StatusBadRequest,
			fmt.Sprintf("密码至少 %d 位", minPasswordLen), "")
		return
	}

	var n int64
	h.db.Model(&model.User{}).Where("username = ?", username).Count(&n)
	if n > 0 {
		h.renderUsers(c, http.StatusConflict, "用户名已存在: "+username, "")
		return
	}

	nu := &model.User{
		Username: username, Email: email, Role: role,
		Active: true, AuthSource: "local",
	}
	if err := nu.SetPassword(password); err != nil {
		h.renderUsers(c, http.StatusInternalServerError, "设置密码失败: "+err.Error(), "")
		return
	}
	if err := h.db.Create(nu).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(nu.ID),
		"created", fmt.Sprintf("username=%s role=%s", username, role))
	h.renderUsers(c, http.StatusOK, "", "已创建用户 "+username+"(角色 "+role+")")
}

func (h *Handler) userChangeRole(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	role := strings.TrimSpace(c.PostForm("role"))
	if !validRole(role) {
		h.renderUsers(c, http.StatusBadRequest, "非法角色: "+role, "")
		return
	}
	if role == target.Role {
		h.renderUsers(c, http.StatusOK, "", "")
		return
	}

	if target.Role == "admin" && role != "admin" && h.countActiveAdmins(target.ID) == 0 {
		h.renderUsers(c, http.StatusConflict,
			"不能降级最后一个启用的 admin —— 系统将失去管理能力", "")
		return
	}

	old := target.Role
	if err := h.db.Model(target).Update("role", role).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	h.sessions.DeleteByUser(target.ID)

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		"role_changed", fmt.Sprintf("%s: %s → %s", target.Username, old, role))
	h.renderUsers(c, http.StatusOK, "",
		fmt.Sprintf("%s 的角色已改为 %s(需重新登录)", target.Username, role))
}

func (h *Handler) userToggleActive(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	if target.ID == actor.ID {
		h.renderUsers(c, http.StatusForbidden,
			"不能停用自己的账号 —— 那会把你锁在系统外面", "")
		return
	}

	if target.Active && target.Role == "admin" && h.countActiveAdmins(target.ID) == 0 {
		h.renderUsers(c, http.StatusConflict,
			"不能停用最后一个启用的 admin", "")
		return
	}

	newState := !target.Active
	if err := h.db.Model(target).Update("active", newState).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	verb := "enabled"
	msg := "已启用 " + target.Username
	if !newState {
		verb = "disabled"
		msg = "已停用 " + target.Username + ",其会话已吊销"

		h.sessions.DeleteByUser(target.ID)
	}

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		verb, target.Username)
	h.renderUsers(c, http.StatusOK, "", msg)
}

func (h *Handler) userDelete(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	if target.ID == actor.ID {
		h.renderUsers(c, http.StatusForbidden, "不能删除自己的账号", "")
		return
	}
	if target.Role == "admin" && h.countActiveAdmins(target.ID) == 0 {
		h.renderUsers(c, http.StatusConflict, "不能删除最后一个启用的 admin", "")
		return
	}

	name := target.Username

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		"deleted", name)

	if err := h.db.Delete(target).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}
	h.sessions.DeleteByUser(target.ID)

	h.renderUsers(c, http.StatusOK, "",
		"已删除用户 "+name+"(其历史封禁记录保留在审计中)")
}

func (h *Handler) userChangePassword(c *gin.Context) {
	actor := h.currentUser(c)

	target, ok := h.loadTargetUser(c)
	if !ok {
		return
	}
	newPwd := c.PostForm("password")
	if len(newPwd) < minPasswordLen {
		h.renderUsers(c, http.StatusBadRequest,
			fmt.Sprintf("密码至少 %d 位", minPasswordLen), "")
		return
	}

	if err := target.SetPassword(newPwd); err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}
	if err := h.db.Model(target).Update("password_hash", target.PasswordHash).Error; err != nil {
		h.renderUsers(c, http.StatusInternalServerError, err.Error(), "")
		return
	}

	h.sessions.DeleteByUser(target.ID)

	_ = model.WriteAudit(h.db, &actor.ID, actor.Label(), "User", itoa(target.ID),
		"password_changed", target.Username)

	msg := "已重置 " + target.Username + " 的密码,其会话已吊销"
	if target.ID == actor.ID {
		msg = "密码已修改,请重新登录"
	}
	h.renderUsers(c, http.StatusOK, "", msg)
}

func (h *Handler) loadTargetUser(c *gin.Context) (*model.User, bool) {
	var target model.User
	if h.db.First(&target, c.Param("id")).Error != nil {
		h.renderUsers(c, http.StatusNotFound, "用户不存在", "")
		return nil, false
	}
	return &target, true
}

func (h *Handler) countActiveAdmins(excludeID uint) int {
	var n int64
	h.db.Model(&model.User{}).
		Where("role = ? AND active = ? AND id <> ?", "admin", true, excludeID).
		Count(&n)
	return int(n)
}

func validRole(role string) bool {
	for _, r := range policy.Roles {
		if r == role {
			return true
		}
	}
	return false
}
