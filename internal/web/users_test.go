package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newUsersTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:userstest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM audit_logs")
	return db
}

func mkUser(t *testing.T, db *gorm.DB, name, role string, active bool) *model.User {
	t.Helper()
	u := &model.User{Username: name, Role: role, Active: active, AuthSource: "local"}
	if err := u.SetPassword("password123"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return u
}

func loginAs(t *testing.T, r *gin.Engine, username string) string {
	t.Helper()
	body := strings.NewReader("username=" + username + "&password=password123")
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	for _, c := range w.Result().Cookies() {
		if c.Name == "sid" {
			return c.Value
		}
	}
	t.Fatalf("登录 %s 未获得 sid(状态码 %d)", username, w.Code)
	return ""
}

func postAs(t *testing.T, r *gin.Engine, sid, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func getAs(t *testing.T, r *gin.Engine, sid, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func newUsersRouter(t *testing.T, db *gorm.DB) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, db, &fakeRevoker{})
	return r
}

func TestUsersList_OnlineReflectsSessionsNotActiveFlag(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	mkUser(t, db, "bob", "approver", true)
	mkUser(t, db, "carol", "operator", true)
	r := newUsersRouter(t, db)

	sid := loginAs(t, r, "admin")
	body := getAs(t, r, sid, "/users").Body.String()

	if n := strings.Count(body, ">在线<"); n != 1 {
		t.Errorf("在线标记出现 %d 次,期望 1 —— 只有 admin 登录了", n)
	}

	if n := strings.Count(body, ">离线<"); n != 2 {
		t.Errorf("离线标记出现 %d 次,期望 2", n)
	}

	if n := strings.Count(body, ">启用<"); n != 3 {
		t.Errorf("启用标记出现 %d 次,期望 3(账号状态与在线状态是两件事)", n)
	}
}

func TestUserCreate(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	r := newUsersRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/users", url.Values{
		"username": {"dave"}, "email": {"dave@example.com"},
		"role": {"operator"}, "password": {"secret12345"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("创建用户状态码 = %d, body=%s", w.Code, w.Body.String())
	}

	var u model.User
	if err := db.Where("username = ?", "dave").First(&u).Error; err != nil {
		t.Fatalf("新用户未入库: %v", err)
	}
	if u.Role != "operator" || !u.Active {
		t.Errorf("新用户属性不符: role=%s active=%v", u.Role, u.Active)
	}
	if !u.CheckPassword("secret12345") {
		t.Error("新用户密码校验失败")
	}
	assertAudit(t, db, "created")
}

func TestUserCreate_RejectsBadInput(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	mkUser(t, db, "existing", "viewer", true)
	r := newUsersRouter(t, db)
	sid := loginAs(t, r, "admin")

	cases := []struct {
		name string
		form url.Values
		why  string
	}{
		{"空用户名", url.Values{"username": {""}, "role": {"viewer"}, "password": {"secret12345"}}, "用户名必填"},
		{"非法角色", url.Values{"username": {"x"}, "role": {"superuser"}, "password": {"secret12345"}}, "角色必须在矩阵内"},
		{"密码过短", url.Values{"username": {"x"}, "role": {"viewer"}, "password": {"short"}}, "至少 8 位"},
		{"用户名重复", url.Values{"username": {"existing"}, "role": {"viewer"}, "password": {"secret12345"}}, "唯一约束"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postAs(t, r, sid, "/users", tc.form)
			if w.Code == http.StatusOK {
				t.Errorf("应拒绝(%s),实际 200", tc.why)
			}
		})
	}
}

func TestUserToggle_CannotDisableSelf(t *testing.T) {
	db := newUsersTestDB(t)
	admin := mkUser(t, db, "admin", "admin", true)
	r := newUsersRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/users/"+itoa(admin.ID)+"/toggle", nil)
	if w.Code == http.StatusOK {
		t.Error("停用自己应被拒绝")
	}

	var reloaded model.User
	db.First(&reloaded, admin.ID)
	if !reloaded.Active {
		t.Error("自己的账号被停用了")
	}
}

func TestUserDelete_CannotDeleteSelf(t *testing.T) {
	db := newUsersTestDB(t)
	admin := mkUser(t, db, "admin", "admin", true)
	mkUser(t, db, "admin2", "admin", true)
	r := newUsersRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/users/"+itoa(admin.ID)+"/delete", nil)
	if w.Code == http.StatusOK {
		t.Error("删除自己应被拒绝")
	}
	var n int64
	db.Model(&model.User{}).Where("id = ?", admin.ID).Count(&n)
	if n != 1 {
		t.Error("自己的账号被删了")
	}
}

func TestLastAdminProtection(t *testing.T) {
	t.Run("不能降级最后一个 admin", func(t *testing.T) {
		db := newUsersTestDB(t)
		admin := mkUser(t, db, "admin", "admin", true)
		other := mkUser(t, db, "bob", "viewer", true)
		r := newUsersRouter(t, db)
		sid := loginAs(t, r, "admin")

		_ = other
		w := postAs(t, r, sid, "/users/"+itoa(admin.ID)+"/role",
			url.Values{"role": {"viewer"}})
		if w.Code == http.StatusOK {
			t.Error("降级最后一个 admin 应被拒绝")
		}
		var reloaded model.User
		db.First(&reloaded, admin.ID)
		if reloaded.Role != "admin" {
			t.Errorf("最后一个 admin 被降级成 %s", reloaded.Role)
		}
	})

	t.Run("有第二个 admin 时可以降级", func(t *testing.T) {
		db := newUsersTestDB(t)
		mkUser(t, db, "admin", "admin", true)
		admin2 := mkUser(t, db, "admin2", "admin", true)
		r := newUsersRouter(t, db)
		sid := loginAs(t, r, "admin")

		w := postAs(t, r, sid, "/users/"+itoa(admin2.ID)+"/role",
			url.Values{"role": {"operator"}})
		if w.Code != http.StatusOK {
			t.Fatalf("应允许降级(还有一个 admin),实际 %d: %s", w.Code, w.Body.String())
		}
		var reloaded model.User
		db.First(&reloaded, admin2.ID)
		if reloaded.Role != "operator" {
			t.Errorf("角色 = %s, 期望 operator", reloaded.Role)
		}
	})
}

func TestUserToggle_RevokesTargetSession(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	bob := mkUser(t, db, "bob", "operator", true)
	r := newUsersRouter(t, db)

	adminSid := loginAs(t, r, "admin")
	bobSid := loginAs(t, r, "bob")

	if code := getAs(t, r, bobSid, "/dashboard").Code; code != http.StatusOK {
		t.Fatalf("bob 登录后访问 dashboard = %d", code)
	}

	if w := postAs(t, r, adminSid, "/users/"+itoa(bob.ID)+"/toggle", nil); w.Code != http.StatusOK {
		t.Fatalf("停用 bob 失败: %d %s", w.Code, w.Body.String())
	}

	if code := getAs(t, r, bobSid, "/dashboard").Code; code != http.StatusFound {
		t.Errorf("停用后 bob 仍能访问 dashboard(状态码 %d),会话未吊销", code)
	}
}

func TestUserChangePassword_RevokesSessionAndUpdatesHash(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	bob := mkUser(t, db, "bob", "operator", true)
	r := newUsersRouter(t, db)

	adminSid := loginAs(t, r, "admin")
	bobSid := loginAs(t, r, "bob")

	w := postAs(t, r, adminSid, "/users/"+itoa(bob.ID)+"/password",
		url.Values{"password": {"brandnew12345"}})
	if w.Code != http.StatusOK {
		t.Fatalf("改密失败: %d %s", w.Code, w.Body.String())
	}

	var reloaded model.User
	db.First(&reloaded, bob.ID)
	if !reloaded.CheckPassword("brandnew12345") {
		t.Error("新密码校验失败")
	}
	if reloaded.CheckPassword("password123") {
		t.Error("旧密码仍然有效")
	}
	if code := getAs(t, r, bobSid, "/dashboard").Code; code != http.StatusFound {
		t.Error("改密后旧会话未吊销")
	}
}

func TestUserDelete_KeepsAuditTrail(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	bob := mkUser(t, db, "bob", "operator", true)
	r := newUsersRouter(t, db)
	sid := loginAs(t, r, "admin")

	w := postAs(t, r, sid, "/users/"+itoa(bob.ID)+"/delete", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("删除失败: %d %s", w.Code, w.Body.String())
	}

	var n int64
	db.Model(&model.User{}).Where("id = ?", bob.ID).Count(&n)
	if n != 0 {
		t.Error("用户未被删除")
	}

	assertAudit(t, db, "deleted")
}

func TestUserManagement_RequiresAdmin(t *testing.T) {
	db := newUsersTestDB(t)
	mkUser(t, db, "admin", "admin", true)
	target := mkUser(t, db, "target", "viewer", true)
	mkUser(t, db, "bob", "approver", true)
	r := newUsersRouter(t, db)

	bobSid := loginAs(t, r, "bob")

	if code := getAs(t, r, bobSid, "/users").Code; code != http.StatusForbidden {
		t.Errorf("approver 访问 /users = %d, 期望 403", code)
	}

	paths := []string{
		"/users",
		"/users/" + itoa(target.ID) + "/password",
		"/users/" + itoa(target.ID) + "/role",
		"/users/" + itoa(target.ID) + "/toggle",
		"/users/" + itoa(target.ID) + "/delete",
	}
	for _, p := range paths {
		if code := postAs(t, r, bobSid, p, url.Values{"role": {"admin"}}).Code; code != http.StatusForbidden {
			t.Errorf("approver POST %s = %d, 期望 403", p, code)
		}
	}
}

func assertAudit(t *testing.T, db *gorm.DB, event string) {
	t.Helper()
	var n int64
	db.Model(&model.AuditLog{}).Where("event = ?", event).Count(&n)
	if n == 0 {
		t.Errorf("审计中缺少 %q 事件 —— 用户变更必须留痕", event)
	}
}
