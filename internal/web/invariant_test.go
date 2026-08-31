package web

import (
	"net/http"
	"testing"

	"github.com/xdpban/xdp-ban/internal/model"
)

// TestFourEyesInvariant_SelfActionDeniedOnMutatingRoutes 是一个表驱动不变量测试:
// 每个会改变 BanRequest/ScopedBan 审批状态的路由,在请求人对自己提交的请求操作时都必须 403。
//
// lookupRollback 和 scopedBanRevoke 故意不在此列——这是设计决定,不是遗漏:
// 用户已确认撤销/回滚只需要 policy.UnbanExecute 权限门槛,不需要四眼互斥,
// 因为撤销是安全阀,误撤销代价远低于误新增封禁,且审计日志已完整记录操作人。
// 如果日后有人想把 lookupRollback/scopedBanRevoke 加进这个表,先去看这条注释和上层的设计决定。
func TestFourEyesInvariant_SelfActionDeniedOnMutatingRoutes(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T) int
	}{
		{
			name: "banApprove denies requester approving own request",
			run: func(t *testing.T) int {
				db := newUsersTestDB(t)
				if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{}, &model.ProtectedTarget{}, &model.BanLadder{}); err != nil {
					t.Fatalf("migrate: %v", err)
				}
				db.Exec("DELETE FROM ban_requests")
				u := mkUser(t, db, "self", "approver", true)
				req := model.BanRequest{ActionType: "ban", Target: "203.0.113.1", Source: "manual",
					State: "pending", RequestedByID: &u.ID, ApprovalMode: "manual_dual"}
				db.Create(&req)
				r := newUsersRouter(t, db)
				sid := loginAs(t, r, "self")
				return postAs(t, r, sid, "/bans/"+itoa(req.ID)+"/approve", nil).Code
			},
		},
		{
			name: "banReject denies requester rejecting own request",
			run: func(t *testing.T) int {
				db := newUsersTestDB(t)
				if err := db.AutoMigrate(&model.BanRequest{}, &model.Dispatch{}); err != nil {
					t.Fatalf("migrate: %v", err)
				}
				db.Exec("DELETE FROM ban_requests")
				u := mkUser(t, db, "self", "approver", true)
				req := model.BanRequest{ActionType: "ban", Target: "203.0.113.2", Source: "manual",
					State: "pending", RequestedByID: &u.ID, ApprovalMode: "manual_dual"}
				db.Create(&req)
				r := newUsersRouter(t, db)
				sid := loginAs(t, r, "self")
				return postAs(t, r, sid, "/bans/"+itoa(req.ID)+"/reject", nil).Code
			},
		},
		{
			name: "scopedBanApprove denies requester approving own request",
			run: func(t *testing.T) int {
				db := newScopedTestDB(t)
				u := mkUser(t, db, "self", "approver", true)
				setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})
				sb := model.ScopedBan{Global: true, Country: "XX", PrefixCount: 1, AddressCount: 256,
					State: "pending", RequestedByID: &u.ID}
				db.Create(&sb)
				r := newScopedRouter(t, db, &fakeRevoker{})
				sid := loginAs(t, r, "self")
				return postAs(t, r, sid, "/scoped/"+itoa(sb.ID)+"/approve", nil).Code
			},
		},
		{
			name: "scopedBanReject denies requester rejecting own request",
			run: func(t *testing.T) int {
				db := newScopedTestDB(t)
				u := mkUser(t, db, "self", "approver", true)
				setTestPrefixDB(t, map[string][]string{"XX": {"198.51.100.0/24"}})
				sb := model.ScopedBan{Global: true, Country: "XX", PrefixCount: 1, AddressCount: 256,
					State: "pending", RequestedByID: &u.ID}
				db.Create(&sb)
				r := newScopedRouter(t, db, &fakeRevoker{})
				sid := loginAs(t, r, "self")
				return postAs(t, r, sid, "/scoped/"+itoa(sb.ID)+"/reject", nil).Code
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := tc.run(t); code != http.StatusForbidden {
				t.Errorf("状态码 = %d, 期望 403(四眼原则应拒绝自我操作)", code)
			}
		})
	}
}
