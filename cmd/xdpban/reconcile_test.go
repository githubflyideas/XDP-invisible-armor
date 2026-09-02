package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/xdpban/xdp-ban/internal/model"
)

func newReconcileTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:reconciletest?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&model.User{}, &model.BanRequest{}, &model.Dispatch{}, &model.AuditLog{},
		&model.ApprovalToken{}, &model.ProtectedTarget{}, &model.BanLadder{}, &model.ScopedBan{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	db.Exec("DELETE FROM dispatches")
	db.Exec("DELETE FROM audit_logs")
	return db
}

func mustPayload(t *testing.T, p BanPayload) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(b)
}

func TestReconcile_DetectsAckedDispatchMissingFromLiveMap(t *testing.T) {
	db := newReconcileTestDB(t)
	bm, _, _, _ := newTestMaps()

	payload := mustPayload(t, BanPayload{Target: "203.0.113.7", TTLSecs: 0, BanID: "ban-1-203.0.113.7"})
	d := model.Dispatch{BanRequestID: 1, BanID: "ban-1-203.0.113.7", Payload: payload, State: "acked"}
	if err := db.Create(&d).Error; err != nil {
		t.Fatalf("create dispatch: %v", err)
	}

	drifts := reconcile(db, bm)
	if len(drifts) == 0 {
		t.Fatal("期望检测到 drift,实际为空")
	}

	var audits []model.AuditLog
	db.Where("event = ?", "drift_detected").Find(&audits)
	if len(audits) != 1 {
		t.Errorf("期望写入 1 条 drift_detected 审计,实际 %d", len(audits))
	}
}

func TestReconcile_NoDriftWhenMapMatchesDB(t *testing.T) {
	db := newReconcileTestDB(t)
	bm, _, _, _ := newTestMaps()

	if err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 0}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	payload := mustPayload(t, BanPayload{Target: "203.0.113.7", TTLSecs: 0, BanID: "ban-1-203.0.113.7"})
	d := model.Dispatch{BanRequestID: 1, BanID: "ban-1-203.0.113.7", Payload: payload, State: "acked"}
	if err := db.Create(&d).Error; err != nil {
		t.Fatalf("create dispatch: %v", err)
	}

	drifts := reconcile(db, bm)
	if len(drifts) != 0 {
		t.Errorf("期望零 drift,实际 %v", drifts)
	}

	var audits []model.AuditLog
	db.Where("event = ?", "drift_detected").Find(&audits)
	if len(audits) != 0 {
		t.Errorf("匹配时不应写入 drift_detected 审计,实际 %d 条", len(audits))
	}
}

func TestReconcile_ExpiredEntryIsNotFlaggedAsDrift(t *testing.T) {
	db := newReconcileTestDB(t)
	bm, _, _, _ := newTestMaps()

	// 两小时前下发、TTL 只有 60 秒 —— eBPF 侧早就自然过期了,
	// map 里找不到是预期行为,不该报漂移。
	ackedAt := time.Now().Add(-2 * time.Hour)
	payload := mustPayload(t, BanPayload{Target: "203.0.113.7", TTLSecs: 60, BanID: "ban-1-203.0.113.7"})
	d := model.Dispatch{BanRequestID: 1, BanID: "ban-1-203.0.113.7", Payload: payload,
		State: "acked", AckedAt: &ackedAt}
	if err := db.Create(&d).Error; err != nil {
		t.Fatalf("create dispatch: %v", err)
	}

	drifts := reconcile(db, bm)
	if len(drifts) != 0 {
		t.Errorf("已过期条目不应报 drift,实际 %v", drifts)
	}
}

func TestReconcile_UnexpiredEntryMissingFromMapIsDrift(t *testing.T) {
	db := newReconcileTestDB(t)
	bm, _, _, _ := newTestMaps()

	// 刚下发、TTL 一小时 —— 远未到期,map 里却找不到,这才是真漂移。
	ackedAt := time.Now()
	payload := mustPayload(t, BanPayload{Target: "203.0.113.8", TTLSecs: 3600, BanID: "ban-2-203.0.113.8"})
	d := model.Dispatch{BanRequestID: 2, BanID: "ban-2-203.0.113.8", Payload: payload,
		State: "acked", AckedAt: &ackedAt}
	if err := db.Create(&d).Error; err != nil {
		t.Fatalf("create dispatch: %v", err)
	}

	if drifts := reconcile(db, bm); len(drifts) != 1 {
		t.Errorf("未到期却不在 map 里应报 1 条 drift,实际 %v", drifts)
	}
}
