package model

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpen_EnablesWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		t.Fatalf("查询 journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, 期望 wal", mode)
	}

	var timeout int
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatalf("查询 busy_timeout: %v", err)
	}
	if timeout < 1000 {
		t.Errorf("busy_timeout = %d ms, 过短会在并发写时直接返回 SQLITE_BUSY", timeout)
	}
}

func TestOpen_ConcurrentReadWriteNoLockError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 128)

	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := WriteAudit(db, nil, fmt.Sprintf("writer%d", id),
					"Test", fmt.Sprint(i), "event", ""); err != nil {
					errCh <- fmt.Errorf("写者 %d: %w", id, err)
					return
				}
			}
		}(w)
	}

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				var n int64
				if err := db.Model(&AuditLog{}).Count(&n).Error; err != nil {
					errCh <- fmt.Errorf("读者: %w", err)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("并发读写失败(WAL/busy_timeout 未生效?): %v", err)
	}
}

func TestWriteAudit_AppendOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := WriteAudit(db, nil, "tester", "BanRequest", "1", "created", "detail"); err != nil {
		t.Fatalf("WriteAudit: %v", err)
	}

	var logs []AuditLog
	db.Find(&logs)
	if len(logs) != 1 {
		t.Fatalf("审计条数 = %d, 期望 1", len(logs))
	}
	if logs[0].Event != "created" || logs[0].ActorLabel != "tester" {
		t.Errorf("审计内容不符: %+v", logs[0])
	}
	if logs[0].OccurredAt.IsZero() {
		t.Error("occurred_at 未填充")
	}
}

func BenchmarkWriteAudit(b *testing.B) {
	path := filepath.Join(b.TempDir(), "bench.db")
	db, err := Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := WriteAudit(db, nil, "bench", "Test", "1", "event", ""); err != nil {
			b.Fatalf("WriteAudit: %v", err)
		}
	}
}

func BenchmarkDashboardCounts(b *testing.B) {
	path := filepath.Join(b.TempDir(), "counts.db")
	db, err := Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	for i := 0; i < 1000; i++ {
		db.Create(&BanRequest{Target: fmt.Sprintf("10.0.%d.%d", i/256, i%256), State: "pending"})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var pending, active, failed int64
		db.Model(&BanRequest{}).Where("state = ?", "pending").Count(&pending)
		db.Model(&BanRequest{}).Where("state = ?", "active").Count(&active)
		db.Model(&Dispatch{}).Where("state = ?", "failed").Count(&failed)
	}
}
