package web

import (
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/dispatch"
	"github.com/xdpban/xdp-ban/internal/escalation"
	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/safety"
)

func (h *Handler) restoreQuota() {
	live := []string{"pending", "active"}

	var agg struct {
		Prefixes int
		Rules    int
	}
	h.db.Model(&model.ScopedBan{}).
		Where("state IN ? AND global = ?", live, false).
		Select("COALESCE(SUM(prefix_count),0) as prefixes, COUNT(*) as rules").
		Scan(&agg)

	var targets int64
	h.db.Model(&model.ScopedBan{}).
		Where("state IN ? AND global = ?", live, false).
		Distinct("target_ip").
		Count(&targets)

	h.quota.SetBaseline(agg.Prefixes, agg.Rules, int(targets))

	var globalAgg struct {
		Prefixes int
		Rules    int
	}
	h.db.Model(&model.ScopedBan{}).
		Where("state IN ? AND global = ?", live, true).
		Select("COALESCE(SUM(prefix_count),0) as prefixes, COUNT(*) as rules").
		Scan(&globalAgg)

	h.quota.SetGlobalBaseline(globalAgg.Prefixes, globalAgg.Rules)
}

func (h *Handler) guard() *safety.Guard {
	g := safety.New(nil)
	var targets []model.ProtectedTarget
	if err := h.db.Where("active = ?", true).Find(&targets).Error; err == nil {
		for _, t := range targets {
			g.Add(t.Target)
		}
	}
	return g
}

func (h *Handler) dispatches() *dispatch.Service {
	return dispatch.NewService(h.db, h.guard())
}

func (h *Handler) nextTTL(target string) *int64 {
	var ladder model.BanLadder
	err := h.db.Where("target = ?", target).First(&ladder).Error

	p := escalation.NewPenalty(target)
	if err == nil {
		p.Level = ladder.Level
		p.OffenseCount = ladder.OffenseCount
		if ladder.ObserveUntil != nil {
			p.ObserveUntil = *ladder.ObserveUntil
		}
	}

	ttl := p.CurrentTTL()
	if p.Observing() && p.Level < len(escalation.Ladder)-1 {
		ttl = escalation.Ladder[p.Level+1]
	}
	if ttl == 0 {
		return nil
	}
	return &ttl
}

func (h *Handler) recordLadder(target string) {
	var ladder model.BanLadder
	err := h.db.Where("target = ?", target).First(&ladder).Error

	p := escalation.NewPenalty(target)
	escalate := false
	if err == nil {
		p.Level = ladder.Level
		p.OffenseCount = ladder.OffenseCount
		if ladder.ObserveUntil != nil {
			p.ObserveUntil = *ladder.ObserveUntil
		}
		escalate = p.Observing()
	}

	p.RegisterBan(escalate)

	now := time.Now()
	row := model.BanLadder{
		Target:       target,
		Level:        p.Level,
		OffenseCount: p.OffenseCount,
		LastBannedAt: &now,
		Permanent:    p.Permanent(),
	}
	if !p.ObserveUntil.IsZero() {
		ou := p.ObserveUntil
		row.ObserveUntil = &ou
	}
	if !p.ExpiresAt.IsZero() {
		ea := p.ExpiresAt
		row.ExpiresAt = &ea
	}

	if err == gorm.ErrRecordNotFound {
		h.db.Create(&row)
		return
	}
	h.db.Model(&ladder).Updates(map[string]any{
		"level":          row.Level,
		"offense_count":  row.OffenseCount,
		"last_banned_at": row.LastBannedAt,
		"observe_until":  row.ObserveUntil,
		"expires_at":     row.ExpiresAt,
		"permanent":      row.Permanent,
	})
}
