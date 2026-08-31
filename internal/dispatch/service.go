package dispatch

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/resolution"
	"github.com/xdpban/xdp-ban/internal/safety"
)

type Service struct {
	db    *gorm.DB
	guard *safety.Guard
}

func NewService(db *gorm.DB, guard *safety.Guard) *Service {
	return &Service{db: db, guard: guard}
}

type BanPayload struct {
	Target  string `json:"target"`
	TTLSecs int64  `json:"ttl_secs"`
	NodeID  string `json:"node_id"`
	ReqID   uint   `json:"req_id"`
	BanID   string `json:"ban_id"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`

	ScopedTarget string   `json:"scoped_target,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
}

func (s *Service) CreateDispatch(req *model.BanRequest) (*model.Dispatch, string, error) {

	if err := s.guard.AssertSafe(req.Target); err != nil {
		s.db.Model(req).Update("state", "safety_blocked")
		return nil, err.Error(), err
	}

	res := resolution.Resolve([]string{req.Source}, false)

	banID := fmt.Sprintf("ban-%d-%s", req.ID, req.Target)

	var existing model.Dispatch
	if err := s.db.Where("ban_id = ?", banID).First(&existing).Error; err == nil {
		return &existing, resolution.Explain("ban", res), nil
	}

	ttl := int64(0)
	if req.TTLSeconds != nil {
		ttl = *req.TTLSeconds
	}
	payload := BanPayload{
		Target:  req.Target,
		TTLSecs: ttl,
		NodeID:  "local",
		ReqID:   req.ID,
		BanID:   banID,
		Backend: "xdp",
		Reason:  req.Reason,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal payload: %w", err)
	}

	dispatch := &model.Dispatch{
		BanRequestID: req.ID,
		BanID:        banID,
		NodeID:       "local",
		Payload:      string(payloadJSON),
		State:        "pending",
	}
	if err := s.db.Create(dispatch).Error; err != nil {
		return nil, "", fmt.Errorf("create dispatch: %w", err)
	}

	_ = model.WriteAudit(s.db, req.ApprovedByID, "dispatch", "Dispatch",
		fmt.Sprint(dispatch.ID), "created", string(payloadJSON))

	return dispatch, resolution.Explain("ban", res), nil
}

func (s *Service) CreateScopedDispatch(sb *model.ScopedBan, prefixes []string) (*model.Dispatch, string, error) {

	if err := s.guard.AssertSafe(sb.TargetIP); err != nil {
		s.db.Model(sb).Update("state", "safety_blocked")
		return nil, err.Error(), err
	}

	res := resolution.Resolve([]string{"manual"}, false)

	banID := fmt.Sprintf("scoped-%d-%s", sb.ID, sb.TargetIP)
	var existing model.Dispatch
	if err := s.db.Where("ban_id = ?", banID).First(&existing).Error; err == nil {
		return &existing, resolution.Explain("ban", res), nil
	}

	ttl := int64(0)
	if sb.TTLSeconds != nil {
		ttl = *sb.TTLSeconds
	}
	payload := BanPayload{
		TTLSecs:      ttl,
		NodeID:       "local",
		ReqID:        sb.ID,
		BanID:        banID,
		Backend:      "xdp",
		Reason:       sb.Reason,
		ScopedTarget: sb.TargetIP,
		Prefixes:     prefixes,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal scoped payload: %w", err)
	}

	dispatch := &model.Dispatch{
		BanRequestID: sb.ID,
		BanID:        banID,
		NodeID:       "local",
		Payload:      string(payloadJSON),
		State:        "pending",
	}
	if err := s.db.Create(dispatch).Error; err != nil {
		return nil, "", fmt.Errorf("create scoped dispatch: %w", err)
	}

	detail := fmt.Sprintf("target=%s prefixes=%d ttl=%ds",
		sb.TargetIP, len(prefixes), ttl)
	_ = model.WriteAudit(s.db, sb.ApprovedByID, "dispatch", "Dispatch",
		fmt.Sprint(dispatch.ID), "created", detail)

	return dispatch, resolution.Explain("ban", res), nil
}

func (s *Service) CreateGlobalScopedDispatch(sb *model.ScopedBan, prefixes []string) ([]*model.Dispatch, string, error) {

	var resolved []netip.Prefix
	for _, p := range prefixes {
		pp, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, "", fmt.Errorf("解析前缀 %q 失败: %w", p, err)
		}
		resolved = append(resolved, pp)
	}
	if err := s.guard.AssertSafeAll(resolved); err != nil {
		s.db.Model(sb).Update("state", "safety_blocked")
		return nil, err.Error(), err
	}

	res := resolution.Resolve([]string{"manual"}, false)

	ttl := int64(0)
	if sb.TTLSeconds != nil {
		ttl = *sb.TTLSeconds
	}

	dispatches := make([]*model.Dispatch, 0, len(prefixes))
	for _, prefix := range prefixes {
		banID := fmt.Sprintf("scoped-global-%d-%s", sb.ID, prefix)

		var existing model.Dispatch
		if err := s.db.Where("ban_id = ?", banID).First(&existing).Error; err == nil {
			dispatches = append(dispatches, &existing)
			continue
		}

		payload := BanPayload{
			Target:  prefix,
			TTLSecs: ttl,
			NodeID:  "local",
			ReqID:   sb.ID,
			BanID:   banID,
			Backend: "xdp",
			Reason:  sb.Reason,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			return nil, "", fmt.Errorf("marshal global scoped payload: %w", err)
		}

		d := &model.Dispatch{
			BanRequestID: sb.ID,
			BanID:        banID,
			NodeID:       "local",
			Payload:      string(payloadJSON),
			State:        "pending",
		}
		if err := s.db.Create(d).Error; err != nil {
			return nil, "", fmt.Errorf("create global scoped dispatch: %w", err)
		}
		dispatches = append(dispatches, d)
	}

	detail := fmt.Sprintf("scope=%s/AS%d prefixes=%d ttl=%ds", sb.Country, sb.ASN, len(prefixes), ttl)
	_ = model.WriteAudit(s.db, sb.ApprovedByID, "dispatch", "Dispatch",
		fmt.Sprint(sb.ID), "created_global", detail)

	return dispatches, resolution.Explain("ban", res), nil
}

func (s *Service) MarkAcked(dispatch *model.Dispatch) error {
	now := time.Now()
	return s.db.Model(dispatch).Updates(map[string]any{
		"state":    "acked",
		"acked_at": now,
	}).Error
}

func (s *Service) MarkFailed(dispatch *model.Dispatch, errMsg string) error {
	return s.db.Model(dispatch).Updates(map[string]any{
		"state":      "failed",
		"last_error": errMsg,
		"attempts":   dispatch.Attempts + 1,
	}).Error
}
