package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
)

type Filter struct {
	From time.Time
	To   time.Time
}

type Row struct {
	Kind        string
	ID          uint
	Target      string
	Scope       string
	Reason      string
	State       string
	Requester   string
	Approver    string
	ApprovalWay string
	OverrideAck bool
	RequestedAt time.Time
	ApprovedAt  *time.Time
	ExpiresAt   *time.Time
	TTL         string
	PrefixCount int
}

type Summary struct {
	From, To          time.Time
	GeneratedAt       time.Time
	GeneratedBy       string
	TotalBans         int
	Approved          int
	Rejected          int
	SafetyBlocked     int
	OverrideCount     int
	DistinctApprovers int
	DistinctTargets   int
}

func Build(db *gorm.DB, f Filter, generatedBy string) (*Summary, []Row, error) {
	users, err := loadUsers(db)
	if err != nil {
		return nil, nil, err
	}

	var rows []Row

	var reqs []model.BanRequest
	if err := db.Where("created_at >= ? AND created_at <= ?", f.From, f.To).
		Order("created_at asc").Find(&reqs).Error; err != nil {
		return nil, nil, fmt.Errorf("查询封禁请求: %w", err)
	}
	for i := range reqs {
		rows = append(rows, banRequestRow(&reqs[i], users))
	}

	var scoped []model.ScopedBan
	if err := db.Where("created_at >= ? AND created_at <= ?", f.From, f.To).
		Order("created_at asc").Find(&scoped).Error; err != nil {
		return nil, nil, fmt.Errorf("查询范围封禁: %w", err)
	}
	for i := range scoped {
		rows = append(rows, scopedBanRow(&scoped[i], users))
	}

	sum := summarize(db, f, rows, generatedBy)
	return sum, rows, nil
}

func banRequestRow(r *model.BanRequest, users map[uint]string) Row {
	row := Row{
		Kind: "ban", ID: r.ID, Target: r.Target, Reason: r.Reason,
		State: r.State, RequestedAt: r.CreatedAt,
		Requester: userName(users, r.RequestedByID),
		Approver:  userName(users, r.ApprovedByID),
		ExpiresAt: r.ExpiresAt,
		TTL:       formatTTL(r.TTLSeconds),
	}
	row.ApprovalWay = approvalWay(r.ApprovedByPolicy)
	if r.EffectiveAt != nil {
		row.ApprovedAt = r.EffectiveAt
	}
	return row
}

func scopedBanRow(s *model.ScopedBan, users map[uint]string) Row {
	return Row{
		Kind: "scoped_ban", ID: s.ID, Target: s.TargetIP,
		Scope: scopeLabel(s), Reason: s.Reason, State: s.State,
		RequestedAt: s.CreatedAt,
		Requester:   userName(users, s.RequestedByID),
		Approver:    userName(users, s.ApprovedByID),
		ApprovalWay: "界面审批",
		OverrideAck: s.OverrideAck,
		ApprovedAt:  s.EffectiveAt,
		ExpiresAt:   s.ExpiresAt,
		TTL:         formatTTL(s.TTLSeconds),
		PrefixCount: s.PrefixCount,
	}
}

func summarize(db *gorm.DB, f Filter, rows []Row, by string) *Summary {
	s := &Summary{
		From: f.From, To: f.To,
		GeneratedAt: time.Now(), GeneratedBy: by,
		TotalBans: len(rows),
	}
	approvers := map[string]bool{}
	targets := map[string]bool{}
	for _, r := range rows {
		switch r.State {
		case "active", "expired", "revoked":
			s.Approved++
		case "rejected":
			s.Rejected++
		case "safety_blocked":
			s.SafetyBlocked++
		}
		if r.OverrideAck {
			s.OverrideCount++
		}
		if r.Approver != "" && r.Approver != "-" {
			approvers[r.Approver] = true
		}
		targets[r.Target] = true
	}
	s.DistinctApprovers = len(approvers)
	s.DistinctTargets = len(targets)

	// 这里曾经统计 self_approval_denied 事件数(四眼原则拦截次数)。四眼已移除,
	// 该事件不会再写入,留着只会在报告里挂一个恒为 0 的指标。历史记录仍在审计日志里可查。

	return s
}

func WriteCSV(w io.Writer, sum *Summary, rows []Row) error {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}

	cw := csv.NewWriter(w)
	defer cw.Flush()

	meta := [][]string{
		{"xdp-ban 封禁操作合规报告"},
		{"统计区间", sum.From.Format("2006-01-02 15:04:05") + " ~ " + sum.To.Format("2006-01-02 15:04:05")},
		{"导出时间", sum.GeneratedAt.Format("2006-01-02 15:04:05")},
		{"导出人", sum.GeneratedBy},
		{"封禁总数", strconv.Itoa(sum.TotalBans)},
		{"已批准", strconv.Itoa(sum.Approved)},
		{"已驳回", strconv.Itoa(sum.Rejected)},
		{"被保护集否决", strconv.Itoa(sum.SafetyBlocked)},
		{"大范围显式确认", strconv.Itoa(sum.OverrideCount)},
		{"参与审批人数", strconv.Itoa(sum.DistinctApprovers)},
		{},
	}
	for _, m := range meta {
		if err := cw.Write(m); err != nil {
			return err
		}
	}

	header := []string{
		"类型", "编号", "目标地址", "源范围", "原因", "状态",
		"提交人", "审批人", "审批方式", "大范围确认",
		"提交时间", "生效时间", "到期时间", "封禁时长", "前缀数",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, r := range rows {
		rec := []string{
			kindLabel(r.Kind), strconv.FormatUint(uint64(r.ID), 10),
			r.Target, r.Scope, r.Reason, stateLabel(r.State),
			dash(r.Requester), dash(r.Approver), dash(r.ApprovalWay),
			boolLabel(r.OverrideAck),
			r.RequestedAt.Format("2006-01-02 15:04:05"),
			timePtr(r.ApprovedAt), timePtr(r.ExpiresAt),
			r.TTL, prefixLabel(r.PrefixCount),
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	return cw.Error()
}

func loadUsers(db *gorm.DB) (map[uint]string, error) {
	var us []model.User
	if err := db.Find(&us).Error; err != nil {
		return nil, fmt.Errorf("查询用户: %w", err)
	}
	m := make(map[uint]string, len(us))
	for _, u := range us {
		m[u.ID] = u.Username
	}
	return m, nil
}

func userName(m map[uint]string, id *uint) string {
	if id == nil {
		return ""
	}
	if n, ok := m[*id]; ok {
		return n
	}
	return "user#" + strconv.FormatUint(uint64(*id), 10)
}

func approvalWay(policy string) string {
	switch policy {
	case "email_link":
		return "邮件链接"
	case "":
		return ""
	default:
		return policy
	}
}

func scopeLabel(s *model.ScopedBan) string {
	var parts []string
	if s.Country != "" {
		parts = append(parts, s.Country)
	}
	if s.ASN != 0 {
		parts = append(parts, "AS"+strconv.FormatUint(uint64(s.ASN), 10))
	}
	return strings.Join(parts, " + ")
}

func formatTTL(secs *int64) string {
	if secs == nil || *secs == 0 {
		return "永久"
	}
	d := time.Duration(*secs) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.0f 天", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0f 小时", d.Hours())
	default:
		return fmt.Sprintf("%.0f 分钟", d.Minutes())
	}
}

func kindLabel(k string) string {
	if k == "scoped_ban" {
		return "范围封禁"
	}
	return "单点封禁"
}

func stateLabel(s string) string {
	switch s {
	case "pending":
		return "待审批"
	case "active":
		return "生效中"
	case "rejected":
		return "已驳回"
	case "expired":
		return "已过期"
	case "revoked":
		return "已撤销"
	case "safety_blocked":
		return "保护集否决"
	default:
		return s
	}
}

func boolLabel(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func timePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02 15:04:05")
}

func prefixLabel(n int) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(n)
}
