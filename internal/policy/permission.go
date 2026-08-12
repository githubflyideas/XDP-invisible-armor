package policy

type Capability string

const (
	DashboardView      Capability = "dashboard_view"
	BanRequestCreate   Capability = "ban_request_create"
	BanRequestView     Capability = "ban_request_view"
	BanRequestApprove  Capability = "ban_request_approve"
	BanRequestReject   Capability = "ban_request_reject"
	UnbanExecute       Capability = "unban_execute"
	AllowlistManage    Capability = "allowlist_manage"
	SourcePolicyManage Capability = "source_policy_manage"
	AuditView          Capability = "audit_view"
	UserManage         Capability = "user_manage"
	SystemConfig       Capability = "system_config"
)

var Roles = []string{"admin", "approver", "operator", "viewer"}

var matrix = map[string][]Capability{
	"admin": {
		DashboardView, BanRequestCreate, BanRequestView, BanRequestApprove,
		BanRequestReject, UnbanExecute, AllowlistManage, SourcePolicyManage,
		AuditView, UserManage, SystemConfig,
	},
	"approver": {
		DashboardView, BanRequestView, BanRequestApprove, BanRequestReject,
		UnbanExecute, AllowlistManage, AuditView,
	},
	"operator": {
		DashboardView, BanRequestCreate, BanRequestView, AuditView,
	},
	"viewer": {
		DashboardView, BanRequestView, AuditView,
	},
}

func Allow(role string, cap Capability) bool {
	caps, ok := matrix[role]
	if !ok {
		return false
	}
	for _, c := range caps {
		if c == cap {
			return true
		}
	}
	return false
}

type NavSection struct {
	Key   string
	Label string
	Cap   Capability
}

func NavSections(role string) []NavSection {
	all := []NavSection{
		{"dashboard", "Dashboard", DashboardView},
		{"bans", "封禁请求", BanRequestView},
		{"scoped", "范围封禁", BanRequestView},
		{"prefixdb", "IP 库管理", SystemConfig},
		{"audit", "审计日志", AuditView},
		{"report", "合规报告", AuditView},
		{"users", "用户管理", UserManage},
	}
	var out []NavSection
	for _, s := range all {
		if Allow(role, s.Cap) {
			out = append(out, s)
		}
	}
	return out
}
