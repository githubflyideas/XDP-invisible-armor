package resolution

type Effect string

const (
	Pass Effect = "pass"
	Drop Effect = "drop"
)

type Rule struct {
	Source     string
	Precedence int
	Effect     Effect
	Note       string
}

var Rules = []Rule{
	{"__safety__", 0, Pass, "绝对保护集,永不封(SafetyGuard 独立强制)"},
	{"allowlist", 10, Pass, "白名单免封,压过所有黑名单"},
	{"blacklist_manual", 20, Drop, "人工封禁"},
	{"blacklist_blackhole", 30, Drop, "BGP/blackhole 黑洞"},
	{"blacklist_intel", 40, Drop, "威胁情报(将来)"},
}

type Resolution struct {
	Effect       Effect
	DecidedBy    string
	Contributing []string
	Reason       string
}

func Resolve(hitSources []string, safetyVeto bool) Resolution {

	if safetyVeto {
		return Resolution{Pass, "__safety__", hitSources, "命中绝对保护集,安全兜底强制放行"}
	}

	best := -1
	var winner *Rule
	for i := range Rules {
		r := &Rules[i]
		if r.Source == "__safety__" {
			continue
		}
		if contains(hitSources, r.Source) {
			if winner == nil || r.Precedence < best {
				best = r.Precedence
				winner = r
			}
		}
	}
	if winner == nil {
		return Resolution{Pass, "", nil, "无任何来源命中,默认放行"}
	}
	return Resolution{winner.Effect, winner.Source, hitSources, winner.Note}
}

func Explain(action string, r Resolution) string {
	switch {
	case action == "ban" && r.Effect == Drop:
		return "封禁已生效,当前该 IP 被丢弃(裁决来源:" + r.DecidedBy + ")"
	case action == "ban" && r.Effect == Pass:
		return "⚠️ 封禁已记录,但当前【未拦截】—— " + r.DecidedBy + " 优先级更高(" + r.Reason + ")。要真拦截需先处理 " + r.DecidedBy
	case action == "unban" && r.Effect == Pass:
		return "解封成功,当前该 IP 已放行"
	case action == "unban" && r.Effect == Drop:
		return "⚠️ 解封成功,但该 IP 当前【仍被丢弃】—— 仍被 " + r.DecidedBy + " 拦着(" + r.Reason + ")。需一并处理 " + r.DecidedBy
	default:
		return "操作已执行,当前有效状态:" + string(r.Effect)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
