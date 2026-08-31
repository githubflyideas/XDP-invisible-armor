package quota

import (
	"fmt"
	"net/netip"
	"sync"
)

const (
	MapCapacity = 262144

	GlobalHighWater = MapCapacity * 80 / 100

	PerRuleMaxPrefixes = 32768

	MaxAddressSharePPM = 250000

	GlobalBanMapCapacity = 65536

	GlobalBanHighWater = GlobalBanMapCapacity * 80 / 100
)

const TotalIPv4 = uint64(1) << 32

type Usage struct {
	Prefixes  int
	Rules     int
	Targets   int
	Capacity  int
	HighWater int
}

func (u Usage) Free() int {
	free := u.HighWater - u.Prefixes
	if free < 0 {
		return 0
	}
	return free
}

func (u Usage) UtilizationPPM() int {
	if u.HighWater == 0 {
		return 0
	}
	return int(uint64(u.Prefixes) * 1000000 / uint64(u.HighWater))
}

type Tracker struct {
	mu       sync.RWMutex
	prefixes int
	rules    int
	targets  int

	globalPrefixes int
	globalRules    int
}

func NewTracker() *Tracker { return &Tracker{} }

func (t *Tracker) Usage() Usage {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Usage{
		Prefixes:  t.prefixes,
		Rules:     t.rules,
		Targets:   t.targets,
		Capacity:  MapCapacity,
		HighWater: GlobalHighWater,
	}
}

func (t *Tracker) GlobalBanUsage() Usage {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Usage{
		Prefixes:  t.globalPrefixes,
		Rules:     t.globalRules,
		Capacity:  GlobalBanMapCapacity,
		HighWater: GlobalBanHighWater,
	}
}

func (t *Tracker) Reserve(prefixCount int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prefixes+prefixCount > GlobalHighWater {
		return &QuotaError{
			Kind:      KindGlobalFull,
			Requested: prefixCount,
			Available: GlobalHighWater - t.prefixes,
		}
	}
	t.prefixes += prefixCount
	t.rules++
	return nil
}

func (t *Tracker) Release(prefixCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prefixes -= prefixCount
	if t.prefixes < 0 {
		t.prefixes = 0
	}
	t.rules--
	if t.rules < 0 {
		t.rules = 0
	}
}

func (t *Tracker) ReserveGlobal(prefixCount int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.globalPrefixes+prefixCount > GlobalBanHighWater {
		return &QuotaError{
			Kind:      KindGlobalBanFull,
			Requested: prefixCount,
			Available: GlobalBanHighWater - t.globalPrefixes,
		}
	}
	t.globalPrefixes += prefixCount
	t.globalRules++
	return nil
}

func (t *Tracker) ReleaseGlobal(prefixCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.globalPrefixes -= prefixCount
	if t.globalPrefixes < 0 {
		t.globalPrefixes = 0
	}
	t.globalRules--
	if t.globalRules < 0 {
		t.globalRules = 0
	}
}

func (t *Tracker) SetBaseline(prefixes, rules, targets int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prefixes, t.rules, t.targets = prefixes, rules, targets
}

func (t *Tracker) SetGlobalBaseline(prefixes, rules int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.globalPrefixes, t.globalRules = prefixes, rules
}

type Decision struct {
	Allowed          bool
	RequiresOverride bool
	Reason           string
	PrefixCount      int
	AddressCount     uint64
	AddressSharePPM  int
}

func Check(t *Tracker, cidrs []netip.Prefix) Decision {
	d := Decision{PrefixCount: len(cidrs)}
	for _, c := range cidrs {
		d.AddressCount += uint64(1) << (32 - c.Bits())
	}
	d.AddressSharePPM = int(d.AddressCount * 1000000 / TotalIPv4)

	if len(cidrs) == 0 {
		d.Reason = "该选择未匹配到任何 IP 前缀(前缀库可能未导入或选择条件过窄)"
		return d
	}

	if len(cidrs) > PerRuleMaxPrefixes {
		d.Reason = fmt.Sprintf(
			"该选择展开为 %d 条前缀,超过单条规则上限 %d。"+
				"单机 XDP 不适合承载这个量级,建议缩小范围(按 AS 而非整个国家)"+
				"或在上游做清洗。",
			len(cidrs), PerRuleMaxPrefixes)
		return d
	}

	u := t.Usage()
	if len(cidrs) > u.Free() {
		d.Reason = fmt.Sprintf(
			"需要 %d 条表项,当前仅剩 %d 条(水位线 %d / 容量 %d)。"+
				"请先清理过期规则,或调高 MAX_SRC_BANS 后重新编译 eBPF。",
			len(cidrs), u.Free(), u.HighWater, u.Capacity)
		return d
	}

	d.Allowed = true

	if d.AddressSharePPM > MaxAddressSharePPM {
		d.RequiresOverride = true
		d.Reason = fmt.Sprintf(
			"该选择覆盖 %.1f%% 的 IPv4 地址空间(%d 条前缀)。"+
				"范围异常大,请确认这是有意为之。",
			float64(d.AddressSharePPM)/10000, len(cidrs))
		return d
	}

	d.Reason = fmt.Sprintf("将占用 %d 条表项(剩余 %d),覆盖 %.4f%% 的 IPv4 空间。",
		len(cidrs), u.Free()-len(cidrs), float64(d.AddressSharePPM)/10000)
	return d
}

type QuotaKind string

const (
	KindGlobalFull    QuotaKind = "global_full"
	KindPerRule       QuotaKind = "per_rule"
	KindGlobalBanFull QuotaKind = "global_ban_full"
)

type QuotaError struct {
	Kind      QuotaKind
	Requested int
	Available int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("配额不足(%s):需要 %d 条表项,可用 %d 条",
		e.Kind, e.Requested, e.Available)
}
