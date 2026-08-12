package quota

import (
	"net/netip"
	"sync"
	"testing"
)

func mkCIDRs(t *testing.T, n int, bits int) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {

		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0})
		out = append(out, netip.PrefixFrom(a, bits))
	}
	return out
}

func TestCheck_RejectsOversizedRule(t *testing.T) {
	tr := NewTracker()
	d := Check(tr, mkCIDRs(t, PerRuleMaxPrefixes+1, 32))
	if d.Allowed {
		t.Error("超过单规则上限应被拒绝")
	}
	if d.Reason == "" {
		t.Error("拒绝时必须给出可展示的原因")
	}
}

func TestCheck_RespectsGlobalHighWater(t *testing.T) {
	tr := NewTracker()

	tr.SetBaseline(GlobalHighWater-10, 1, 1)

	d := Check(tr, mkCIDRs(t, 100, 32))
	if d.Allowed {
		t.Error("超过剩余水位应被拒绝")
	}

	d = Check(tr, mkCIDRs(t, 10, 32))
	if !d.Allowed {
		t.Errorf("在余量内应放行,却被拒: %s", d.Reason)
	}
}

func TestCheck_LargeCoverageRequiresOverride(t *testing.T) {
	tr := NewTracker()

	half := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}
	d := Check(tr, half)

	if !d.Allowed {
		t.Error("大范围不应硬拒绝(可能是有意的)")
	}
	if !d.RequiresOverride {
		t.Error("覆盖 50%% IPv4 空间必须要求二次确认")
	}
	if d.AddressSharePPM < 490000 || d.AddressSharePPM > 510000 {
		t.Errorf("占比计算错误: %d ppm(期望约 500000)", d.AddressSharePPM)
	}
}

func TestCheck_NormalRulePasses(t *testing.T) {
	tr := NewTracker()
	d := Check(tr, mkCIDRs(t, 500, 24))
	if !d.Allowed {
		t.Errorf("常规规模应放行: %s", d.Reason)
	}
	if d.RequiresOverride {
		t.Error("常规规模不该要求二次确认")
	}
	if d.PrefixCount != 500 {
		t.Errorf("PrefixCount = %d, 期望 500", d.PrefixCount)
	}
}

func TestCheck_EmptySelectionRejected(t *testing.T) {
	tr := NewTracker()
	d := Check(tr, nil)
	if d.Allowed {
		t.Error("空选择应被拒绝")
	}
}

func TestTracker_ConcurrentReserveRespectsLimit(t *testing.T) {
	tr := NewTracker()
	const each = 1000
	const workers = 500

	var wg sync.WaitGroup
	var okCount int
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tr.Reserve(each); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	u := tr.Usage()
	if u.Prefixes > GlobalHighWater {
		t.Errorf("并发预占突破水位线: %d > %d", u.Prefixes, GlobalHighWater)
	}
	if okCount*each != u.Prefixes {
		t.Errorf("成功次数与占用量不一致: %d×%d != %d", okCount, each, u.Prefixes)
	}
	t.Logf("成功 %d/%d 次,占用 %d/%d 表项", okCount, workers, u.Prefixes, GlobalHighWater)
}

func TestTracker_ReleaseRestoresQuota(t *testing.T) {
	tr := NewTracker()
	if err := tr.Reserve(1000); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	before := tr.Usage()
	tr.Release(1000)
	after := tr.Usage()

	if after.Prefixes != before.Prefixes-1000 {
		t.Errorf("Release 后占用 = %d, 期望 %d", after.Prefixes, before.Prefixes-1000)
	}
	if after.Rules != 0 {
		t.Errorf("Release 后规则数 = %d, 期望 0", after.Rules)
	}
}

func TestTracker_ReleaseDoesNotUnderflow(t *testing.T) {
	tr := NewTracker()
	tr.Release(500)
	u := tr.Usage()
	if u.Prefixes != 0 || u.Rules != 0 {
		t.Errorf("过度释放导致负值: prefixes=%d rules=%d", u.Prefixes, u.Rules)
	}
}

func TestHighWaterLeavesHeadroom(t *testing.T) {
	if GlobalHighWater >= MapCapacity {
		t.Fatal("水位线不得等于或超过 map 容量")
	}
	headroom := MapCapacity - GlobalHighWater
	if headroom < 10000 {
		t.Errorf("余量仅 %d 条,攻击进行中可能无法插入精准封禁", headroom)
	}
}
