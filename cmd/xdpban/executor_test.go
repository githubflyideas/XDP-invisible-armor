package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

type fakeMap struct {
	name    string
	entries map[string][]byte
	putErr  error
	puts    int
}

func newFakeMap(name string) *fakeMap {
	return &fakeMap{name: name, entries: make(map[string][]byte)}
}

func (m *fakeMap) Put(key, value any) error {
	if m.putErr != nil {
		return m.putErr
	}
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte,实际 %T", m.name, key)
	}
	vb, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("%s: value 类型应为 []byte,实际 %T", m.name, value)
	}
	m.entries[string(kb)] = vb
	m.puts++
	return nil
}

func (m *fakeMap) Delete(key any) error {
	kb, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("%s: key 类型应为 []byte", m.name)
	}
	delete(m.entries, string(kb))
	return nil
}

func (m *fakeMap) Iterate() MapIterator {
	keys := make([][]byte, 0, len(m.entries))
	vals := make([][]byte, 0, len(m.entries))
	for k, v := range m.entries {
		keys = append(keys, []byte(k))
		vals = append(vals, v)
	}
	return &fakeMapIterator{keys: keys, vals: vals}
}

type fakeMapIterator struct {
	keys [][]byte
	vals [][]byte
	pos  int
}

func (it *fakeMapIterator) Next(keyOut, valueOut any) bool {
	if it.pos >= len(it.keys) {
		return false
	}
	*(keyOut.(*[]byte)) = it.keys[it.pos]
	*(valueOut.(*[]byte)) = it.vals[it.pos]
	it.pos++
	return true
}

func newTestMaps() (*banMaps, *fakeMap, *fakeMap, *fakeMap) {
	g := newFakeMap(banmap.MapGlobalBans)
	t := newFakeMap(banmap.MapTargetHosts)
	s := newFakeMap(banmap.MapSrcBans)

	boot := time.Now().Add(-time.Hour)
	return newBanMaps(g, t, s, boot), g, t, s
}

func TestApply_SingleHostGoesToGlobalMap(t *testing.T) {
	bm, global, targets, src := newTestMaps()

	err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600, ReqID: 42})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if global.puts != 1 {
		t.Errorf("全局表写入 %d 次,期望 1", global.puts)
	}
	if targets.puts != 0 || src.puts != 0 {
		t.Errorf("单点封禁不应碰定向表(targets=%d src=%d)", targets.puts, src.puts)
	}

	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.7/32"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Errorf("未找到期望的 key %v;实际键集合 %v", wantKey, keysOf(global))
	}
}

func TestApply_GlobalBanSupportsCIDR(t *testing.T) {
	bm, global, _, _ := newTestMaps()

	if err := bm.Apply(&BanPayload{Target: "203.0.113.0/24", TTLSecs: 0}); err != nil {
		t.Fatalf("Apply CIDR: %v", err)
	}

	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.0/24"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Errorf("网段封禁未写入正确的 key")
	}

	if got := binary.LittleEndian.Uint32(wantKey[0:4]); got != 24 {
		t.Errorf("prefixlen = %d,期望 24", got)
	}
}

func TestApply_ScopedWritesBothMaps(t *testing.T) {
	bm, global, targets, src := newTestMaps()

	err := bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     []string{"203.0.113.0/24", "198.51.100.0/24", "1.2.3.4"},
		TTLSecs:      3600,
		ReqID:        7,
	})
	if err != nil {
		t.Fatalf("Apply scoped: %v", err)
	}

	if targets.puts != 1 {
		t.Errorf("target_hosts 写入 %d 次,期望 1", targets.puts)
	}
	if src.puts != 3 {
		t.Errorf("src_ban 写入 %d 次,期望 3(每条源前缀一次)", src.puts)
	}
	if global.puts != 0 {
		t.Errorf("范围封禁不应写全局表")
	}

	for k := range src.entries {
		kb := []byte(k)
		if len(kb) != banmap.SrcKeySize {
			t.Fatalf("src key 长度 %d,期望 %d", len(kb), banmap.SrcKeySize)
		}
		pl := binary.LittleEndian.Uint32(kb[0:4])
		if pl < 32 {
			t.Errorf("prefixlen = %d < 32,target_id 不再是精确匹配", pl)
		}
		tid := binary.LittleEndian.Uint32(kb[4:8])
		if tid == 0 {
			t.Errorf("target_id 为 0 —— 0 应保留不用,以区分'未分配'")
		}
	}
}

func TestRevokeGlobal_DeletesPreviouslyAppliedKey(t *testing.T) {
	bm, global, _, _ := newTestMaps()

	if err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantKey, _ := banmap.EncodeGlobalKey(netip.MustParsePrefix("203.0.113.7/32"))
	if _, ok := global.entries[string(wantKey)]; !ok {
		t.Fatalf("Apply 后未找到 key,前提条件不满足")
	}

	if err := bm.RevokeGlobal("203.0.113.7"); err != nil {
		t.Fatalf("RevokeGlobal: %v", err)
	}
	if _, ok := global.entries[string(wantKey)]; ok {
		t.Errorf("RevokeGlobal 后 key 仍存在")
	}
}

func TestRevokeGlobal_NeverAppliedIsNotError(t *testing.T) {
	bm, _, _, _ := newTestMaps()

	if err := bm.RevokeGlobal("198.51.100.9"); err != nil {
		t.Errorf("撤销一个从未下发过的全局封禁应静默成功,实际报错: %v", err)
	}
}

func TestRevokeScoped_DeletesPreviouslyAppliedKeys(t *testing.T) {
	bm, _, _, src := newTestMaps()

	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24"}
	if err := bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     prefixes,
		TTLSecs:      3600,
	}); err != nil {
		t.Fatalf("Apply scoped: %v", err)
	}
	if src.puts != 2 {
		t.Fatalf("Apply 后 src puts = %d,期望 2", src.puts)
	}

	if err := bm.RevokeScoped("10.0.1.100", prefixes); err != nil {
		t.Fatalf("RevokeScoped: %v", err)
	}
	if len(src.entries) != 0 {
		t.Errorf("RevokeScoped 后 src_ban 仍残留 %d 条", len(src.entries))
	}
}

func TestRevokeScoped_UnknownTargetIsNotError(t *testing.T) {
	bm, _, _, _ := newTestMaps()

	err := bm.RevokeScoped("10.0.1.200", []string{"203.0.113.0/24"})
	if err != nil {
		t.Errorf("撤销一个从未 ensureTarget 过的目标应静默成功(target_id 映射非持久化),实际报错: %v", err)
	}
}

func TestEnsureTarget_ReusesID(t *testing.T) {
	bm, _, targets, _ := newTestMaps()

	addr := netip.MustParseAddr("10.0.1.100")
	id1, err := bm.ensureTarget(addr)
	if err != nil {
		t.Fatalf("ensureTarget: %v", err)
	}
	id2, err := bm.ensureTarget(addr)
	if err != nil {
		t.Fatalf("ensureTarget 二次: %v", err)
	}

	if id1 != id2 {
		t.Errorf("同一目标分配了不同 id: %d vs %d", id1, id2)
	}
	if targets.puts != 1 {
		t.Errorf("target_hosts 被重复写入 %d 次", targets.puts)
	}

	id3, _ := bm.ensureTarget(netip.MustParseAddr("10.0.1.200"))
	if id3 == id1 {
		t.Errorf("不同目标复用了同一 id %d", id1)
	}
}

func TestApply_MapFullReturnsError(t *testing.T) {
	bm, global, _, src := newTestMaps()
	global.putErr = fmt.Errorf("argument list too long")

	err := bm.Apply(&BanPayload{Target: "203.0.113.7", TTLSecs: 600})
	if err == nil {
		t.Fatal("map 满时必须返回错误")
	}

	src.putErr = fmt.Errorf("argument list too long")
	err = bm.Apply(&BanPayload{
		ScopedTarget: "10.0.1.100",
		Prefixes:     []string{"1.0.0.0/8", "2.0.0.0/8"},
	})
	if err == nil {
		t.Fatal("src_ban 满时必须返回错误")
	}
	if !contains(err.Error(), "已写入") {
		t.Errorf("错误信息应说明已写入条数,便于判断部分生效范围,实际: %v", err)
	}
}

func TestKtimeDeadline_UsesUptimeNotUnix(t *testing.T) {
	boot := time.Now().Add(-2 * time.Hour)
	now := time.Now()

	got := banmap.KtimeDeadline(boot, now, 600)

	wantLow := uint64((2*time.Hour + 590*time.Second).Nanoseconds())
	wantHigh := uint64((2*time.Hour + 610*time.Second).Nanoseconds())
	if got < wantLow || got > wantHigh {
		t.Errorf("deadline = %d ns,期望约 %d..%d(uptime + TTL)", got, wantLow, wantHigh)
	}

	if got > uint64(1e17) {
		t.Errorf("deadline = %d 看起来是 Unix 时间而非 ktime,所有 TTL 判断都会错", got)
	}
}

func TestKtimeDeadline_ZeroTTLMeansPermanent(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	for _, ttl := range []int64{0, -1, -3600} {
		if got := banmap.KtimeDeadline(boot, time.Now(), ttl); got != 0 {
			t.Errorf("TTL=%d 应表示永久(deadline=0),实际 %d", ttl, got)
		}
	}
}

func TestApply_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		payload BanPayload
	}{
		{"空目标", BanPayload{Target: ""}},
		{"非法目标", BanPayload{Target: "not-an-ip"}},
		{"IPv6 目标", BanPayload{Target: "2001:db8::1"}},
		{"范围封禁目标非法", BanPayload{ScopedTarget: "bad", Prefixes: []string{"1.0.0.0/8"}}},
		{"范围封禁目标为网段", BanPayload{ScopedTarget: "10.0.0.0/8", Prefixes: []string{"1.0.0.0/8"}}},
		{"范围封禁前缀非法", BanPayload{ScopedTarget: "10.0.1.1", Prefixes: []string{"garbage"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bm, _, _, _ := newTestMaps()
			if err := bm.Apply(&tc.payload); err == nil {
				t.Errorf("应拒绝: %+v", tc.payload)
			}
		})
	}
}

func TestValueLayout_MatchesKernelStruct(t *testing.T) {
	v := banmap.Value{ExpiresAt: 0x1122334455667788, Hits: 42, RuleID: 7}
	b := banmap.EncodeValue(v)

	if len(b) != banmap.ValueSize {
		t.Fatalf("value 长度 %d,期望 %d(u64+u64+u32+pad)", len(b), banmap.ValueSize)
	}
	back, err := banmap.DecodeValue(b)
	if err != nil {
		t.Fatalf("DecodeValue: %v", err)
	}
	if back != v {
		t.Errorf("编解码不一致: %+v → %+v", v, back)
	}
}

func keysOf(m *fakeMap) [][]byte {
	out := make([][]byte, 0, len(m.entries))
	for k := range m.entries {
		out = append(out, []byte(k))
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
