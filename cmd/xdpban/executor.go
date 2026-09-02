package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

type mapWriter interface {
	Put(key, value any) error
	Delete(key any) error
	Iterate() MapIterator
}

// MapIterator 抽象掉 map 遍历,让 banMaps 不直接依赖 cilium/ebpf 的具体类型,
// 测试里用切片实现一个假的即可。
type MapIterator interface {
	Next(keyOut, valueOut any) bool
}

// ebpfMap 把 *ebpf.Map 适配到 mapWriter。
// 不能直接把 *ebpf.Map 当 mapWriter 用:它的 Iterate() 返回具体类型
// *ebpf.MapIterator,而 Go 的接口满足不做返回值协变——即使
// *ebpf.MapIterator 本身满足 MapIterator,方法签名也必须逐字一致。
// Put/Delete 通过嵌入直接提升,只有 Iterate 需要转一层。
type ebpfMap struct {
	*ebpf.Map
}

func (m ebpfMap) Iterate() MapIterator { return m.Map.Iterate() }

type banMaps struct {
	globalBans  mapWriter
	targetHosts mapWriter
	srcBans     mapWriter

	bootTime time.Time

	nextTargetID uint32
	targetIDs    map[string]uint32
}

func newBanMaps(global, targets, src mapWriter, bootTime time.Time) *banMaps {
	return &banMaps{
		globalBans:   global,
		targetHosts:  targets,
		srcBans:      src,
		bootTime:     bootTime,
		nextTargetID: 1,
		targetIDs:    make(map[string]uint32),
	}
}

type ScopedPayload struct {
	TargetIP string   `json:"target_ip"`
	Prefixes []string `json:"prefixes"`
}

func (m *banMaps) Apply(p *BanPayload) error {
	deadline := banmap.KtimeDeadline(m.bootTime, time.Now(), p.TTLSecs)
	val := banmap.EncodeValue(banmap.Value{
		ExpiresAt: deadline,
		RuleID:    uint32(p.ReqID),
	})

	if p.ScopedTarget != "" {
		return m.applyScoped(p, val)
	}

	prefix, err := banmap.ParseIPv4Prefix(p.Target)
	if err != nil {
		return err
	}
	key, err := banmap.EncodeGlobalKey(prefix)
	if err != nil {
		return err
	}
	if err := m.globalBans.Put(key, val); err != nil {
		return fmt.Errorf("写 %s (%s): %w", banmap.MapGlobalBans, prefix, err)
	}
	log.Printf("  ✓ 全局封禁 %s (TTL=%ds)", prefix, p.TTLSecs)
	return nil
}

func (m *banMaps) applyScoped(p *BanPayload, val []byte) error {
	targetAddr, err := netip.ParseAddr(p.ScopedTarget)
	if err != nil {
		return fmt.Errorf("非法目标主机 %q: %w", p.ScopedTarget, err)
	}
	if !targetAddr.Is4() {
		return fmt.Errorf("目标仅支持 IPv4: %q", p.ScopedTarget)
	}

	tid, err := m.ensureTarget(targetAddr)
	if err != nil {
		return err
	}

	var written int
	for _, s := range p.Prefixes {
		prefix, err := banmap.ParseIPv4Prefix(s)
		if err != nil {
			return fmt.Errorf("第 %d 条前缀: %w(已写入 %d 条)", written+1, err, written)
		}
		key, err := banmap.EncodeSrcKey(tid, prefix)
		if err != nil {
			return fmt.Errorf("第 %d 条前缀: %w(已写入 %d 条)", written+1, err, written)
		}
		if err := m.srcBans.Put(key, val); err != nil {

			return fmt.Errorf("写 %s (%s → %s): %w(已写入 %d 条)",
				banmap.MapSrcBans, prefix, targetAddr, err, written)
		}
		written++
	}

	log.Printf("  ✓ 定向封禁 %d 条源前缀 → %s (target_id=%d, TTL=%ds)",
		written, targetAddr, tid, p.TTLSecs)
	return nil
}

func (m *banMaps) RevokeGlobal(target string) error {
	prefix, err := banmap.ParseIPv4Prefix(target)
	if err != nil {
		return err
	}
	key, err := banmap.EncodeGlobalKey(prefix)
	if err != nil {
		return err
	}
	if err := m.globalBans.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("删除 %s (%s): %w", banmap.MapGlobalBans, prefix, err)
	}
	log.Printf("  ✓ 已回滚全局封禁 %s", prefix)
	return nil
}

func (m *banMaps) RevokeScoped(targetIP string, prefixes []string) error {
	targetAddr, err := netip.ParseAddr(targetIP)
	if err != nil {
		return fmt.Errorf("非法目标主机 %q: %w", targetIP, err)
	}
	if !targetAddr.Is4() {
		return fmt.Errorf("目标仅支持 IPv4: %q", targetIP)
	}

	tid, ok := m.targetIDs[targetAddr.String()]
	if !ok {

		return nil
	}

	for _, s := range prefixes {
		prefix, err := banmap.ParseIPv4Prefix(s)
		if err != nil {
			return fmt.Errorf("非法前缀 %q: %w", s, err)
		}
		key, err := banmap.EncodeSrcKey(tid, prefix)
		if err != nil {
			return err
		}
		if err := m.srcBans.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("删除 %s (%s → %s): %w", banmap.MapSrcBans, prefix, targetAddr, err)
		}
	}
	log.Printf("  ✓ 已回滚定向封禁 %d 条源前缀 → %s (target_id=%d)", len(prefixes), targetAddr, tid)
	return nil
}

func (m *banMaps) ensureTarget(addr netip.Addr) (uint32, error) {
	s := addr.String()
	if tid, ok := m.targetIDs[s]; ok {
		return tid, nil
	}

	tid := m.nextTargetID
	key, err := banmap.EncodeTargetKey(addr)
	if err != nil {
		return 0, err
	}
	if err := m.targetHosts.Put(key, banmap.EncodeTargetID(tid)); err != nil {
		return 0, fmt.Errorf("写 %s (%s): %w", banmap.MapTargetHosts, addr, err)
	}

	m.targetIDs[s] = tid
	m.nextTargetID++
	return tid, nil
}

// ListGlobalBans 遍历 src_ban_global map,返回当前存活的全局封禁前缀集合
// (键为前缀的字符串表示,如 "203.0.113.0/24")。用于与 DB 侧 dispatch 记录做回读核对。
func (m *banMaps) ListGlobalBans() (map[string]bool, error) {
	out := make(map[string]bool)
	it := m.globalBans.Iterate()
	var key, val []byte
	for it.Next(&key, &val) {
		prefix, err := banmap.DecodeGlobalKey(key)
		if err != nil {
			return nil, fmt.Errorf("解码 %s key 失败: %w", banmap.MapGlobalBans, err)
		}
		out[prefix.String()] = true
	}
	return out, nil
}
