package main

import (
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

type mapWriter interface {
	Put(key, value any) error
	Delete(key any) error
}

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
