package banmap

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const (
	MapGlobalBans  = "src_ban_global"
	MapTargetHosts = "target_hosts"
	MapSrcBans     = "src_ban"
	MapCounters    = "counters"
)

const (
	GlobalKeySize = 8
	SrcKeySize    = 12
	TargetKeySize = 4
	ValueSize     = 24
)

const (
	CntDropped = iota
	CntPassed
	CntExpired
	CntNotTarget
	CntMax
)

type Value struct {
	ExpiresAt uint64
	Hits      uint64
	RuleID    uint32
}

func EncodeValue(v Value) []byte {
	b := make([]byte, ValueSize)
	binary.LittleEndian.PutUint64(b[0:8], v.ExpiresAt)
	binary.LittleEndian.PutUint64(b[8:16], v.Hits)
	binary.LittleEndian.PutUint32(b[16:20], v.RuleID)

	return b
}

func DecodeValue(b []byte) (Value, error) {
	if len(b) < ValueSize {
		return Value{}, fmt.Errorf("ban_value 长度 %d,期望 %d", len(b), ValueSize)
	}
	return Value{
		ExpiresAt: binary.LittleEndian.Uint64(b[0:8]),
		Hits:      binary.LittleEndian.Uint64(b[8:16]),
		RuleID:    binary.LittleEndian.Uint32(b[16:20]),
	}, nil
}

func EncodeGlobalKey(prefix netip.Prefix) ([]byte, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 前缀,收到 %s", prefix)
	}
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return nil, fmt.Errorf("非法前缀长度 %d", bits)
	}

	p := prefix.Masked()
	a4 := p.Addr().As4()

	b := make([]byte, GlobalKeySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(bits))
	copy(b[4:8], a4[:])
	return b, nil
}

func DecodeGlobalKey(b []byte) (netip.Prefix, error) {
	if len(b) < GlobalKeySize {
		return netip.Prefix{}, fmt.Errorf("global_key 长度 %d,期望 %d", len(b), GlobalKeySize)
	}
	bits := binary.LittleEndian.Uint32(b[0:4])
	if bits > 32 {
		return netip.Prefix{}, fmt.Errorf("非法前缀长度 %d", bits)
	}
	var a4 [4]byte
	copy(a4[:], b[4:8])
	addr := netip.AddrFrom4(a4)
	return netip.PrefixFrom(addr, int(bits)), nil
}

func EncodeSrcKey(targetID uint32, prefix netip.Prefix) ([]byte, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("仅支持 IPv4 前缀,收到 %s", prefix)
	}
	srcBits := prefix.Bits()
	if srcBits < 0 || srcBits > 32 {
		return nil, fmt.Errorf("非法前缀长度 %d", srcBits)
	}

	p := prefix.Masked()
	a4 := p.Addr().As4()

	b := make([]byte, SrcKeySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(32+srcBits))
	binary.LittleEndian.PutUint32(b[4:8], targetID)
	copy(b[8:12], a4[:])
	return b, nil
}

func EncodeTargetKey(addr netip.Addr) ([]byte, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("目标仅支持 IPv4,收到 %s", addr)
	}
	a4 := addr.As4()
	b := make([]byte, TargetKeySize)
	copy(b, a4[:])
	return b, nil
}

func EncodeTargetID(id uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, id)
	return b
}

func KtimeDeadline(bootTime time.Time, now time.Time, ttlSecs int64) uint64 {
	if ttlSecs <= 0 {
		return 0
	}
	uptime := now.Sub(bootTime)
	if uptime < 0 {
		uptime = 0
	}
	return uint64(uptime) + uint64(ttlSecs)*uint64(time.Second)
}

func ParseIPv4Prefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6: %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("非法地址或前缀: %q", s)
	}
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("暂不支持 IPv6: %q", s)
	}
	return netip.PrefixFrom(a, 32), nil
}
