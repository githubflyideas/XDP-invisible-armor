package safety

import (
	"fmt"
	"net/netip"
)

type Guard struct {
	protected []netip.Prefix
}

func New(extra []string) *Guard {
	g := &Guard{}

	for _, c := range []string{"127.0.0.0/8", "::1/128", "0.0.0.0/32"} {
		if p, err := netip.ParsePrefix(c); err == nil {
			g.protected = append(g.protected, p)
		}
	}
	g.Add(extra...)
	return g
}

func (g *Guard) Add(targets ...string) {
	for _, t := range targets {
		if p, err := toPrefix(t); err == nil {
			g.protected = append(g.protected, p)
		}
	}
}

func (g *Guard) AssertSafe(target string) error {
	t, err := toPrefix(target)
	if err != nil {

		return fmt.Errorf("SAFETY VETO: 目标 %s 非法或无法判定(%v),保守否决", target, err)
	}
	for _, p := range g.protected {

		if p.Overlaps(t) {
			return fmt.Errorf("SAFETY VETO: 目标 %s 命中绝对保护集(%s),封禁被最终否决", target, p)
		}
	}
	return nil
}

func (g *Guard) VetoReason(target string) string {
	if err := g.AssertSafe(target); err != nil {
		return err.Error()
	}
	return ""
}

func (g *Guard) AssertSafeAll(targets []netip.Prefix) error {
	for _, t := range targets {
		for _, p := range g.protected {
			if p.Overlaps(t) {
				return fmt.Errorf("SAFETY VETO: 前缀 %s 命中绝对保护集(%s),封禁被最终否决", t, p)
			}
		}
	}
	return nil
}

func (g *Guard) VetoReasonAll(targets []netip.Prefix) string {
	if err := g.AssertSafeAll(targets); err != nil {
		return err.Error()
	}
	return ""
}

func toPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}
