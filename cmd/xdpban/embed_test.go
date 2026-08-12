package main

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/xdpban/xdp-ban/internal/banmap"
)

func TestEmbeddedBytecodeHasRequiredMaps(t *testing.T) {
	if len(xdpFilterBytecode) == 0 {
		t.Skip("obj/xdp_filter.o 为占位空文件;在有 clang 的环境执行 `make bpf` 后此测试才有意义")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		t.Fatalf("内嵌 bytecode 无法解析: %v", err)
	}

	for _, name := range []string{
		banmap.MapGlobalBans, banmap.MapTargetHosts,
		banmap.MapSrcBans, banmap.MapCounters,
	} {
		m, ok := spec.Maps[name]
		if !ok {
			t.Errorf("内嵌 bytecode 缺少 map %q —— xdp-ban 启动会 Fatalf", name)
			continue
		}
		t.Logf("✓ %s: %s, max_entries=%d", name, m.Type, m.MaxEntries)
	}

	if m, ok := spec.Maps[banmap.MapSrcBans]; ok {
		const want = 262144
		if m.MaxEntries != want {
			t.Errorf("%s max_entries=%d,期望 %d(须与 quota.MapCapacity 一致)",
				banmap.MapSrcBans, m.MaxEntries, want)
		}
	}

	if _, ok := spec.Programs["xdp_filter"]; !ok {
		t.Error("内嵌 bytecode 缺少 xdp_filter 程序")
	}
}
