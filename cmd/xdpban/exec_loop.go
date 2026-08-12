package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/banmap"
	"github.com/xdpban/xdp-ban/internal/model"
)

type BanPayload struct {
	Target  string `json:"target"`
	TTLSecs int64  `json:"ttl_secs"`
	NodeID  string `json:"node_id"`
	ReqID   uint   `json:"req_id"`
	BanID   string `json:"ban_id"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`

	ScopedTarget string   `json:"scoped_target,omitempty"`
	Prefixes     []string `json:"prefixes,omitempty"`
}

func startExecutor(db *gorm.DB, iface string) (*banMaps, func()) {
	if len(xdpFilterBytecode) == 0 {
		log.Fatalf("嵌入的 eBPF bytecode 为空:请先运行 `make bpf` 编译 bpf/xdp_filter.c,再重新构建本程序")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpFilterBytecode))
	if err != nil {
		log.Fatalf("load ebpf spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("create ebpf collection: %v", err)
	}

	maps, err := resolveMaps(coll)
	if err != nil {
		coll.Close()
		log.Fatalf("%v", err)
	}
	log.Printf("✓ eBPF map 就绪: %s / %s / %s",
		banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans)

	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		log.Fatalf("查找网卡 %q 失败: %v", iface, err)
	}

	prog := coll.Programs["xdp_filter"]
	if prog == nil {
		coll.Close()
		log.Fatalf("内嵌 bytecode 缺少 xdp_filter 程序 —— bytecode 与本程序版本不匹配")
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifc.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		log.Fatalf("attach XDP(generic 模式)到 %s 失败: %v ——"+
			"常见原因:权限不足(需 root/CAP_NET_ADMIN)、内核过旧不支持 generic XDP、"+
			"或已有另一个 XDP 程序占用该网卡", iface, err)
	}
	log.Printf("✓ XDP 封禁程序已以 generic 模式挂载到 %s", iface)

	boot, err := systemBootTime()
	if err != nil {
		lnk.Close()
		coll.Close()
		log.Fatalf("读取系统启动时刻(TTL 换算依赖它): %v", err)
	}
	log.Printf("✓ 系统启动于 %s,TTL 将换算为 ktime 基准", boot.Format(time.RFC3339))

	bm := newBanMaps(
		maps[banmap.MapGlobalBans],
		maps[banmap.MapTargetHosts],
		maps[banmap.MapSrcBans],
		boot,
	)

	closeFn := func() {
		lnk.Close()
		coll.Close()
	}
	return bm, closeFn
}

func runExecutorLoop(db *gorm.DB, bm *banMaps, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		pollAndExecute(db, bm)
	}
}

func pollAndExecute(db *gorm.DB, bm *banMaps) {
	var dispatches []model.Dispatch
	if err := db.Where("state = ?", "pending").Limit(50).Find(&dispatches).Error; err != nil {
		log.Printf("查询待执行 dispatch 失败: %v", err)
		return
	}
	if len(dispatches) == 0 {
		return
	}
	log.Printf("获取 %d 条待执行指令", len(dispatches))

	for _, d := range dispatches {
		var payload BanPayload
		if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
			log.Printf("指令 #%d payload 解析失败: %v", d.ID, err)
			markFailed(db, &d, fmt.Sprintf("parse error: %v", err))
			continue
		}

		log.Printf("执行指令 #%d: %s", d.ID, describePayload(&payload))

		if err := bm.Apply(&payload); err != nil {
			log.Printf("指令 #%d 执行失败: %v", d.ID, err)
			markFailed(db, &d, err.Error())
			continue
		}

		markAcked(db, &d)
		log.Printf("指令 #%d 执行成功", d.ID)
	}
}

func describePayload(p *BanPayload) string {
	if p.ScopedTarget != "" {
		return fmt.Sprintf("范围封禁 %d 条源前缀 → %s (TTL=%ds)",
			len(p.Prefixes), p.ScopedTarget, p.TTLSecs)
	}
	return fmt.Sprintf("全局封禁 %s (TTL=%ds)", p.Target, p.TTLSecs)
}

func markAcked(db *gorm.DB, d *model.Dispatch) {
	now := time.Now()
	if err := db.Model(d).Updates(map[string]any{
		"state":    "acked",
		"acked_at": now,
	}).Error; err != nil {
		log.Printf("指令 #%d 标记 acked 失败: %v", d.ID, err)
		return
	}
	_ = model.WriteAudit(db, nil, "executor", "Dispatch", strconv.FormatUint(uint64(d.ID), 10), "acked", "")
}

func markFailed(db *gorm.DB, d *model.Dispatch, errMsg string) {
	if err := db.Model(d).Updates(map[string]any{
		"state":      "failed",
		"last_error": errMsg,
		"attempts":   d.Attempts + 1,
	}).Error; err != nil {
		log.Printf("指令 #%d 标记 failed 失败: %v", d.ID, err)
		return
	}
	_ = model.WriteAudit(db, nil, "executor", "Dispatch", strconv.FormatUint(uint64(d.ID), 10), "failed", errMsg)
}

func resolveMaps(coll *ebpf.Collection) (map[string]*ebpf.Map, error) {
	want := []string{banmap.MapGlobalBans, banmap.MapTargetHosts, banmap.MapSrcBans}
	out := make(map[string]*ebpf.Map, len(want))
	var missing []string
	for _, name := range want {
		m := coll.Maps[name]
		if m == nil {
			missing = append(missing, name)
			continue
		}
		out[name] = m
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("eBPF bytecode 中缺少 map: %s —— "+
			"bytecode 与本程序版本不匹配,请重新 `make bpf && make build`",
			strings.Join(missing, ", "))
	}
	return out, nil
}

func systemBootTime() (time.Time, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return time.Time{}, fmt.Errorf("/proc/uptime 格式异常: %q", string(b))
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析 uptime %q: %w", fields[0], err)
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second))), nil
}
