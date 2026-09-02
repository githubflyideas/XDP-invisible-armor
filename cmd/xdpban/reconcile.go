package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/banmap"
	"github.com/xdpban/xdp-ban/internal/model"
)

// reconcile 比对 DB 里标记为 acked 的全局封禁 dispatch 与 eBPF map 里实际存活的前缀,
// 检测两者是否漂移。只检测,不自动重新下发——自动修复可能掩盖合法的撤销竞态或
// 误判正常过期,超出这次的范围。返回可读的 drift 描述列表。
//
// 只覆盖全局封禁(BanPayload.ScopedTarget == ""):定向封禁写入 src_ban,其 key
// 依赖进程内存态的 target_id 映射(重启后丢失,已知限制),回读核对意义不大。
func reconcile(db *gorm.DB, bm *banMaps) []string {
	var dispatches []model.Dispatch
	if err := db.Where("state = ?", "acked").Find(&dispatches).Error; err != nil {
		log.Printf("reconcile: 查询 acked dispatch 失败: %v", err)
		return nil
	}

	live, err := bm.ListGlobalBans()
	if err != nil {
		log.Printf("reconcile: 读取 eBPF map 失败: %v", err)
		return nil
	}

	now := time.Now()
	var drifts []string

	for _, d := range dispatches {
		var payload BanPayload
		if err := json.Unmarshal([]byte(d.Payload), &payload); err != nil {
			log.Printf("reconcile: 指令 #%d payload 解析失败: %v", d.ID, err)
			continue
		}
		if payload.ScopedTarget != "" {
			continue
		}

		prefix, err := banmap.ParseIPv4Prefix(payload.Target)
		if err != nil {
			log.Printf("reconcile: 指令 #%d 目标 %q 解析失败: %v", d.ID, payload.Target, err)
			continue
		}

		if live[prefix.String()] {
			continue
		}

		// TTL>0 的封禁由 eBPF 侧自然过期,到期后 map 里找不到是预期行为,不是漂移。
		// 过期基准取 AckedAt(真正写进 map 的时刻),缺失时退回 CreatedAt。
		//
		// 注意:不能用 banmap.KtimeDeadline 反推——它算的是"从现在起 TTL 秒后到期",
		// 每次调用都会把到期时刻推到未来,拿它做过期判断永远为假。
		//
		// 主机重启后 map 全空,此时未到期的 acked 记录会集中报漂移。这是有意的:
		// 封禁没能跨重启存活,值得被看到。
		if payload.TTLSecs > 0 {
			appliedAt := d.CreatedAt
			if d.AckedAt != nil {
				appliedAt = *d.AckedAt
			}
			if now.After(appliedAt.Add(time.Duration(payload.TTLSecs) * time.Second)) {
				continue
			}
		}

		detail := fmt.Sprintf("dispatch_id=%d ban_id=%s target=%s",
			d.ID, d.BanID, payload.Target)
		drifts = append(drifts, fmt.Sprintf(
			"DB 记录 dispatch #%d (ban_id=%s) 状态为 acked,但目标 %s 在 eBPF map 中未找到",
			d.ID, d.BanID, payload.Target))
		_ = model.WriteAudit(db, nil, "reconciler", "Dispatch", d.BanID, "drift_detected", detail)
	}

	return drifts
}
