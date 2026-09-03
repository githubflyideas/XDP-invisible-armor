package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
)

// 这里曾经还有一个 errSelfApproval,以及 selfActionDenied/denySelfAction 一对辅助函数,
// 用来实现四眼原则(审批人 ≠ 申请人)。已按单人使用的定位移除:提交和审批本来就是同一个人,
// 强行要求两个账号只会逼出"建个小号点批准"这种把审计搞脏的用法。
//
// 保留下来的是"提交 → pending → 批准"这个两步流程本身:它仍然给出一次改主意的机会,
// 并且让审计日志能分辨"什么时候申请"和"什么时候真正生效"。
var errStateConflict = errors.New("state conflict")

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func itoa(u uint) string { return strconv.FormatUint(uint64(u), 10) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
