package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/xdpban/xdp-ban/internal/model"
	"github.com/xdpban/xdp-ban/internal/policy"
	"github.com/xdpban/xdp-ban/internal/prefixdb"
	"github.com/xdpban/xdp-ban/internal/web"
)

var Version = "dev"

func main() {
	dbPath := env("XDPBAN_DB", "xdpban.db")
	addr := env("XDPBAN_ADDR", ":8080")

	ifaceFlag := flag.String("iface", "", "XDP 封禁程序挂载的网卡(业务口,不是采样镜像口)")
	pollInterval := flag.Duration("poll-interval", 5*time.Second, "扫描待执行 dispatch 的间隔")
	flag.Parse()

	iface := *ifaceFlag
	if iface == "" {
		iface = os.Getenv("XDPBAN_IFACE")
	}
	if iface == "" {
		log.Fatalf("必须指定 XDP 封禁网卡:-iface <ifname> 或环境变量 XDPBAN_IFACE。" +
			"这是执行层生效的前提,没有它封禁只会停留在审批记录里,不会真正拦截流量。")
	}

	log.Printf("xdp-ban %s starting", Version)

	db, err := model.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	seed(db)

	loadPrefixDB()

	bm, closeXDP := startExecutor(db, iface)
	defer closeXDP()
	go runExecutorLoop(db, bm, *pollInterval)

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	web.Register(r, db)

	if web.PprofEnabled() {
		web.RegisterPprof(r)
		log.Printf("pprof 已启用: %s/debug/pprof/ (务必仅绑定内网)", addr)
	}

	log.Printf("xdp-ban listening on %s (db=%s, xdp iface=%s)", addr, dbPath, iface)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadPrefixDB() {
	candidates := []string{}
	if p := os.Getenv("XDPBAN_PREFIX_DB"); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, prefixdb.ActivePath())

	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		pdb, err := prefixdb.Load(p)
		if err != nil {
			log.Printf("加载前缀库 %s 失败: %v", p, err)
			continue
		}
		prefixdb.SetGlobal(pdb)
		st := pdb.Stats()
		log.Printf("前缀库已加载(%s): %d 条区间, %d 个国家, %d 个 AS",
			p, st.Entries, st.Countries, st.ASNs)

		if err := prefixdb.Reload(); err != nil && p == prefixdb.ActivePath() {
			log.Printf("应用本地覆盖规则: %v", err)
		}
		return
	}
	log.Printf("未找到 IP 前缀库,按国家/AS 封禁功能不可用 —— 可在界面「IP 库管理」中同步或上传")
}

func seed(db *gorm.DB) {
	var n int64
	db.Model(&model.User{}).Count(&n)
	if n > 0 {
		return
	}
	accounts := []struct{ u, r, p string }{
		{"admin", "admin", "admin12345"},
		{"approver", "approver", "approver12345"},
		{"operator", "operator", "operator12345"},
		{"viewer", "viewer", "viewer12345"},
	}
	for _, a := range accounts {
		u := &model.User{Username: a.u, Role: a.r, Active: true, AuthSource: "local",
			Email: a.u + "@example.com"}
		_ = u.SetPassword(a.p)
		db.Create(u)
	}
	for _, p := range []struct{ t, l string }{
		{"127.0.0.0/8", "环回(硬保护)"},
		{"::1/128", "IPv6 环回"},
		{"8.8.8.8", "公共DNS示例"},
	} {
		db.Create(&model.ProtectedTarget{Target: p.t, Label: p.l, Active: true})
	}
	_ = policy.Roles
	log.Println("seeded default accounts (change passwords!)")
}

var _ = http.StatusOK
