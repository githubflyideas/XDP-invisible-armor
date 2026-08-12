package web

import (
	"net/http/pprof"
	"runtime"

	"github.com/gin-gonic/gin"
)

func RegisterPprof(r *gin.Engine) {

	runtime.SetBlockProfileRate(10000)
	runtime.SetMutexProfileFraction(100)

	g := r.Group("/debug/pprof")
	g.GET("/", gin.WrapF(pprof.Index))
	g.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	g.GET("/profile", gin.WrapF(pprof.Profile))
	g.GET("/symbol", gin.WrapF(pprof.Symbol))
	g.POST("/symbol", gin.WrapF(pprof.Symbol))
	g.GET("/trace", gin.WrapF(pprof.Trace))

	for _, name := range []string{"heap", "goroutine", "block", "mutex", "threadcreate", "allocs"} {
		g.GET("/"+name, gin.WrapH(pprof.Handler(name)))
	}
}

func PprofEnabled() bool {
	return envOr("XDPBAN_PPROF", "") != ""
}
