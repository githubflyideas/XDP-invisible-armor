package web

import (
	"embed"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// faviconFS 把 favicon 编进二进制。
//
// 原先这里是 r.StaticFile("/favicon.ico", "favicon.ico"),从进程工作目录读文件——
// 而仓库里根本没有这个文件,所以浏览器一直拿到 404,而且行为还取决于从哪个目录启动。
// 单文件部署就不该有这种运行时磁盘依赖:HTML 模板本来就是 Go 字符串常量,
// 图标是最后一块,一起编进来。
//
//go:embed assets/favicon.ico
var faviconFS embed.FS

var faviconBytes = func() []byte {
	b, err := faviconFS.ReadFile("assets/favicon.ico")
	if err != nil {
		// 走不到:embed 在编译期就会因为文件缺失而报错。
		panic(err)
	}
	return b
}()

// buildTime 给 favicon 的 Last-Modified 用。进程启动时刻足够了——
// 二进制换了就是新进程,缓存自然失效。
var buildTime = time.Now()

func serveFavicon(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=86400")
	c.Header("Last-Modified", buildTime.UTC().Format(http.TimeFormat))
	c.Data(http.StatusOK, "image/x-icon", faviconBytes)
}
