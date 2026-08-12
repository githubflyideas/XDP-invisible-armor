package prefixdb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Source struct {
	ID      string
	Name    string
	URL     string
	Format  string
	License string
	Note    string
}

var Sources = []Source{
	{
		ID: "apnic", Name: "APNIC 分配记录(亚太)",
		URL:    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
		Format: "rir_delegated", License: "APNIC 开放数据",
		Note: "亚太地区权威注册数据,含国家但不含 AS;归属口径为注册而非路由",
	},
	{
		ID: "ripe", Name: "RIPE NCC 分配记录(欧洲/中东)",
		URL:    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
		Format: "rir_delegated", License: "RIPE 开放数据",
		Note: "欧洲与中东地区权威注册数据",
	},
	{
		ID: "arin", Name: "ARIN 分配记录(北美)",
		URL:    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
		Format: "rir_delegated", License: "ARIN 开放数据",
		Note: "北美地区权威注册数据",
	},
}

func SourceByID(id string) (Source, bool) {
	for _, s := range Sources {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

type SyncStatus struct {
	InProgress bool
	SourceID   string
	StartedAt  time.Time
	FinishedAt time.Time
	BytesRead  int64
	Entries    int
	Err        string
}

var (
	syncMu     sync.RWMutex
	syncStatus SyncStatus
)

func Status() SyncStatus {
	syncMu.RLock()
	defer syncMu.RUnlock()
	return syncStatus
}

func DataDir() string {
	if d := os.Getenv("XDPBAN_DATA_DIR"); d != "" {
		return d
	}
	return "./data"
}

func ActivePath() string { return filepath.Join(DataDir(), "prefixdb.tsv") }

func OverridePath() string { return filepath.Join(DataDir(), "overrides.tsv") }

func SyncFrom(src Source) error {
	syncMu.Lock()
	if syncStatus.InProgress {
		syncMu.Unlock()
		return fmt.Errorf("已有同步任务在进行中")
	}
	syncStatus = SyncStatus{InProgress: true, SourceID: src.ID, StartedAt: time.Now()}
	syncMu.Unlock()

	finish := func(entries int, n int64, err error) error {
		syncMu.Lock()
		syncStatus.InProgress = false
		syncStatus.FinishedAt = time.Now()
		syncStatus.Entries = entries
		syncStatus.BytesRead = n
		if err != nil {
			syncStatus.Err = err.Error()
		}
		syncMu.Unlock()
		return err
	}

	if err := os.MkdirAll(DataDir(), 0o755); err != nil {
		return finish(0, 0, fmt.Errorf("创建数据目录: %w", err))
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(src.URL)
	if err != nil {
		return finish(0, 0, fmt.Errorf("下载 %s: %w", src.URL, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return finish(0, 0, fmt.Errorf("下载 %s 返回 %d", src.URL, resp.StatusCode))
	}

	tmp, err := os.CreateTemp(DataDir(), ".sync-*.tmp")
	if err != nil {
		return finish(0, 0, fmt.Errorf("创建临时文件: %w", err))
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	n, err := io.Copy(tmp, resp.Body)
	tmp.Close()
	if err != nil {
		return finish(0, n, fmt.Errorf("写入临时文件: %w", err))
	}

	normalized := tmpName + ".norm"
	entries, err := normalize(tmpName, normalized, src.Format)
	if err != nil {
		return finish(0, n, fmt.Errorf("解析 %s 数据: %w", src.Format, err))
	}
	defer os.Remove(normalized)

	if err := os.Rename(normalized, ActivePath()); err != nil {
		return finish(entries, n, fmt.Errorf("启用新库: %w", err))
	}

	if err := Reload(); err != nil {
		return finish(entries, n, fmt.Errorf("重新加载: %w", err))
	}
	return finish(entries, n, nil)
}

func ImportUpload(r io.Reader, format string) (int, error) {
	if err := os.MkdirAll(DataDir(), 0o755); err != nil {
		return 0, fmt.Errorf("创建数据目录: %w", err)
	}

	tmp, err := os.CreateTemp(DataDir(), ".upload-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("创建临时文件: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("接收上传: %w", err)
	}
	tmp.Close()

	normalized := tmpName + ".norm"
	entries, err := normalize(tmpName, normalized, format)
	if err != nil {
		return 0, fmt.Errorf("解析上传文件: %w", err)
	}
	defer os.Remove(normalized)

	if err := os.Rename(normalized, ActivePath()); err != nil {
		return entries, fmt.Errorf("启用新库: %w", err)
	}
	if err := Reload(); err != nil {
		return entries, fmt.Errorf("重新加载: %w", err)
	}
	return entries, nil
}

func Reload() error {
	db, err := Load(ActivePath())
	if err != nil {
		return err
	}
	if n, err := db.applyOverrides(OverridePath()); err != nil {

		return fmt.Errorf("主库已加载,但本地覆盖文件有误(已忽略): %w", err)
	} else if n > 0 {
		db.overrideCount = n
	}
	SetGlobal(db)
	return nil
}

func normalize(inPath, outPath, format string) (int, error) {
	in, err := openMaybeGzip(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	bw := bufio.NewWriterSize(out, 1<<20)
	defer bw.Flush()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	count := 0
	switch format {
	case "ip2asn_tsv":
		for sc.Scan() {
			line := sc.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			f := strings.Split(line, "\t")
			if len(f) < 4 {
				continue
			}
			if net.ParseIP(strings.TrimSpace(f[0])) == nil {
				continue
			}
			if _, err := bw.WriteString(line + "\n"); err != nil {
				return count, err
			}
			count++
		}

	case "rir_delegated":

		for sc.Scan() {
			line := sc.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Split(line, "|")
			if len(f) < 7 || f[2] != "ipv4" {
				continue
			}
			cc := strings.ToUpper(strings.TrimSpace(f[1]))
			startIP := net.ParseIP(strings.TrimSpace(f[3]))
			cnt, err := strconv.ParseUint(strings.TrimSpace(f[4]), 10, 32)
			if err != nil || startIP == nil || cnt == 0 {
				continue
			}
			s4 := startIP.To4()
			if s4 == nil {
				continue
			}
			start := binary.BigEndian.Uint32(s4)
			end := start + uint32(cnt-1)
			if end < start {
				continue
			}

			_, err = fmt.Fprintf(bw, "%s\t%s\t0\t%s\tRIR-%s\n",
				u32ToAddr(start), u32ToAddr(end), cc, strings.TrimSpace(f[0]))
			if err != nil {
				return count, err
			}
			count++
		}

	default:
		return 0, fmt.Errorf("未知格式 %q(支持 ip2asn_tsv / rir_delegated)", format)
	}

	if err := sc.Err(); err != nil {
		return count, err
	}
	if count == 0 {
		return 0, fmt.Errorf("未解析出任何有效记录,请确认格式选择正确")
	}
	return count, nil
}

func ValidateOverrides(r io.Reader) error {
	sc := bufio.NewScanner(r)
	lineNo := 0
	valid := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := parseOverrideLine(line); err != nil {
			return fmt.Errorf("第 %d 行: %w", lineNo, err)
		}
		valid++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

type Override struct {
	Start   uint32
	End     uint32
	ASN     uint32
	Country string
	Note    string
}

func (db *DB) applyOverrides(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	var ovs []Override
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ov, err := parseOverrideLine(line)
		if err != nil {
			return 0, fmt.Errorf("第 %d 行: %w", lineNo, err)
		}
		ovs = append(ovs, ov)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if len(ovs) == 0 {
		return 0, nil
	}

	kept := db.entries[:0:len(db.entries)]
	for _, e := range db.entries {
		if overlapsAny(e.Start, e.End, ovs) {
			continue
		}
		kept = append(kept, e)
	}
	for _, ov := range ovs {
		kept = append(kept, Entry{
			Start: ov.Start, End: ov.End, ASN: ov.ASN,
			Country: ov.Country, ASName: ov.Note,
		})
	}
	db.entries = kept
	sort.Slice(db.entries, func(i, j int) bool { return db.entries[i].Start < db.entries[j].Start })
	db.rebuildIndex()

	return len(ovs), nil
}

func parseOverrideLine(line string) (Override, error) {
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	f := strings.Fields(strings.ReplaceAll(line, "\t", " "))
	if len(f) < 2 {
		return Override{}, fmt.Errorf("字段不足,至少需要 <范围> <国家码>")
	}

	var start, end uint32
	rest := f[1:]

	if strings.Contains(f[0], "/") {
		_, netw, err := net.ParseCIDR(f[0])
		if err != nil {
			return Override{}, fmt.Errorf("CIDR 非法: %q", f[0])
		}
		ip4 := netw.IP.To4()
		if ip4 == nil {
			return Override{}, fmt.Errorf("暂只支持 IPv4: %q", f[0])
		}
		ones, bits := netw.Mask.Size()
		if bits != 32 {
			return Override{}, fmt.Errorf("暂只支持 IPv4: %q", f[0])
		}
		start = binary.BigEndian.Uint32(ip4)
		size := uint64(1) << (32 - ones)
		end = uint32(uint64(start) + size - 1)
	} else {

		if len(f) < 3 {
			return Override{}, fmt.Errorf("区间写法需要 <起始IP> <结束IP> <国家码>")
		}
		s := net.ParseIP(f[0])
		e := net.ParseIP(f[1])
		if s == nil || e == nil || s.To4() == nil || e.To4() == nil {
			return Override{}, fmt.Errorf("IP 地址非法: %q %q", f[0], f[1])
		}
		start = binary.BigEndian.Uint32(s.To4())
		end = binary.BigEndian.Uint32(e.To4())
		if end < start {
			return Override{}, fmt.Errorf("结束地址小于起始地址")
		}
		rest = f[2:]
	}

	ov := Override{Start: start, End: end}
	if len(rest) >= 1 {
		ov.Country = strings.ToUpper(rest[0])
	}
	if len(rest) >= 2 {
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(rest[1]), "AS"), 10, 32); err == nil {
			ov.ASN = uint32(n)
		}
	}
	if len(rest) >= 3 {
		ov.Note = strings.Join(rest[2:], " ")
	}
	if ov.Note == "" {
		ov.Note = "本地覆盖"
	}
	return ov, nil
}

func overlapsAny(start, end uint32, ovs []Override) bool {
	for _, o := range ovs {
		if start <= o.End && o.Start <= end {
			return true
		}
	}
	return false
}
