package prefixdb

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Start   uint32
	End     uint32
	ASN     uint32
	Country string
	ASName  string
}

type DB struct {
	entries []Entry

	byCountry map[string][]int
	byASN     map[uint32][]int

	sourcePath    string
	loadedAt      time.Time
	overrideCount int
}

var (
	global   *DB
	globalMu sync.RWMutex
)

func Global() *DB {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

func SetGlobal(db *DB) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = db
}

func Load(path string) (*DB, error) {
	r, err := openMaybeGzip(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	db := &DB{
		byCountry:  make(map[string][]int, 256),
		byASN:      make(map[uint32][]int, 100000),
		sourcePath: path,
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		start := net.ParseIP(strings.TrimSpace(fields[0]))
		end := net.ParseIP(strings.TrimSpace(fields[1]))
		if start == nil || end == nil {
			continue
		}
		s4, e4 := start.To4(), end.To4()
		if s4 == nil || e4 == nil {
			continue
		}
		asn, _ := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32)
		country := strings.ToUpper(strings.TrimSpace(fields[3]))
		asName := ""
		if len(fields) >= 5 {
			asName = strings.TrimSpace(fields[4])
		}

		e := Entry{
			Start:   binary.BigEndian.Uint32(s4),
			End:     binary.BigEndian.Uint32(e4),
			ASN:     uint32(asn),
			Country: country,
			ASName:  asName,
		}
		if e.End < e.Start {
			continue
		}

		idx := len(db.entries)
		db.entries = append(db.entries, e)
		if country != "" && country != "NONE" {
			db.byCountry[country] = append(db.byCountry[country], idx)
		}
		if asn != 0 {
			db.byASN[uint32(asn)] = append(db.byASN[uint32(asn)], idx)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s (第 %d 行): %w", path, line, err)
	}
	if len(db.entries) == 0 {
		return nil, fmt.Errorf("%s 未解析出任何有效记录", path)
	}

	sort.Slice(db.entries, func(i, j int) bool { return db.entries[i].Start < db.entries[j].Start })
	db.rebuildIndex()
	db.loadedAt = time.Now()

	return db, nil
}

func (db *DB) rebuildIndex() {
	db.byCountry = make(map[string][]int, 256)
	db.byASN = make(map[uint32][]int, 100000)
	for i := range db.entries {
		e := &db.entries[i]
		if e.Country != "" && e.Country != "NONE" {
			db.byCountry[e.Country] = append(db.byCountry[e.Country], i)
		}
		if e.ASN != 0 {
			db.byASN[e.ASN] = append(db.byASN[e.ASN], i)
		}
	}
}

type Stats struct {
	SourcePath    string
	Entries       int
	Countries     int
	ASNs          int
	LoadedAt      time.Time
	OverrideCount int
}

func (db *DB) Stats() Stats {
	return Stats{
		SourcePath:    db.sourcePath,
		Entries:       len(db.entries),
		Countries:     len(db.byCountry),
		ASNs:          len(db.byASN),
		LoadedAt:      db.loadedAt,
		OverrideCount: db.overrideCount,
	}
}

func openMaybeGzip(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 %s: %w", path, err)
	}

	var magic [2]byte
	n, _ := io.ReadFull(f, magic[:])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}

	if n == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("解压 %s: %w", path, err)
		}
		return &gzipCloser{gz: gz, f: f}, nil
	}
	return f, nil
}

type gzipCloser struct {
	gz *gzip.Reader
	f  *os.File
}

func (g *gzipCloser) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzipCloser) Close() error {
	g.gz.Close()
	return g.f.Close()
}
