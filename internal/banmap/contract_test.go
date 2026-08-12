package banmap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestMapNamesMatchBPFSource(t *testing.T) {
	src := findBPFSource(t, "xdp_filter.c")

	defined := parseMapNames(t, src)
	sort.Strings(defined)

	declared := []string{MapCounters, MapGlobalBans, MapSrcBans, MapTargetHosts}
	sort.Strings(declared)

	if strings.Join(defined, ",") != strings.Join(declared, ",") {
		t.Errorf("map 名不一致:\n  C 侧定义: %v\n  Go 侧声明: %v\n"+
			"这类不一致编译期抓不到,运行时表现为 agent 启动失败或规则静默不生效",
			defined, declared)
	}
}

func TestKeyValueSizesMatchBPFSource(t *testing.T) {
	src := findBPFSource(t, "xdp_filter.c")
	body := readFile(t, src)

	cases := []struct {
		structName string
		goSize     int
	}{
		{"global_ban_key", GlobalKeySize},
		{"src_ban_key", SrcKeySize},
		{"target_key", TargetKeySize},
		{"ban_value", ValueSize},
	}

	for _, tc := range cases {
		got, err := cStructSize(body, tc.structName)
		if err != nil {
			t.Errorf("解析 struct %s: %v", tc.structName, err)
			continue
		}
		if got != tc.goSize {
			t.Errorf("struct %s: C 侧 %d 字节,Go 侧常量 %d 字节 —— "+
				"不一致会导致 key/value 编码错位,规则静默失效",
				tc.structName, got, tc.goSize)
		}
	}
}

func TestMaxSrcBansMatchesQuotaCapacity(t *testing.T) {
	src := findBPFSource(t, "xdp_filter.c")
	body := readFile(t, src)

	re := regexp.MustCompile(`#define\s+MAX_SRC_BANS\s+(\d+)`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("未在 C 源码中找到 MAX_SRC_BANS")
	}

	var cVal int
	fmt.Sscanf(m[1], "%d", &cVal)

	const quotaMapCapacity = 262144
	if cVal != quotaMapCapacity {
		t.Errorf("MAX_SRC_BANS(C)=%d 与 quota.MapCapacity=%d 不一致 —— "+
			"配额预检会算错余量,最终在下发时收到 E2BIG 而规则静默不生效",
			cVal, quotaMapCapacity)
	}
}

func findBPFSource(t *testing.T, name string) string {
	t.Helper()

	for _, rel := range []string{
		filepath.Join("..", "..", "bpf", name),
		filepath.Join("..", "bpf", name),
		filepath.Join("bpf", name),
	} {
		if _, err := os.Stat(rel); err == nil {
			return rel
		}
	}
	t.Fatalf("找不到 bpf/%s —— 测试需要读 C 源码来校验跨语言契约", name)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	return string(b)
}

func parseMapNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开 %s: %v", path, err)
	}
	defer f.Close()

	re := regexp.MustCompile(`^\}\s*(\w+)\s+SEC\("\.maps"\)`)
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := re.FindStringSubmatch(sc.Text()); m != nil {
			names = append(names, m[1])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("扫描 %s: %v", path, err)
	}
	if len(names) == 0 {
		t.Fatalf("%s 中未解析出任何 map 定义", path)
	}
	return names
}

func cStructSize(body, name string) (int, error) {
	re := regexp.MustCompile(`struct\s+` + regexp.QuoteMeta(name) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0, fmt.Errorf("未找到定义")
	}

	widths := map[string]int{
		"__u8": 1, "__u16": 2, "__u32": 4, "__u64": 8,
	}

	total := 0
	maxAlign := 1
	for _, line := range strings.Split(m[1], "\n") {

		if i := strings.Index(line, "/*"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasSuffix(line, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(fields) < 2 {
			continue
		}
		w, ok := widths[fields[0]]
		if !ok {
			return 0, fmt.Errorf("未知字段类型 %q", fields[0])
		}
		if w > maxAlign {
			maxAlign = w
		}

		count := 1
		decl := fields[1]
		if i := strings.Index(decl, "["); i >= 0 {
			j := strings.Index(decl, "]")
			if j > i {
				fmt.Sscanf(decl[i+1:j], "%d", &count)
			}
		}
		total += w * count
	}

	if rem := total % maxAlign; rem != 0 {
		total += maxAlign - rem
	}
	return total, nil
}
