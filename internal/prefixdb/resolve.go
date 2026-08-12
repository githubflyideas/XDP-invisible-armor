package prefixdb

import (
	"fmt"
	"net/netip"
	"sort"
)

type Selector struct {
	Country string
	ASN     uint32
}

func (s Selector) String() string {
	switch {
	case s.Country != "" && s.ASN != 0:
		return fmt.Sprintf("%s+AS%d", s.Country, s.ASN)
	case s.Country != "":
		return s.Country
	case s.ASN != 0:
		return fmt.Sprintf("AS%d", s.ASN)
	}
	return "(空)"
}

func (db *DB) Resolve(sel Selector) ([]netip.Prefix, error) {
	idxs, err := db.candidates(sel)
	if err != nil {
		return nil, err
	}
	if len(idxs) == 0 {
		return nil, nil
	}

	type rng struct{ start, end uint32 }
	ranges := make([]rng, 0, len(idxs))
	for _, i := range idxs {
		e := &db.entries[i]
		ranges = append(ranges, rng{e.Start, e.End})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	merged := make([]rng, 0, len(ranges))
	cur := ranges[0]
	for _, r := range ranges[1:] {

		if r.start <= cur.end || (cur.end != ^uint32(0) && r.start == cur.end+1) {
			if r.end > cur.end {
				cur.end = r.end
			}
			continue
		}
		merged = append(merged, cur)
		cur = r
	}
	merged = append(merged, cur)

	var out []netip.Prefix
	for _, r := range merged {
		out = append(out, rangeToCIDRs(r.start, r.end)...)
	}
	return out, nil
}

func (db *DB) candidates(sel Selector) ([]int, error) {
	switch {
	case sel.Country == "" && sel.ASN == 0:
		return nil, fmt.Errorf("必须指定国家或 AS 号")

	case sel.Country != "" && sel.ASN != 0:

		byC := db.byCountry[sel.Country]
		byA := db.byASN[sel.ASN]
		if len(byC) == 0 || len(byA) == 0 {
			return nil, nil
		}
		base, other := byC, sel.ASN
		if len(byA) < len(byC) {

			out := make([]int, 0, len(byA))
			for _, i := range byA {
				if db.entries[i].Country == sel.Country {
					out = append(out, i)
				}
			}
			return out, nil
		}
		out := make([]int, 0, len(base))
		for _, i := range base {
			if db.entries[i].ASN == other {
				out = append(out, i)
			}
		}
		return out, nil

	case sel.Country != "":
		return db.byCountry[sel.Country], nil

	default:
		return db.byASN[sel.ASN], nil
	}
}

func rangeToCIDRs(start, end uint32) []netip.Prefix {
	var out []netip.Prefix
	for start <= end {

		maxSize := uint32(32)
		for maxSize > 0 {
			mask := ^uint32(0) << (32 - (maxSize - 1))
			if start&^mask != 0 {
				break
			}
			maxSize--
		}

		remaining := uint64(end) - uint64(start) + 1
		for maxSize < 32 {
			if uint64(1)<<(32-maxSize) <= remaining {
				break
			}
			maxSize++
		}

		out = append(out, netip.PrefixFrom(u32ToAddr(start), int(maxSize)))

		blockSize := uint64(1) << (32 - maxSize)
		next := uint64(start) + blockSize
		if next > uint64(^uint32(0)) {
			break
		}
		start = uint32(next)
	}
	return out
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	})
}

type Preview struct {
	Selector  Selector
	CIDRCount int
	AddrCount uint64
	Samples   []string
	Truncated bool
}

func (db *DB) Preview(sel Selector, limitSamples int) (*Preview, error) {
	cidrs, err := db.Resolve(sel)
	if err != nil {
		return nil, err
	}
	p := &Preview{Selector: sel, CIDRCount: len(cidrs)}
	for _, c := range cidrs {
		p.AddrCount += uint64(1) << (32 - c.Bits())
	}
	for i, c := range cidrs {
		if i >= limitSamples {
			p.Truncated = true
			break
		}
		p.Samples = append(p.Samples, c.String())
	}
	return p, nil
}

type CountryOption struct {
	Code       string
	CIDRBlocks int
}

type ASNOption struct {
	ASN        uint32
	Name       string
	Country    string
	CIDRBlocks int
}

func (db *DB) Countries() []CountryOption {
	out := make([]CountryOption, 0, len(db.byCountry))
	for code, idxs := range db.byCountry {
		out = append(out, CountryOption{Code: code, CIDRBlocks: len(idxs)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDRBlocks > out[j].CIDRBlocks })
	return out
}

func (db *DB) SearchASN(query string, limit int) []ASNOption {
	q := normalizeASNQuery(query)
	var out []ASNOption
	seen := make(map[uint32]bool)

	for asn, idxs := range db.byASN {
		if len(out) >= limit {
			break
		}
		if seen[asn] {
			continue
		}
		e := &db.entries[idxs[0]]
		if !matchASN(asn, e.ASName, q) {
			continue
		}
		seen[asn] = true
		out = append(out, ASNOption{
			ASN: asn, Name: e.ASName, Country: e.Country, CIDRBlocks: len(idxs),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDRBlocks > out[j].CIDRBlocks })
	return out
}
