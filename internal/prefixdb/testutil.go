package prefixdb

func NewForTest(entries []Entry, byCountry map[string][]int, byASN map[uint32][]int) *DB {
	if byCountry == nil {
		byCountry = make(map[string][]int)
	}
	if byASN == nil {
		byASN = make(map[uint32][]int)
	}
	return &DB{
		entries:   entries,
		byCountry: byCountry,
		byASN:     byASN,
	}
}
