package web

type fakeRevoker struct {
	globalCalls []string
	scopedCalls []struct {
		targetIP string
		prefixes []string
	}
	err error
}

func (f *fakeRevoker) RevokeGlobal(target string) error {
	f.globalCalls = append(f.globalCalls, target)
	return f.err
}

func (f *fakeRevoker) RevokeScoped(targetIP string, prefixes []string) error {
	f.scopedCalls = append(f.scopedCalls, struct {
		targetIP string
		prefixes []string
	}{targetIP, prefixes})
	return f.err
}
