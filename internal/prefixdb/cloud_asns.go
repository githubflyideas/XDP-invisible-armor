package prefixdb

var CloudProviderASNs = map[uint32]string{
	16509:  "AWS",
	14618:  "AWS",
	8987:   "AWS",
	15169:  "Google Cloud",
	396982: "Google Cloud",
	19527:  "Google Cloud",
	8075:   "Microsoft Azure",
	8068:   "Microsoft Azure",
	37963:  "Alibaba Cloud",
	45102:  "Alibaba Cloud",
	31898:  "Oracle Cloud",
	138915: "Oracle Cloud",
}

func CloudProviderName(asn uint32) (string, bool) {
	name, ok := CloudProviderASNs[asn]
	return name, ok
}
