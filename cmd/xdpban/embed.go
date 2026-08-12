package main

import _ "embed"

//go:embed obj/xdp_filter.o
var xdpFilterBytecode []byte
