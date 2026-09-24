// SPDX-License-Identifier: MIT
package main

// Пресеты: byedpi (дефолт ByeByeDPI) + Flowseal general / ALT / ALT2.
// seqovl / fooling=ts / fakedsplit pattern inject → unsupported (логируется, пропускается).

func presetByeDPI() Preset {
	return Preset{
		Name:        "byedpi",
		Description: "ByeByeDPI UI default: OOB@1 на весь TLS/HTTP (hostsMode=all). Метод/позиция — из настроек.",
		Rules: []Rule{
			{
				Name:    "byedpi-all",
				Buckets: []matchBucket{bucketAll},
				Ports:   defaultPorts(),
				Prims:   []Primitive{{Kind: "oob", Positions: []int{1}, OOBChar: 'a'}},
			},
		},
	}
}

func presetGeneral() Preset {
	return Preset{
		Name:        "general",
		Description: "Flowseal general: multisplit на TLS :443 (hostlist), split-pos≈1; seqovl пропущен",
		Rules: []Rule{
			{
				Name:    "discord-media-tcp",
				Buckets: []matchBucket{bucketDiscord},
				Ports:   []uint16{2053, 2083, 2087, 2096, 8443, 443},
				Prims: []Primitive{
					{Kind: "unsupported", Note: "seqovl=681 not available on SOCKS path"},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
			{
				Name:    "google-youtube-tcp",
				Buckets: []matchBucket{bucketGoogle},
				Ports:   []uint16{443},
				Prims: []Primitive{
					{Kind: "unsupported", Note: "seqovl=681 not available on SOCKS path"},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
			{
				Name:    "general-tcp",
				Buckets: []matchBucket{bucketGeneral, bucketDiscord},
				Ports:   []uint16{80, 443},
				Prims: []Primitive{
					{Kind: "unsupported", Note: "seqovl=568 not available on SOCKS path"},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
			{
				// Аналог ipset-all / filter без hostlist: после SNI-матча и list-матча.
				Name:    "any-tls-http",
				Buckets: []matchBucket{bucketAll},
				Ports:   defaultPorts(),
				Prims: []Primitive{
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
		},
	}
}

func presetAlt() Preset {
	return Preset{
		Name:        "alt",
		Description: "Flowseal ALT: fake+split вместо multisplit/seqovl; fooling=ts недоступен",
		Rules: []Rule{
			{
				Name:    "discord-alt",
				Buckets: []matchBucket{bucketDiscord},
				Ports:   []uint16{2053, 2083, 2087, 2096, 8443, 443},
				Prims: []Primitive{
					{Kind: "unsupported", Note: "fooling=ts / fakedsplit WinDivert inject unsupported"},
					{Kind: "fake", FakeTTL: 1, FakeRepeats: 2, FakeSize: 1200},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
			{
				Name:    "google-alt",
				Buckets: []matchBucket{bucketGoogle},
				Ports:   []uint16{443},
				Prims: []Primitive{
					{Kind: "fake", FakeTTL: 1, FakeRepeats: 2, FakeSize: 1200},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
			{
				Name:    "general-alt",
				Buckets: []matchBucket{bucketGeneral, bucketDiscord},
				Ports:   []uint16{80, 443},
				Prims: []Primitive{
					{Kind: "fake", FakeTTL: 1, FakeRepeats: 2, FakeSize: 1200},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
			{
				Name:    "any-tls-http",
				Buckets: []matchBucket{bucketAll},
				Ports:   []uint16{80, 443, 2053, 2083, 2087, 2096, 8443},
				Prims: []Primitive{
					{Kind: "fake", FakeTTL: 1, FakeRepeats: 2, FakeSize: 1200},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
		},
	}
}

func presetAlt2() Preset {
	return Preset{
		Name:        "alt2",
		Description: "Flowseal ALT2: multisplit с pos≈2; seqovl пропущен",
		Rules: []Rule{
			{
				Name:    "discord-alt2",
				Buckets: []matchBucket{bucketDiscord},
				Ports:   []uint16{2053, 2083, 2087, 2096, 8443, 443},
				Prims: []Primitive{
					{Kind: "unsupported", Note: "seqovl=652 not available on SOCKS path"},
					{Kind: "multisplit", Positions: []int{2}, SplitSNI: true, Parts: 3},
				},
			},
			{
				Name:    "google-alt2",
				Buckets: []matchBucket{bucketGoogle},
				Ports:   []uint16{443},
				Prims: []Primitive{
					{Kind: "multisplit", Positions: []int{2}, SplitSNI: true, Parts: 3},
				},
			},
			{
				Name:    "general-alt2",
				Buckets: []matchBucket{bucketGeneral, bucketDiscord},
				Ports:   []uint16{80, 443},
				Prims: []Primitive{
					{Kind: "multisplit", Positions: []int{2}, SplitSNI: true, Parts: 3},
				},
			},
			{
				Name:    "any-tls-http",
				Buckets: []matchBucket{bucketAll},
				Ports:   []uint16{80, 443, 2053, 2083, 2087, 2096, 8443},
				Prims: []Primitive{
					{Kind: "multisplit", Positions: []int{2}, SplitSNI: true, Parts: 3},
				},
			},
		},
	}
}

func presetYoutube() Preset {
	return Preset{
		Name:        "youtube",
		Description: "Узкий профиль: google/youtube hostlist, multisplit+fake",
		Rules: []Rule{
			{
				Name:    "youtube",
				Buckets: []matchBucket{bucketGoogle},
				Ports:   []uint16{80, 443},
				Prims: []Primitive{
					{Kind: "fake", FakeTTL: 1, FakeRepeats: 1, FakeSize: 1000},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
					{Kind: "tlsrec", TlsRecAt: 3},
				},
			},
		},
	}
}

func presetDiscord() Preset {
	return Preset{
		Name:        "discord",
		Description: "Узкий профиль: discord hostlist, fake+multisplit (+ UDP fake для voice)",
		Rules: []Rule{
			{
				Name:    "discord",
				Buckets: []matchBucket{bucketDiscord},
				Ports:   []uint16{80, 443, 2053, 2083, 2087, 2096, 8443},
				Prims: []Primitive{
					{Kind: "fake", FakeTTL: 1, FakeRepeats: 2, FakeSize: 1200},
					{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
				},
			},
		},
	}
}

func presetSafe() Preset {
	return Preset{
		Name:        "safe",
		Description: "Мягкий split без fake/TTL — меньше шансов сломать легитимный DPI-tolerant путь",
		Rules: []Rule{
			{
				Name:    "safe-listed",
				Buckets: []matchBucket{bucketGeneral, bucketGoogle, bucketDiscord},
				Ports:   []uint16{80, 443},
				Prims: []Primitive{
					{Kind: "split", Positions: []int{1}},
				},
			},
			{
				Name:    "any-tls-http",
				Buckets: []matchBucket{bucketAll},
				Ports:   []uint16{80, 443},
				Prims: []Primitive{
					{Kind: "split", Positions: []int{1}},
				},
			},
		},
	}
}

func presetAuto() Preset {
	p := presetGeneral()
	p.Name = "auto"
	p.Description = "Стартует как general; при сбое цепочки — alt → alt2 → safe (см. applyAuto)"
	p.AutoChain = []string{"general", "alt", "alt2", "safe"}
	return p
}

func presetPassthrough() Preset {
	return Preset{
		Name:        "passthrough",
		Description: "Без desync — чистый проброс как moduleecho",
		Rules: []Rule{
			{
				Name:    "all",
				Buckets: []matchBucket{bucketAll},
				Ports:   nil, // любой порт
				Prims:   []Primitive{{Kind: "passthrough"}},
			},
		},
	}
}

func selectRuleForPreset(name string, host string, port uint16, lists hostLists, payload []byte, opts desyncOpts, dialIP string) (Rule, Preset, bool) {
	p := getPreset(name)
	if p.Name == "passthrough" {
		return p.Rules[0], p, true
	}
	r, ok := selectRule(p, host, port, lists, payload, opts, dialIP)
	return r, p, ok
}
