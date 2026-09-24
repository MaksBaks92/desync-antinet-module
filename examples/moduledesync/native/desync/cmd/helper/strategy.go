// SPDX-License-Identifier: MIT
//
// Strategy engine: ByeByeDPI-like (byedpi) + Flowseal-inspired presets.
package main

import "strings"

// Primitive — один шаг desync на первом payload.
type Primitive struct {
	Kind string // split | multisplit | disorder | oob | disoob | fake | tlsrec | passthrough | unsupported

	Positions []int
	SplitSNI  bool
	Parts     int

	FakeTTL     int
	FakeRepeats int
	FakeSize    int

	// TlsRecAt — позиция content для part_tls (байты handshake после 5-байтного record hdr).
	// При TlsRecSNI: как byeDPI -rN[+s][+e] — смещение относительно SNI (отрицательное = до якоря).
	TlsRecAt  int
	TlsRecSNI bool // якорь — hostname в SNI (flag +s)
	TlsRecEnd bool // якорь — конец hostname (+e); иначе начало

	OOBChar byte // для oob/disoob; 0 → 'a' как ByeByeDPI

	Note string
}

type Rule struct {
	Name    string
	Buckets []matchBucket
	Ports   []uint16
	Prims   []Primitive
}

type Preset struct {
	Name        string
	Description string
	Rules       []Rule
	AutoChain   []string
}

func knownPreset(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "byedpi", "general", "alt", "alt2", "youtube", "discord", "safe", "auto", "passthrough":
		return true
	}
	return false
}

func getPreset(name string) Preset {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "byedpi":
		return presetByeDPI()
	case "alt":
		return presetAlt()
	case "alt2":
		return presetAlt2()
	case "youtube":
		return presetYoutube()
	case "discord":
		return presetDiscord()
	case "safe":
		return presetSafe()
	case "auto":
		return presetAuto()
	case "passthrough":
		return presetPassthrough()
	default:
		return presetGeneral()
	}
}

func defaultPorts() []uint16 {
	// 80/443 + типичные TLS-порты приложений (Google mtalk 5228, Discord media, …).
	return []uint16{80, 443, 2053, 2083, 2087, 2096, 5222, 5228, 8443}
}

func portOK(port uint16, ports []uint16) bool {
	if len(ports) == 0 {
		ports = defaultPorts()
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

func bucketOK(b matchBucket, want []matchBucket) bool {
	if b == bucketExclude {
		return false
	}
	if len(want) == 0 {
		return b != bucketNone
	}
	for _, w := range want {
		if w == bucketAll {
			return true
		}
		if w == b {
			return true
		}
	}
	return false
}

// desyncOpts — настройки карточки модуля (ByeByeDPI UI analogy).
type desyncOpts struct {
	HostsMode    string // all | whitelist | blacklist
	Method       string // oob | disoob | split | disorder | fake | multisplit
	SplitPos     int
	OOBChar      byte
	DesyncHTTPS  bool
	DesyncHTTP   bool
	UdpFakeCount int // ByeByeDPI -aN; 0 = off (DEFAULT_CMD_ARGS -a1)
	FakeTTL      int // TTL для TCP/UDP fake; byeDPI DEFAULT_TTL=8
}

func defaultDesyncOpts() desyncOpts {
	return desyncOpts{
		HostsMode:    "all",
		Method:       "oob",
		SplitPos:     1,
		OOBChar:      'a',
		DesyncHTTPS:  true,
		DesyncHTTP:   true,
		UdpFakeCount: 1,
		FakeTTL:      8,
	}
}

func protocolOK(opts desyncOpts, payload []byte) bool {
	if looksLikeTLSClientHello(payload) && opts.DesyncHTTPS {
		return true
	}
	if looksLikeHTTP(payload) && opts.DesyncHTTP {
		return true
	}
	return false
}

func byedpiPrims(opts desyncOpts) []Primitive {
	pos := opts.SplitPos
	if pos == 0 {
		pos = 1
	}
	oob := opts.OOBChar
	if oob == 0 {
		oob = 'a'
	}
	switch strings.ToLower(strings.TrimSpace(opts.Method)) {
	case "split":
		return []Primitive{{Kind: "split", Positions: []int{pos}}}
	case "disorder":
		return []Primitive{{Kind: "disorder", Positions: []int{pos}}}
	case "disoob":
		return []Primitive{{Kind: "disoob", Positions: []int{pos}, OOBChar: oob}}
	case "fake":
		return []Primitive{
			{Kind: "fake", FakeTTL: 8, FakeRepeats: 1, FakeSize: 1200},
			{Kind: "split", Positions: []int{pos}},
		}
	case "multisplit":
		return []Primitive{{Kind: "multisplit", Positions: []int{pos}, SplitSNI: true, Parts: 2}}
	default: // oob — ByeByeDPI DEFAULT_CMD_ARGS "-o1 -a1 -r-5+se"
		// tlsrec сначала (tamp буфера), затем OOB@pos. UDP -a1 — udpDesyncConn на UDPASSOC.
		return []Primitive{
			{Kind: "tlsrec", TlsRecAt: -5, TlsRecSNI: true, TlsRecEnd: true},
			{Kind: "oob", Positions: []int{pos}, OOBChar: oob},
		}
	}
}

// selectRule — первое подходящее правило с учётом hostsMode (ByeByeDPI).
func selectRule(p Preset, host string, port uint16, lists hostLists, payload []byte, opts desyncOpts) (Rule, bool) {
	if !hostsModeGate(opts.HostsMode, host, lists) {
		return Rule{Name: "hosts-gate-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
	}
	if !protocolOK(opts, payload) && p.Name != "passthrough" {
		if p.Name != "youtube" && p.Name != "discord" {
			return Rule{Name: "proto-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
		}
	}

	// ByeByeDPI-путь (auto/byedpi): method из настроек (oob/fake/…), не Flowseal multisplit.
	if useByeDPIMethod(p.Name, opts) {
		if !portOK(port, defaultPorts()) {
			return Rule{Name: "port-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
		}
		method := strings.ToLower(strings.TrimSpace(opts.Method))
		if method == "" {
			method = "oob"
		}
		return Rule{Name: "byedpi-" + method, Prims: byedpiPrims(opts)}, true
	}

	b := lists.classify(host)
	if b == bucketExclude {
		return Rule{Name: "exclude-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
	}
	if strings.ToLower(opts.HostsMode) == "all" || opts.HostsMode == "" {
		for _, r := range p.Rules {
			if !portOK(port, r.Ports) {
				continue
			}
			for _, w := range r.Buckets {
				if w == bucketAll {
					return r, true
				}
			}
		}
	}
	for _, r := range p.Rules {
		if !portOK(port, r.Ports) {
			continue
		}
		if !bucketOK(b, r.Buckets) {
			continue
		}
		return r, true
	}
	if p.Name != "youtube" && p.Name != "discord" && p.Name != "passthrough" {
		if portOK(port, defaultPorts()) && (looksLikeTLSClientHello(payload) || looksLikeHTTP(payload)) {
			return Rule{Name: "tls-http-fallback", Prims: fallbackPrims(p.Name)}, true
		}
	}
	return Rule{Name: "no-match-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
}

// useByeDPIMethod — применять SETTING_method (oob/fake/…) вместо Flowseal-цепочек.
// Пресеты auto/byedpi = путь ByeByeDPI; general/alt/… остаются Flowseal (с exclude через classify).
func useByeDPIMethod(preset string, _ desyncOpts) bool {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "byedpi", "auto":
		return true
	default:
		return false
	}
}

func fallbackPrims(preset string) []Primitive {
	switch strings.ToLower(preset) {
	case "alt", "auto":
		return []Primitive{
			{Kind: "fake", FakeTTL: 1, FakeRepeats: 2, FakeSize: 1200},
			{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2},
		}
	case "alt2":
		return []Primitive{{Kind: "multisplit", Positions: []int{2}, SplitSNI: true, Parts: 3}}
	case "safe":
		return []Primitive{{Kind: "split", Positions: []int{1}}}
	default:
		return []Primitive{{Kind: "multisplit", Positions: []int{1}, SplitSNI: true, Parts: 2}}
	}
}
