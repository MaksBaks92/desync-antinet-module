// SPDX-License-Identifier: MIT
//
// Strategy engine: именованные пресеты → цепочки SOCKS-path примитивов.
// Intent портирован с Flowseal/zapret-discord-youtube (general/ALT*); seqovl/WinDivert —
// unsupported (см. README).
package main

import "strings"

// Primitive — один шаг desync на первом payload.
type Primitive struct {
	Kind string // split | multisplit | fake | tlsrec | passthrough | unsupported

	// split / multisplit
	Positions []int  // абсолютные смещения; 0 = «после 1-го байта» стиля Flowseal split-pos=1
	SplitSNI  bool   // резать перед SNI в TLS ClientHello, если найден
	Parts     int    // multisplit: на сколько кусков (если Positions пуст)

	// fake
	FakeTTL     int // временный TTL для фейка (0 = не трогать / недоступно)
	FakeRepeats int
	FakeSize    int // размер синтетического TLS-like blob

	// tlsrec
	TlsRecAt int // байт внутри TLS record payload, после которого режем record

	Note string // почему unsupported / комментарий
}

// Rule — одно правило пресета (аналог сегмента winws между --new).
type Rule struct {
	Name     string
	Buckets  []matchBucket // пусто = любой не-exclude
	Ports    []uint16      // пусто = 80,443 и типичные
	Prims    []Primitive
}

// Preset — готовый профиль.
type Preset struct {
	Name        string
	Description string
	Rules       []Rule
	// AutoChain — запасные пресеты для режима auto (порядок failover).
	AutoChain []string
}

func knownPreset(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "general", "alt", "alt2", "youtube", "discord", "safe", "auto", "passthrough":
		return true
	}
	return false
}

func getPreset(name string) Preset {
	switch strings.ToLower(strings.TrimSpace(name)) {
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
	return []uint16{80, 443, 2053, 2083, 2087, 2096, 8443}
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
		return b != bucketNone // только hostlist-матч; «all» правила задают bucketAll явно
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

// selectRule — первое подходящее правило пресета.
func selectRule(p Preset, host string, port uint16, lists hostLists) (Rule, bool) {
	b := lists.classify(host)
	if b == bucketExclude {
		return Rule{Name: "exclude-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
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
	// Нет матча hostlist → passthrough (как отсутствие фильтра winws).
	return Rule{Name: "no-match-passthrough", Prims: []Primitive{{Kind: "passthrough"}}}, true
}
