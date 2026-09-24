// SPDX-License-Identifier: MIT
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// searchStrategy — одна строка из ByeByeDPI strategies.list, смапленная на SOCKS-примитивы.
type searchStrategy struct {
	Raw   string
	Label string
	Prims []Primitive
	Opts  desyncOpts // для applyBest в byedpi-режиме
}

var (
	reShortFlag = regexp.MustCompile(`^-([fodsqm])(-?\d+)`)
	reLongFake  = regexp.MustCompile(`(?i)^--fake`)
	reLongSplit = regexp.MustCompile(`(?i)^--split$`)
	reLongDis   = regexp.MustCompile(`(?i)^--disorder$`)
	reLongTTL   = regexp.MustCompile(`(?i)^--ttl$`)
)

// parseStrategyLines — строки CMD → стратегии; пустые/непарсящиеся пропускаются.
func parseStrategyLines(raw, sni string) []searchStrategy {
	sni = strings.TrimSpace(sni)
	if sni == "" {
		sni = "google.com"
	}
	var out []searchStrategy
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ReplaceAll(line, "{sni}", sni)
		st, ok := parseByeDPICmd(line)
		if !ok || len(st.Prims) == 0 {
			continue
		}
		if seen[st.Raw] {
			continue
		}
		seen[st.Raw] = true
		out = append(out, st)
	}
	return out
}

func parseByeDPICmd(cmd string) (searchStrategy, bool) {
	toks := strings.Fields(cmd)
	if len(toks) == 0 {
		return searchStrategy{}, false
	}

	var prims []Primitive
	method := "oob"
	splitPos := 1
	fakeTTL := 8
	oob := byte('a')

	addPrim := func(p Primitive) {
		if len(prims) >= 4 {
			return
		}
		prims = append(prims, p)
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]

		// long options: --fake -1 --ttl 8 --split 1+s --disorder 3+s
		if reLongFake.MatchString(t) {
			ttl := fakeTTL
			if i+2 < len(toks) && reLongTTL.MatchString(toks[i+1]) {
				if v, err := strconv.Atoi(toks[i+2]); err == nil && v > 0 {
					ttl = v
				}
				i += 2
			}
			addPrim(Primitive{Kind: "fake", FakeTTL: ttl, FakeRepeats: 1, FakeSize: 1200})
			method = "fake"
			continue
		}
		if reLongSplit.MatchString(t) && i+1 < len(toks) {
			pos := parsePosToken(toks[i+1])
			i++
			addPrim(Primitive{Kind: "split", Positions: []int{pos}})
			method = "split"
			splitPos = pos
			continue
		}
		if reLongDis.MatchString(t) && i+1 < len(toks) {
			pos := parsePosToken(toks[i+1])
			i++
			addPrim(Primitive{Kind: "disorder", Positions: []int{pos}})
			method = "disorder"
			splitPos = pos
			continue
		}

		// -r-5+se / -r3+s: tlsrec с signed offset и якорями +s/+e (до regex, иначе +se теряется).
		if len(t) >= 3 && t[0] == '-' && t[1] == 'r' {
			addPrim(parseTlsRecPrim(t[2:]))
			continue
		}

		m := reShortFlag.FindStringSubmatch(t)
		if m == nil {
			// -o1+s / -q1+s / -s3:5+sm без полного match на весь токен
			if len(t) >= 3 && t[0] == '-' {
				flag := t[1]
				rest := t[2:]
				if strings.ContainsAny(string(flag), "fodsqm") {
					pos := parsePosToken(rest)
					switch flag {
					case 'o':
						addPrim(Primitive{Kind: "oob", Positions: []int{pos}, OOBChar: oob})
						method, splitPos = "oob", pos
					case 'q':
						addPrim(Primitive{Kind: "disoob", Positions: []int{pos}, OOBChar: oob})
						method, splitPos = "disoob", pos
					case 'd':
						addPrim(Primitive{Kind: "disorder", Positions: []int{pos}})
						method, splitPos = "disorder", pos
					case 's':
						addPrim(Primitive{Kind: "multisplit", Positions: []int{pos}, SplitSNI: strings.Contains(rest, "s"), Parts: 2})
						method, splitPos = "multisplit", pos
					case 'f':
						addPrim(Primitive{Kind: "fake", FakeTTL: fakeTTL, FakeRepeats: 1, FakeSize: 1200})
						if method == "oob" {
							method = "fake"
						}
					case 'm':
						addPrim(Primitive{Kind: "multisplit", Positions: []int{1}, Parts: absInt(pos)})
						method = "multisplit"
					}
				}
			}
			continue
		}
		flag := m[1]
		pos, _ := strconv.Atoi(m[2])
		if pos == 0 {
			pos = 1
		}
		pos = absInt(pos)
		switch flag {
		case "o":
			addPrim(Primitive{Kind: "oob", Positions: []int{pos}, OOBChar: oob})
			method, splitPos = "oob", pos
		case "q":
			addPrim(Primitive{Kind: "disoob", Positions: []int{pos}, OOBChar: oob})
			method, splitPos = "disoob", pos
		case "d":
			addPrim(Primitive{Kind: "disorder", Positions: []int{pos}})
			method, splitPos = "disorder", pos
		case "s":
			addPrim(Primitive{Kind: "multisplit", Positions: []int{pos}, Parts: 2})
			method, splitPos = "multisplit", pos
		case "f":
			addPrim(Primitive{Kind: "fake", FakeTTL: fakeTTL, FakeRepeats: 1, FakeSize: 1200})
			if method == "oob" {
				method = "fake"
			}
		case "m":
			addPrim(Primitive{Kind: "multisplit", Positions: []int{1}, Parts: pos})
			method = "multisplit"
		}
	}

	if len(prims) == 0 {
		return searchStrategy{}, false
	}

	opts := defaultDesyncOpts()
	opts.Method = method
	opts.SplitPos = splitPos
	opts.OOBChar = oob

	label := method + "@" + strconv.Itoa(splitPos)
	if len(prims) > 1 {
		label += "+" + strconv.Itoa(len(prims)) + "p"
	}

	return searchStrategy{
		Raw:   cmd,
		Label: label,
		Prims: prims,
		Opts:  opts,
	}, true
}

func parsePosToken(tok string) int {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 1
	}
	// 1+s / 3:5+sm / -5+se / 1:11+sm
	neg := false
	if strings.HasPrefix(tok, "-") {
		neg = true
		tok = tok[1:]
	}
	num := ""
	for _, r := range tok {
		if r >= '0' && r <= '9' {
			num += string(r)
		} else {
			break
		}
	}
	if num == "" {
		return 1
	}
	v, err := strconv.Atoi(num)
	if err != nil || v == 0 {
		return 1
	}
	if neg {
		// byeDPI negative offset для split/oob — abs как позиция
		return v
	}
	return v
}

// parseTlsRecPrim — хвост после -r: "-5+se", "3+s", "1" → Primitive tlsrec с signed TlsRecAt.
func parseTlsRecPrim(rest string) Primitive {
	rest = strings.TrimSpace(rest)
	p := Primitive{Kind: "tlsrec", TlsRecAt: 1}
	if rest == "" {
		return p
	}
	neg := false
	tok := rest
	if strings.HasPrefix(tok, "-") {
		neg = true
		tok = tok[1:]
	} else if strings.HasPrefix(tok, "+") {
		tok = tok[1:]
	}
	num := ""
	for _, r := range tok {
		if r >= '0' && r <= '9' {
			num += string(r)
		} else {
			break
		}
	}
	at := 1
	if num != "" {
		if v, err := strconv.Atoi(num); err == nil {
			at = v
		}
	}
	if neg {
		at = -at
	}
	p.TlsRecAt = at
	// +s / +e / +se / +es — якорь SNI (как byeDPI OFFSET_SNI / OFFSET_END)
	flags := rest
	if i := strings.IndexByte(flags, '+'); i >= 0 {
		flags = strings.ToLower(flags[i:])
		p.TlsRecSNI = strings.Contains(flags, "s") || strings.Contains(flags, "h")
		p.TlsRecEnd = strings.Contains(flags, "e")
	}
	return p
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	if v == 0 {
		return 1
	}
	return v
}
