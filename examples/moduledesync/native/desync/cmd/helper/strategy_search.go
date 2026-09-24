// SPDX-License-Identifier: MIT
package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed lists/strategies.list
var strategiesListRaw string

type searchConfig struct {
	Enabled       bool
	ApplyBest     bool
	AskChoice     bool
	UseUserList   bool
	UserList      string
	SNI           string
	Requests      int
	TimeoutSec    int
	DelayMs       int
	Concurrency   int
	MaxSites      int
	MaxStrategies int
}

func defaultSearchConfig() searchConfig {
	return searchConfig{
		Enabled:       false,
		ApplyBest:     true,
		AskChoice:     false,
		SNI:           "google.com",
		Requests:      1,
		TimeoutSec:    4,
		DelayMs:       300,
		Concurrency:   10,
		MaxSites:      12,
		MaxStrategies: 40,
	}
}

type strategyScore struct {
	Strategy searchStrategy
	Success  int
	Total    int
	Sites    []string // "host ok/n"
}

func (s strategyScore) pct() float64 {
	if s.Total <= 0 {
		return 0
	}
	return 100.0 * float64(s.Success) / float64(s.Total)
}

// loadSearchStrategies — builtin ByeByeDPI list или свой список пользователя.
func loadSearchStrategies(cfg searchConfig) []searchStrategy {
	raw := strategiesListRaw
	if cfg.UseUserList && strings.TrimSpace(cfg.UserList) != "" {
		raw = cfg.UserList
	}
	return parseStrategyLines(raw, cfg.SNI)
}

func loadSearchSites(lists hostLists, max int) []string {
	sites := append([]string{}, lists.filter...)
	if len(sites) == 0 {
		sites = parseHostlist(builtinYoutubeRaw)
		sites = append(sites, parseHostlist(builtinGooglevideoRaw)...)
		sites = uniqHosts(sites)
	}
	// Убрать IP-only и совсем короткие
	var out []string
	for _, h := range sites {
		h = strings.TrimSpace(h)
		if h == "" || net.ParseIP(h) != nil {
			continue
		}
		out = append(out, h)
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// runStrategySearch — аналог ByeByeDPI TestActivity: прогон стратегий по доменам.
func runStrategySearch(
	cfg searchConfig,
	lists hostLists,
	protectPath string,
	resolver *protectedResolver,
	profileDir string,
	lang string,
) (best searchStrategy, scores []strategyScore, ok bool) {
	s := uiStringsFor(lang)
	strategies := loadSearchStrategies(cfg)
	if cfg.MaxStrategies > 0 && len(strategies) > cfg.MaxStrategies {
		strategies = strategies[:cfg.MaxStrategies]
	}
	sites := loadSearchSites(lists, cfg.MaxSites)
	if len(strategies) == 0 {
		emitLog("%s", s.searchNoStrategies)
		return searchStrategy{}, nil, false
	}
	if len(sites) == 0 {
		emitLog("%s", s.searchNoSites)
		return searchStrategy{}, nil, false
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	reqs := cfg.Requests
	if reqs <= 0 {
		reqs = 1
	}
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 10
	}
	delay := time.Duration(cfg.DelayMs) * time.Millisecond

	emitProgress("%s", s.searchStart)
	emitLog(s.searchStartFmt, len(strategies), len(sites), reqs)

	scores = make([]strategyScore, 0, len(strategies))
	for i, st := range strategies {
		emitProgress(s.searchProgressFmt, i+1, len(strategies), st.Label)
		emitLog("search [%d/%d] %s | %s", i+1, len(strategies), st.Label, truncate(st.Raw, 80))

		sc := strategyScore{Strategy: st}
		siteResults := probeSitesParallel(sites, reqs, timeout, conc, protectPath, resolver, st)
		for _, r := range siteResults {
			sc.Total += r.total
			sc.Success += r.ok
			sc.Sites = append(sc.Sites, fmt.Sprintf("%s %d/%d", r.host, r.ok, r.total))
		}
		scores = append(scores, sc)
		emitLog("search result %s → %d/%d (%.0f%%)", st.Label, sc.Success, sc.Total, sc.pct())

		if delay > 0 {
			time.Sleep(delay)
		}
	}

	sort.SliceStable(scores, func(i, j int) bool {
		if scores[i].Success != scores[j].Success {
			return scores[i].Success > scores[j].Success
		}
		return scores[i].pct() > scores[j].pct()
	})

	saveSearchResults(profileDir, scores)

	if len(scores) == 0 || scores[0].Success == 0 {
		emitLog("%s", s.searchNoneWorked)
		emitProgress("%s", s.searchDone)
		return searchStrategy{}, scores, false
	}

	best = scores[0].Strategy
	emitLog(s.searchBestFmt, best.Label, scores[0].Success, scores[0].Total, best.Raw)
	emitProgress("%s", s.searchDone)
	return best, scores, true
}

type siteProbeResult struct {
	host  string
	ok    int
	total int
}

func probeSitesParallel(
	sites []string,
	reqs int,
	timeout time.Duration,
	conc int,
	protectPath string,
	resolver *protectedResolver,
	st searchStrategy,
) []siteProbeResult {
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	out := make([]siteProbeResult, len(sites))
	for i, host := range sites {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok := 0
			for n := 0; n < reqs; n++ {
				if probeHTTPS(host, timeout, protectPath, resolver, st) {
					ok++
				}
			}
			out[i] = siteProbeResult{host: host, ok: ok, total: reqs}
		}(i, host)
	}
	wg.Wait()
	return out
}

// probeHTTPS — dial:443 + desync(ClientHello+SNI) + ждём TLS record (ServerHello).
func probeHTTPS(host string, timeout time.Duration, protectPath string, resolver *protectedResolver, st searchStrategy) bool {
	ips, err := resolver.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	var pst protectStat
	d := net.Dialer{Timeout: timeout, Control: dialControl(protectPath, &pst)}
	conn, err := d.Dial("tcp", net.JoinHostPort(ips[0], "443"))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	setTCPNoDelay(conn, true)

	hello := buildTLSClientHello(host)
	rule := Rule{Name: st.Label, Prims: st.Prims}
	if err := applyPrimitives(conn, host, rule, hello); err != nil {
		return false
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		return false
	}
	// TLS record: Handshake(0x16) / Alert(0x15) / ChangeCipherSpec(0x14) / AppData(0x17)
	return buf[0] >= 0x14 && buf[0] <= 0x17 && buf[1] == 0x03
}

func saveSearchResults(profileDir string, scores []strategyScore) {
	if profileDir == "" {
		return
	}
	var b strings.Builder
	b.WriteString("# desync strategy search results (ByeByeDPI-like)\n")
	for i, sc := range scores {
		fmt.Fprintf(&b, "\n# %d) %.0f%% %d/%d  %s\n", i+1, sc.pct(), sc.Success, sc.Total, sc.Strategy.Label)
		b.WriteString(sc.Strategy.Raw)
		b.WriteByte('\n')
		for _, line := range sc.Sites {
			b.WriteString("  ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	path := filepath.Join(profileDir, "strategy_search_results.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		log.Printf("desync: write search results: %v", err)
	}
	if len(scores) > 0 && scores[0].Success > 0 {
		bestPath := filepath.Join(profileDir, "best_strategy.txt")
		_ = os.WriteFile(bestPath, []byte(scores[0].Strategy.Raw+"\n"), 0o644)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// buildTLSClientHello — минимальный TLS 1.2 ClientHello с SNI (для probe).
func buildTLSClientHello(serverName string) []byte {
	sn := []byte(serverName)
	// extension: server_name
	sniBody := make([]byte, 0, 5+len(sn))
	sniBody = append(sniBody, byte((len(sn)+3)>>8), byte(len(sn)+3))
	sniBody = append(sniBody, 0x00) // host_name
	sniBody = append(sniBody, byte(len(sn)>>8), byte(len(sn)))
	sniBody = append(sniBody, sn...)

	ext := make([]byte, 0, 4+len(sniBody))
	ext = append(ext, 0x00, 0x00) // server_name type
	ext = append(ext, byte(len(sniBody)>>8), byte(len(sniBody)))
	ext = append(ext, sniBody...)
	// supported_versions not required for many servers with 1.2 hello

	// cipher suites: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, empty reneg
	ciphers := []byte{0x00, 0x04, 0xc0, 0x2f, 0x00, 0x2f}
	comp := []byte{0x01, 0x00}

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}

	hs := make([]byte, 0, 256)
	hs = append(hs, 0x01)             // ClientHello
	hs = append(hs, 0, 0, 0)          // length placeholder
	hs = append(hs, 0x03, 0x03)       // TLS 1.2
	hs = append(hs, random...)
	hs = append(hs, 0) // session id len
	hs = append(hs, ciphers...)
	hs = append(hs, comp...)
	hs = append(hs, byte(len(ext)>>8), byte(len(ext)))
	hs = append(hs, ext...)

	hsLen := len(hs) - 4
	hs[1] = byte(hsLen >> 16)
	hs[2] = byte(hsLen >> 8)
	hs[3] = byte(hsLen)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// applySearchBest — выставить runtime override примитивов + byedpi opts.
func applySearchBest(sess *session, best searchStrategy) {
	if sess == nil {
		return
	}
	sess.optsMu.Lock()
	sess.opts.Method = best.Opts.Method
	sess.opts.SplitPos = best.Opts.SplitPos
	if best.Opts.OOBChar != 0 {
		sess.opts.OOBChar = best.Opts.OOBChar
	}
	// Подбор имеет смысл в byedpi-режиме.
	if sess.preset == "byedpi" || sess.preset == "" {
		sess.preset = "byedpi"
	}
	sess.optsMu.Unlock()
	prims := append([]Primitive{}, best.Prims...)
	sess.overridePrims.Store(prims)
	log.Printf("desync: applied best strategy label=%s method=%s pos=%d prims=%d",
		best.Label, best.Opts.Method, best.Opts.SplitPos, len(prims))
}

// pickStrategyChoice — опциональный choice с топ-стратегиями (как «применить» в ByeByeDPI).
func pickStrategyChoice(profileDir string, scores []strategyScore, lang string) (searchStrategy, bool) {
	s := uiStringsFor(lang)
	n := len(scores)
	if n > 5 {
		n = 5
	}
	options := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		sc := scores[i]
		if sc.Success == 0 {
			continue
		}
		label := fmt.Sprintf("%.0f%% %s", sc.pct(), sc.Strategy.Label)
		options = append(options, map[string]any{
			"id":    fmt.Sprintf("%d", i),
			"label": label,
		})
	}
	if len(options) == 0 {
		return searchStrategy{}, false
	}
	res, cancelled := runAction(profileDir, "desync-pick-strategy", map[string]any{
		"type":    "choice",
		"title":   s.searchChoiceTitle,
		"text":    s.searchChoiceText,
		"options": options,
	})
	if cancelled {
		return searchStrategy{}, false
	}
	id := strings.TrimSpace(actionResultString(res, "id"))
	if id == "" {
		id = strings.TrimSpace(res)
	}
	idx := 0
	if _, err := fmt.Sscanf(id, "%d", &idx); err != nil {
		return scores[0].Strategy, true
	}
	if idx < 0 || idx >= len(scores) {
		return scores[0].Strategy, true
	}
	return scores[idx].Strategy, true
}