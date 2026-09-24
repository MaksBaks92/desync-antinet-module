// SPDX-License-Identifier: MIT
//
// desync helper — AntiNet SOCKS5-модуль с DPI-desync на исходящем TCP (ByeDPI-like).
// SOCKS5 / protect / dns / lifecycle / hostproto / entry — каноны shared/* через build.py.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func moduleCall(verb, arg string) string {
	switch verb {
	case "summarize":
		name, server := summarizeDesync(strings.TrimSpace(arg))
		return name + "\n" + server
	case "normalize":
		return normalizeDesync(arg)
	}
	return ""
}

func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath
	startHostEventReader()
	dieWithParent()
	protectFromOomKill()

	cfg := parseConfig(configContent)
	port, _ := strconv.Atoi(cfg["LISTEN_PORT"])
	user := cfg["SOCKS_USER"]
	pass := cfg["SOCKS_PASS"]
	link := cfg["LINK"]
	lang := strings.TrimSpace(cfg["APP_LANG"])
	s := uiStringsFor(lang)

	dialTimeout := 5 * time.Second
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_dialTimeoutSec"])); err == nil && v > 0 {
		dialTimeout = time.Duration(v) * time.Second
	}

	opts := defaultDesyncOpts()
	if m := strings.ToLower(strings.TrimSpace(cfg["SETTING_hostsMode"])); m != "" {
		opts.HostsMode = m
	}
	if m := strings.ToLower(strings.TrimSpace(cfg["SETTING_method"])); m != "" {
		opts.Method = m
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_splitPosition"])); err == nil {
		opts.SplitPos = v
	}
	if oc := strings.TrimSpace(cfg["SETTING_oobChar"]); oc != "" {
		opts.OOBChar = oc[0]
	}
	if v, ok := cfg["SETTING_desyncHttps"]; ok {
		opts.DesyncHTTPS = v == "true" || v == "1"
	}
	if v, ok := cfg["SETTING_desyncHttp"]; ok {
		opts.DesyncHTTP = v == "true" || v == "1"
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_udpFakeCount"])); err == nil && v >= 0 {
		opts.UdpFakeCount = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_fakeTTL"])); err == nil && v > 0 {
		opts.FakeTTL = v
	}

	dl, ok := parseDesyncLink(link)
	if !ok {
		dl = desyncLink{Preset: "byedpi", Raw: link}
	}
	// Настройки модуля — на всю схему. Явный путь в ссылке (desync://alt) важнее,
	// иначе все конфиги схлопнулись бы в один SETTING_preset.
	if !dl.Explicit {
		if presetName := strings.TrimSpace(cfg["SETTING_preset"]); presetName != "" && knownPreset(presetName) {
			dl.Preset = strings.ToLower(presetName)
		}
	}
	if cfg["SETTING_auto"] == "true" || cfg["SETTING_auto"] == "1" {
		dl.Auto = true
	}
	if dl.Preset == "auto" {
		dl.Auto = true
	}

	builtinCSV := strings.TrimSpace(cfg["SETTING_builtinLists"])
	if builtinCSV == "" {
		builtinCSV = "youtube,googlevideo"
	}
	userDomains := cfg["SETTING_userDomains"]

	lists := loadDefaultLists()
	lists.filter = buildFilterHosts(builtinCSV, userDomains, profileDir)
	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)

	searchCfg := defaultSearchConfig()
	if cfg["SETTING_strategySearch"] == "true" || cfg["SETTING_strategySearch"] == "1" {
		searchCfg.Enabled = true
	}
	if v, ok := cfg["SETTING_applyBestStrategy"]; ok {
		searchCfg.ApplyBest = v == "true" || v == "1"
	}
	if cfg["SETTING_askStrategyChoice"] == "true" || cfg["SETTING_askStrategyChoice"] == "1" {
		searchCfg.AskChoice = true
	}
	if cfg["SETTING_useUserStrategies"] == "true" || cfg["SETTING_useUserStrategies"] == "1" {
		searchCfg.UseUserList = true
	}
	searchCfg.UserList = cfg["SETTING_userStrategies"]
	if v := strings.TrimSpace(cfg["SETTING_searchSNI"]); v != "" {
		searchCfg.SNI = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_searchRequests"])); err == nil && v > 0 {
		searchCfg.Requests = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_searchTimeoutSec"])); err == nil && v > 0 {
		searchCfg.TimeoutSec = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_searchDelayMs"])); err == nil && v >= 0 {
		searchCfg.DelayMs = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_searchConcurrency"])); err == nil && v > 0 {
		searchCfg.Concurrency = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(cfg["SETTING_searchMaxSites"])); err == nil && v > 0 {
		searchCfg.MaxSites = v
	}

	var netDown atomic.Bool

	setHostEventHandler(func(event string) {
		switch event {
		case "handover":
			emitProgress("%s", s.progressHandover)
			emitLog(s.logHandover)
		case "netlost":
			netDown.Store(true)
			emitLog(s.logNetLost)
		case "netback":
			netDown.Store(false)
			emitLog(s.logNetBack)
		case "stall":
			emitLog(s.logStall)
		}
	})

	ln, err := openListener(port, listenFd)
	if err != nil {
		log.Fatalf("listen 127.0.0.1:%d: %v", port, err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	emitProgress(s.progressSocksUpFmt, actualPort)
	emitStatus(statusOK, "")

	if err := writeReady(profileDir, actualPort); err != nil {
		emitLog(s.logStartFailedFmt, err)
		emitStatus(statusFatal, "write ready marker failed")
		log.Fatalf("write ready marker: %v", err)
	}
	log.Printf("desync helper: SOCKS5 on 127.0.0.1:%d ver=1.2.9 preset=%s method=%s hostsMode=%s udpFake=%d filter=%d auto=%v protect=%s",
		actualPort, dl.Preset, opts.Method, opts.HostsMode, opts.UdpFakeCount, len(lists.filter), dl.Auto, protectPath)
	emitLog("ver=1.2.9 preset=%s method=%s hostsMode=%s udpFake=%d filterHosts=%d builtin=%s",
		dl.Preset, opts.Method, opts.HostsMode, opts.UdpFakeCount, len(lists.filter), builtinCSV)

	sess := &session{
		user:        user,
		pass:        pass,
		protectPath: protectPath,
		dialTimeout: dialTimeout,
		resolver:    resolver,
		lists:       lists,
		preset:      dl.Preset,
		auto:        dl.Auto,
		opts:        opts,
		netDown:     &netDown,
	}

	// SOCKS принимаем сразу; подбор идёт параллельно (как тест в ByeByeDPI на живом прокси).
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		serveSocksListener(ln, func(c net.Conn) {
			handleConn(c, sess)
		})
	}()

	if searchCfg.Enabled {
		best, scores, sok := runStrategySearch(searchCfg, lists, protectPath, resolver, profileDir, lang)
		if sok {
			chosen := best
			if searchCfg.AskChoice {
				if c, ok := pickStrategyChoice(profileDir, scores, lang); ok {
					chosen = c
				}
			}
			if searchCfg.ApplyBest || searchCfg.AskChoice {
				applySearchBest(sess, chosen)
				emitLog(s.searchAppliedFmt, chosen.Label)
			}
		}
	}

	<-serveDone
	return 0
}

type session struct {
	user, pass  string
	protectPath string
	dialTimeout time.Duration
	resolver    *protectedResolver
	lists       hostLists
	preset      string
	auto        bool
	optsMu      sync.Mutex
	opts        desyncOpts
	overridePrims atomic.Value // []Primitive
	netDown     *atomic.Bool
}

func (sess *session) currentOpts() desyncOpts {
	sess.optsMu.Lock()
	defer sess.optsMu.Unlock()
	return sess.opts
}

func (sess *session) currentOverridePrims() []Primitive {
	v := sess.overridePrims.Load()
	if v == nil {
		return nil
	}
	p, _ := v.([]Primitive)
	return p
}

func shouldApplySearchOverride(rule Rule) bool {
	switch rule.Name {
	case "hosts-gate-passthrough", "proto-passthrough", "exclude-passthrough", "port-passthrough", "no-match-passthrough",
		"cloudflare-passthrough", "cloudflare-soft-split", "cloudflare-fake-disorder", "cloudflare-fake-oob", "cloudflare-white-sni",
		"youtube-image-passthrough", "youtube-image-disorder":
		return false
	}
	if strings.HasPrefix(rule.Name, "byedpi-soft-") {
		return false
	}
	if len(rule.Prims) == 1 && rule.Prims[0].Kind == "passthrough" {
		return false
	}
	return true
}

func handleConn(c net.Conn, sess *session) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, sess.user, sess.pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		// ByeByeDPI -aN: UDP fake перед первым датаграммом (QUIC YouTube app / Discord).
		cur := sess.currentOpts()
		fakeCount := cur.UdpFakeCount
		if sess.preset == "passthrough" {
			fakeCount = 0
		}
		fakeTTL := cur.FakeTTL
		if fakeTTL <= 0 {
			fakeTTL = 8
		}
		serveSocksUDPAssociate(c, br, desyncUDPTransport{
			resolver:    sess.resolver,
			protectPath: sess.protectPath,
			fakeCount:   fakeCount,
			fakeTTL:     fakeTTL,
		})
		return
	}

	if sess.netDown != nil && sess.netDown.Load() {
		_, _ = c.Write(socksRep(0x01))
		return
	}

	host := req.TargetLabel()
	target := net.JoinHostPort(host, strconv.Itoa(int(req.Port)))

	dialStart := time.Now()
	lookupMs := 0.0
	dialTarget := target
	if !req.IsIP() {
		ips, lerr := sess.resolver.LookupHost(host)
		lookupMs = float64(time.Since(dialStart).Microseconds()) / 1000.0
		if lerr != nil {
			log.Printf("lookup FAILED host=%s err=%v", host, lerr)
			_, _ = c.Write(socksRep(0x01))
			return
		}
		if len(ips) > 0 {
			dialTarget = net.JoinHostPort(ips[0], strconv.Itoa(int(req.Port)))
		}
	}

	var pst protectStat
	d := net.Dialer{Timeout: sess.dialTimeout, Control: dialControl(sess.protectPath, &pst)}
	up, err := d.Dial("tcp", dialTarget)
	if err != nil {
		log.Printf("dial FAILED host=%s lookupMs=%.1f protectMs=%.1f err=%v", host, lookupMs, pst.elapsedMs, err)
		_, _ = c.Write(socksRep(0x01))
		return
	}
	defer up.Close()
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}

	setTCPNoDelay(up, true)
	setTCPNoDelay(c, true)

	// Первый клиентский payload → strategy; дальше обычный relay.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	payload, perr := readFirstPayload(br, 16*1024)
	_ = c.SetReadDeadline(time.Time{})
	if perr != nil || len(payload) == 0 {
		// Нет данных от клиента — просто реле (редко).
		relayBidi(c, br, up, target, dialStart)
		return
	}

	presetName := sess.preset
	matchHost := matchHostFromPayload(host, payload)
	curOpts := sess.currentOpts()
	// IP после реального Dial (надёжнее LookupHost[0] / hostname).
	dialIP := ""
	if ta, ok := up.RemoteAddr().(*net.TCPAddr); ok && ta.IP != nil {
		dialIP = ta.IP.String()
	} else if req.IsIP() {
		dialIP = host
	} else if h, _, err := net.SplitHostPort(dialTarget); err == nil && net.ParseIP(h) != nil {
		dialIP = h
	}
	rule, preset, _ := selectRuleForPreset(presetName, matchHost, req.Port, sess.lists, payload, curOpts, dialIP)
	if ov := sess.currentOverridePrims(); len(ov) > 0 && shouldApplySearchOverride(rule) {
		rule = Rule{Name: "search-override", Prims: ov}
	}
	log.Printf("desync apply preset=%s rule=%s socks=%s match=%s:%d dialIP=%s payload=%d tls=%v hostsMode=%s",
		preset.Name, rule.Name, host, matchHost, req.Port, dialIP, len(payload), looksLikeTLSClientHello(payload), curOpts.HostsMode)

	if err := applyPrimitives(up, matchHost, rule, payload); err != nil {
		log.Printf("desync apply failed host=%s match=%s rule=%s err=%v", host, matchHost, rule.Name, err)
		if sess.auto {
			// Failover: попробовать следующие пресеты на НОВОМ dial невозможно без
			// повторного CONNECT клиента; на уже открытом сокете меняем только «мягкие»
			// стратегии бессмысленно после partial write. Логируем цепочку для UX.
			log.Printf("desync auto: chain=%v (reconnect needed for next preset)", preset.AutoChain)
		}
		return
	}

	relayBidi(c, br, up, target, dialStart)
}

type desyncUDPTransport struct {
	resolver    *protectedResolver
	protectPath string
	fakeCount   int
	fakeTTL     int
}

func (t desyncUDPTransport) LookupHost(host string) ([]string, error) {
	return t.resolver.LookupHost(host)
}

func (t desyncUDPTransport) DialUDPTarget(dst netip.AddrPort) (net.Conn, error) {
	var pst protectStat
	d := net.Dialer{Control: dialControl(t.protectPath, &pst)}
	nc, err := d.Dial("udp", dst.String())
	if err != nil {
		return nil, fmt.Errorf("protectElapsed=%.3fms protectTries=%d protectErr=%q: %w",
			pst.elapsedMs, pst.attempts, pst.firstErr, err)
	}
	return wrapUDPDesync(nc, t.fakeCount, t.fakeTTL, dst.String()), nil
}

type uiStrings struct {
	progressSocksUpFmt string
	progressHandover   string
	logStartFailedFmt  string
	logHandover        string
	logNetLost         string
	logNetBack         string
	logStall           string
	searchStart        string
	searchStartFmt     string
	searchProgressFmt  string
	searchDone         string
	searchNoStrategies string
	searchNoSites      string
	searchNoneWorked   string
	searchBestFmt      string
	searchAppliedFmt   string
	searchChoiceTitle  string
	searchChoiceText   string
}

var uiRU = uiStrings{
	progressSocksUpFmt: "desync: SOCKS5 поднят на 127.0.0.1:%d",
	progressHandover:   "desync: сеть сменилась — новые соединения пойдут через новый маршрут",
	logStartFailedFmt:  "не удалось записать маркер готовности: %v",
	logHandover:        "хендовер: сменилась сеть по умолчанию",
	logNetLost:         "сети нет — новые dial приостановлены",
	logNetBack:         "сеть вернулась",
	logStall:           "хост не дождался ответа через модуль — сеть не менялась",
	searchStart:        "desync: подбор стратегий…",
	searchStartFmt:     "подбор: %d стратегий × %d доменов × %d запросов",
	searchProgressFmt:  "подбор %d/%d: %s",
	searchDone:         "desync: подбор завершён",
	searchNoStrategies: "подбор: нет стратегий (проверьте список)",
	searchNoSites:      "подбор: нет доменов — заполните списки или «Свои домены»",
	searchNoneWorked:   "подбор: ни одна стратегия не прошла",
	searchBestFmt:      "лучшая стратегия: %s (%d/%d) — %s",
	searchAppliedFmt:   "применена стратегия: %s",
	searchChoiceTitle:  "Выбор стратегии",
	searchChoiceText:   "Топ результатов подбора. Выберите стратегию для применения.",
}

var uiEN = uiStrings{
	progressSocksUpFmt: "desync: SOCKS5 up on 127.0.0.1:%d",
	progressHandover:   "desync: network changed — new connections use the new route",
	logStartFailedFmt:  "failed to write ready marker: %v",
	logHandover:        "handover: default network changed",
	logNetLost:         "no network — dials paused",
	logNetBack:         "network is back",
	logStall:           "host saw no answer through module — network unchanged",
	searchStart:        "desync: strategy search…",
	searchStartFmt:     "search: %d strategies × %d sites × %d requests",
	searchProgressFmt:  "search %d/%d: %s",
	searchDone:         "desync: strategy search done",
	searchNoStrategies: "search: no strategies",
	searchNoSites:      "search: no sites — fill domain lists or user domains",
	searchNoneWorked:   "search: no strategy succeeded",
	searchBestFmt:      "best strategy: %s (%d/%d) — %s",
	searchAppliedFmt:   "applied strategy: %s",
	searchChoiceTitle:  "Pick strategy",
	searchChoiceText:   "Top search results. Choose a strategy to apply.",
}

func uiStringsFor(lang string) uiStrings {
	return stringsForLang(lang, uiRU, uiEN)
}
