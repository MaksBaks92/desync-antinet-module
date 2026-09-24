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

	dl, ok := parseDesyncLink(link)
	if !ok {
		dl = desyncLink{Preset: "general", Raw: link}
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

	lists := loadDefaultLists()
	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)

	var netDown atomic.Bool

	setHostEventHandler(func(event string) {
		switch event {
		case "handover":
			// Нет долгоживущей сессии: новые CONNECT сами пойдут через новый protect/offtun.
			// SOCKS listen не перебиндиваем (контракт MODULE_API).
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
		// dns= — канон shared/dns; обработчика нет намеренно.
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
	log.Printf("desync helper: SOCKS5 on 127.0.0.1:%d preset=%s auto=%v protect=%s",
		actualPort, dl.Preset, dl.Auto, protectPath)
	emitLog("preset=%s auto=%v lists=general/google/exclude", dl.Preset, dl.Auto)

	sess := &session{
		user:        user,
		pass:        pass,
		protectPath: protectPath,
		dialTimeout: dialTimeout,
		resolver:    resolver,
		lists:       lists,
		preset:      dl.Preset,
		auto:        dl.Auto,
		netDown:     &netDown,
	}

	serveSocksListener(ln, func(c net.Conn) {
		handleConn(c, sess)
	})
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
	netDown     *atomic.Bool
}

func handleConn(c net.Conn, sess *session) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, sess.user, sess.pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		// MVP: UDP ASSOCIATE — passthrough (без QUIC/Discord UDP-fake).
		serveSocksUDPAssociate(c, br, desyncUDPTransport{
			resolver:    sess.resolver,
			protectPath: sess.protectPath,
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
	rule, preset, _ := selectRuleForPreset(presetName, host, req.Port, sess.lists)
	log.Printf("desync apply preset=%s rule=%s host=%s:%d payload=%d",
		preset.Name, rule.Name, host, req.Port, len(payload))

	if err := applyPrimitives(up, host, rule, payload); err != nil {
		log.Printf("desync apply failed host=%s rule=%s err=%v", host, rule.Name, err)
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
	return nc, nil
}

type uiStrings struct {
	progressSocksUpFmt string
	progressHandover   string
	logStartFailedFmt  string
	logHandover        string
	logNetLost         string
	logNetBack         string
	logStall           string
}

var uiRU = uiStrings{
	progressSocksUpFmt: "desync: SOCKS5 поднят на 127.0.0.1:%d",
	progressHandover:   "desync: сеть сменилась — новые соединения пойдут через новый маршрут",
	logStartFailedFmt:  "не удалось записать маркер готовности: %v",
	logHandover:        "хендовер: сменилась сеть по умолчанию",
	logNetLost:         "сети нет — новые dial приостановлены",
	logNetBack:         "сеть вернулась",
	logStall:           "хост не дождался ответа через модуль — сеть не менялась",
}

var uiEN = uiStrings{
	progressSocksUpFmt: "desync: SOCKS5 up on 127.0.0.1:%d",
	progressHandover:   "desync: network changed — new connections use the new route",
	logStartFailedFmt:  "failed to write ready marker: %v",
	logHandover:        "handover: default network changed",
	logNetLost:         "no network — dials paused",
	logNetBack:         "network is back",
	logStall:           "host saw no answer through module — network unchanged",
}

func uiStringsFor(lang string) uiStrings {
	return stringsForLang(lang, uiRU, uiEN)
}
