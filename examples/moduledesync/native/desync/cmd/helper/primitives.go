// SPDX-License-Identifier: MIT
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// setTCPNoDelay — сегменты уходят без Nagle (важно для split).
func setTCPNoDelay(c net.Conn, on bool) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(on)
	}
}

func setConnTTL(c net.Conn, ttl int) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl disabled")
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not *net.TCPConn")
	}
	if err := ipv4.NewConn(tc).SetTTL(ttl); err == nil {
		return nil
	}
	return ipv6.NewConn(tc).SetHopLimit(ttl)
}

func resetConnTTL(c net.Conn) {
	// Best-effort restore to a normal hop limit.
	_ = setConnTTL(c, 64)
}

// findSNIOffset — смещение TLS extension server_name; -1 если нет.
func findSNIOffset(b []byte) int {
	_, off := parseTLSClientHelloSNI(b)
	return off
}

// extractTLSServerName — hostname из ClientHello SNI (пустая строка если нет).
func extractTLSServerName(b []byte) string {
	name, _ := parseTLSClientHelloSNI(b)
	return name
}

// parseTLSClientHelloSNI — имя + offset extension server_name.
func parseTLSClientHelloSNI(b []byte) (string, int) {
	// TLS record: type=0x16, ver, len; handshake type=0x01 ClientHello
	if len(b) < 44 || b[0] != 0x16 {
		return "", -1
	}
	if len(b) > 5 && b[5] != 0x01 {
		return "", -1
	}
	i := 43
	if i >= len(b) {
		return "", -1
	}
	if i+1 > len(b) {
		return "", -1
	}
	sidLen := int(b[i])
	i++
	i += sidLen
	if i+2 > len(b) {
		return "", -1
	}
	csLen := int(b[i])<<8 | int(b[i+1])
	i += 2 + csLen
	if i+1 > len(b) {
		return "", -1
	}
	compLen := int(b[i])
	i++
	i += compLen
	if i+2 > len(b) {
		return "", -1
	}
	extLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	end := i + extLen
	if end > len(b) {
		end = len(b)
	}
	for i+4 <= end {
		typ := int(b[i])<<8 | int(b[i+1])
		l := int(b[i+2])<<8 | int(b[i+3])
		extStart := i
		if typ == 0x0000 { // server_name
			j := i + 4
			if j+2 > end {
				return "", extStart
			}
			// list_len + name_type + name_len + name
			j += 2
			if j+3 > end {
				return "", extStart
			}
			if b[j] != 0 { // host_name
				return "", extStart
			}
			j++
			nlen := int(b[j])<<8 | int(b[j+1])
			j += 2
			if j+nlen > end || nlen <= 0 {
				return "", extStart
			}
			return string(b[j : j+nlen]), extStart
		}
		i += 4 + l
	}
	return "", -1
}

// extractHTTPHost — Host: из HTTP/1.x запроса.
func extractHTTPHost(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	// Быстрый отсев TLS
	if b[0] == 0x16 {
		return ""
	}
	s := string(b)
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "\r\nhost:")
	if idx < 0 {
		idx = strings.Index(lower, "\nhost:")
		if idx < 0 {
			if strings.HasPrefix(lower, "host:") {
				idx = 0
			} else {
				return ""
			}
		}
	}
	line := s[idx:]
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	// "Host:" / "\r\nHost:"
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return ""
	}
	host := strings.TrimSpace(line[colon+1:])
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// matchHostFromPayload — SNI или HTTP Host; иначе SOCKS-label (часто уже IP).
func matchHostFromPayload(socksHost string, payload []byte) string {
	if sni := extractTLSServerName(payload); sni != "" {
		return strings.ToLower(strings.TrimSuffix(sni, "."))
	}
	if h := extractHTTPHost(payload); h != "" {
		return h
	}
	return strings.ToLower(strings.TrimSuffix(socksHost, "."))
}

func looksLikeTLSClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[5] == 0x01
}

func looksLikeHTTP(b []byte) bool {
	if len(b) < 4 || b[0] == 0x16 {
		return false
	}
	s := string(b[:min(len(b), 16)])
	for _, p := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "CONNECT "} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func syntheticTLSFake(size int) []byte {
	if size < 64 {
		size = 64
	}
	if size > 8*1024 {
		size = 8 * 1024
	}
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	// TLS record-ish header + handshake ClientHello type
	buf[0] = 0x16
	buf[1] = 0x03
	buf[2] = 0x01
	payload := size - 5
	buf[3] = byte(payload >> 8)
	buf[4] = byte(payload)
	if size > 5 {
		buf[5] = 0x01 // ClientHello
	}
	return buf
}

func writeChunks(c net.Conn, payload []byte, positions []int) error {
	if len(payload) == 0 {
		return nil
	}
	cuts := make([]int, 0, len(positions)+2)
	cuts = append(cuts, 0)
	for _, p := range positions {
		if p <= 0 {
			p = 1
		}
		if p > 0 && p < len(payload) {
			cuts = append(cuts, p)
		}
	}
	cuts = append(cuts, len(payload))
	// unique sorted
	for i := 0; i < len(cuts); i++ {
		for j := i + 1; j < len(cuts); j++ {
			if cuts[j] < cuts[i] {
				cuts[i], cuts[j] = cuts[j], cuts[i]
			}
		}
	}
	uniq := cuts[:0]
	prev := -1
	for _, x := range cuts {
		if x != prev {
			uniq = append(uniq, x)
			prev = x
		}
	}
	for i := 0; i+1 < len(uniq); i++ {
		chunk := payload[uniq[i]:uniq[i+1]]
		if len(chunk) == 0 {
			continue
		}
		if _, err := c.Write(chunk); err != nil {
			return err
		}
		// Небольшая пауза помогает OS отдать отдельные сегменты при NODELAY.
		time.Sleep(1 * time.Millisecond)
	}
	return nil
}

func writeEvenParts(c net.Conn, payload []byte, parts int) error {
	if parts < 2 {
		parts = 2
	}
	n := len(payload)
	if n == 0 {
		return nil
	}
	pos := make([]int, 0, parts-1)
	for i := 1; i < parts; i++ {
		p := n * i / parts
		if p > 0 && p < n {
			pos = append(pos, p)
		}
	}
	return writeChunks(c, payload, pos)
}

func applyTlsRec(c net.Conn, payload []byte, at int) (bool, error) {
	// Базовый tlsrec: если это TLS record, отправить record hdr + at байт handshake,
	// затем остаток отдельной записью (два write → два сегмента). Без пересборки length
	// это «грубый» вариант; полноценный record-split как у ByeDPI — TODO.
	if len(payload) < 6 || payload[0] != 0x16 {
		return false, nil
	}
	if at <= 0 {
		at = 3
	}
	splitAt := 5 + at
	if splitAt >= len(payload) {
		splitAt = len(payload) / 2
	}
	if splitAt <= 0 || splitAt >= len(payload) {
		return false, nil
	}
	if err := writeChunks(c, payload, []int{splitAt}); err != nil {
		return true, err
	}
	return true, nil
}

// applyPrimitives — десинк первого payload; возвращает true если payload уже ушёл на wire.
func applyPrimitives(up net.Conn, host string, rule Rule, payload []byte) error {
	setTCPNoDelay(up, true)

	wrote := false
	for _, p := range rule.Prims {
		switch p.Kind {
		case "unsupported":
			log.Printf("desync: skip unsupported host=%s rule=%s note=%q", host, rule.Name, p.Note)
			continue
		case "passthrough":
			if !wrote {
				_, err := up.Write(payload)
				return err
			}
			return nil
		case "fake":
			ttl := p.FakeTTL
			if ttl <= 0 {
				ttl = 1
			}
			repeats := p.FakeRepeats
			if repeats <= 0 {
				repeats = 1
			}
			fake := syntheticTLSFake(p.FakeSize)
			ttlOK := setConnTTL(up, ttl) == nil
			for i := 0; i < repeats; i++ {
				if _, err := up.Write(fake); err != nil {
					if ttlOK {
						resetConnTTL(up)
					}
					return err
				}
				time.Sleep(1 * time.Millisecond)
			}
			if ttlOK {
				resetConnTTL(up)
			} else {
				log.Printf("desync: fake TTL not set (OS/permission); sent fake anyway host=%s", host)
			}
			// fake не заменяет реальный payload — реальный уйдёт следующим примитивом или в конце
		case "split":
			pos := p.Positions
			if p.SplitSNI {
				if sni := findSNIOffset(payload); sni > 0 {
					pos = append(append([]int{}, pos...), sni)
				}
			}
			if err := writeChunks(up, payload, pos); err != nil {
				return err
			}
			wrote = true
			return nil
		case "multisplit":
			pos := append([]int{}, p.Positions...)
			if p.SplitSNI {
				if sni := findSNIOffset(payload); sni > 0 {
					pos = append(pos, sni)
				}
			}
			var err error
			if len(pos) == 0 {
				err = writeEvenParts(up, payload, p.Parts)
			} else {
				err = writeChunks(up, payload, pos)
			}
			if err != nil {
				return err
			}
			wrote = true
			return nil
		case "tlsrec":
			ok, err := applyTlsRec(up, payload, p.TlsRecAt)
			if err != nil {
				return err
			}
			if ok {
				wrote = true
				return nil
			}
		default:
			log.Printf("desync: unknown primitive %q host=%s", p.Kind, host)
		}
	}
	if !wrote {
		_, err := up.Write(payload)
		return err
	}
	return nil
}
