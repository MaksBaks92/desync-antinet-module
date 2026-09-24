// SPDX-License-Identifier: MIT
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
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

func setUDPConnTTL(c net.Conn, ttl int) error {
	if ttl <= 0 {
		return fmt.Errorf("ttl disabled")
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("not *net.UDPConn")
	}
	if err := ipv4.NewConn(uc).SetTTL(ttl); err == nil {
		return nil
	}
	return ipv6.NewConn(uc).SetHopLimit(ttl)
}

func resetUDPConnTTL(c net.Conn) {
	_ = setUDPConnTTL(c, 64)
}

// byeDPI udp_data — 64 нулевых байта (packets.c).
const udpFakeSize = 64

// udpDesyncConn — ByeByeDPI desync_udp (-aN): перед первым реальным датаграммом
// шлёт N нулевых fake @ TTL (DEFAULT_TTL=8), затем восстанавливает TTL.
type udpDesyncConn struct {
	net.Conn
	fakeCount int
	fakeTTL   int
	dstLabel  string
	once      sync.Once
	fakeErr   error
}

func wrapUDPDesync(c net.Conn, count, ttl int, dst string) net.Conn {
	if c == nil || count <= 0 {
		return c
	}
	if ttl <= 0 {
		ttl = 8
	}
	return &udpDesyncConn{Conn: c, fakeCount: count, fakeTTL: ttl, dstLabel: dst}
}

func (c *udpDesyncConn) Write(b []byte) (int, error) {
	c.once.Do(func() {
		if err := setUDPConnTTL(c.Conn, c.fakeTTL); err != nil {
			log.Printf("desync udp-fake dst=%s SKIP ttl-set-failed err=%v", c.dstLabel, err)
			return
		}
		fake := make([]byte, udpFakeSize)
		for i := 0; i < c.fakeCount; i++ {
			if _, err := c.Conn.Write(fake); err != nil {
				c.fakeErr = err
				resetUDPConnTTL(c.Conn)
				log.Printf("desync udp-fake dst=%s write-failed i=%d err=%v", c.dstLabel, i, err)
				return
			}
		}
		resetUDPConnTTL(c.Conn)
		log.Printf("desync udp-fake dst=%s count=%d ttl=%d", c.dstLabel, c.fakeCount, c.fakeTTL)
	})
	if c.fakeErr != nil {
		return 0, c.fakeErr
	}
	return c.Conn.Write(b)
}

// findSNIOffset — смещение TLS extension server_name; -1 если нет.
func findSNIOffset(b []byte) int {
	_, extOff, _, _ := parseTLSClientHelloSNI(b)
	return extOff
}

// extractTLSServerName — hostname из ClientHello SNI (пустая строка если нет).
func extractTLSServerName(b []byte) string {
	name, _, _, _ := parseTLSClientHelloSNI(b)
	return name
}

// parseTLSClientHelloSNI — имя, offset extension, absolute hostPos/hostLen (байты hostname).
// hostPos совпадает с byeDPI host_pos (абсолютный offset в буфере).
func parseTLSClientHelloSNI(b []byte) (name string, extStart, hostPos, hostLen int) {
	extStart, hostPos, hostLen = -1, -1, 0
	// TLS record: type=0x16, ver, len; handshake type=0x01 ClientHello
	if len(b) < 44 || b[0] != 0x16 {
		return "", -1, -1, 0
	}
	if len(b) > 5 && b[5] != 0x01 {
		return "", -1, -1, 0
	}
	i := 43
	if i >= len(b) {
		return "", -1, -1, 0
	}
	sidLen := int(b[i])
	i++
	i += sidLen
	if i+2 > len(b) {
		return "", -1, -1, 0
	}
	csLen := int(b[i])<<8 | int(b[i+1])
	i += 2 + csLen
	if i+1 > len(b) {
		return "", -1, -1, 0
	}
	compLen := int(b[i])
	i++
	i += compLen
	if i+2 > len(b) {
		return "", -1, -1, 0
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
		es := i
		if typ == 0x0000 { // server_name
			j := i + 4
			if j+2 > end {
				return "", es, -1, 0
			}
			// list_len + name_type + name_len + name
			j += 2
			if j+3 > end {
				return "", es, -1, 0
			}
			if b[j] != 0 { // host_name
				return "", es, -1, 0
			}
			j++
			nlen := int(b[j])<<8 | int(b[j+1])
			j += 2
			if j+nlen > end || nlen <= 0 {
				return "", es, -1, 0
			}
			return string(b[j : j+nlen]), es, j, nlen
		}
		i += 4 + l
	}
	return "", -1, -1, 0
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

func firstPos(positions []int, def int) int {
	if len(positions) > 0 && positions[0] != 0 {
		if positions[0] < 0 {
			return def
		}
		return positions[0]
	}
	return def
}

func oobChar(b byte) byte {
	if b == 0 {
		return 'a'
	}
	return b
}

// writeDisorder — аналог byeDPI -dN: сначала хвост, потом голова.
func writeDisorder(c net.Conn, payload []byte, pos int) error {
	if len(payload) == 0 {
		return nil
	}
	if pos <= 0 {
		pos = 1
	}
	if pos >= len(payload) {
		pos = len(payload) / 2
		if pos <= 0 {
			_, err := c.Write(payload)
			return err
		}
	}
	if _, err := c.Write(payload[pos:]); err != nil {
		return err
	}
	time.Sleep(1 * time.Millisecond)
	_, err := c.Write(payload[:pos])
	return err
}

// writeOOB — аналог byeDPI -oN -eX: голова, urgent byte, хвост.
func writeOOB(c net.Conn, payload []byte, pos int, ch byte) error {
	if len(payload) == 0 {
		return nil
	}
	if pos <= 0 {
		pos = 1
	}
	if pos >= len(payload) {
		pos = 1
		if pos >= len(payload) {
			_, err := c.Write(payload)
			return err
		}
	}
	if _, err := c.Write(payload[:pos]); err != nil {
		return err
	}
	if err := sendTCPOOB(c, ch); err != nil {
		return err
	}
	time.Sleep(1 * time.Millisecond)
	_, err := c.Write(payload[pos:])
	return err
}

// writeDisOOB — аналог byeDPI -qN: хвост, OOB, голова.
func writeDisOOB(c net.Conn, payload []byte, pos int, ch byte) error {
	if len(payload) == 0 {
		return nil
	}
	if pos <= 0 {
		pos = 1
	}
	if pos >= len(payload) {
		pos = len(payload) / 2
		if pos <= 0 {
			_, err := c.Write(payload)
			return err
		}
	}
	if _, err := c.Write(payload[pos:]); err != nil {
		return err
	}
	if err := sendTCPOOB(c, ch); err != nil {
		return err
	}
	time.Sleep(1 * time.Millisecond)
	_, err := c.Write(payload[:pos])
	return err
}

func applyTlsRec(c net.Conn, payload []byte, at int) (bool, error) {
	// Legacy write-split path (absolute content pos). Prefer partTLS via applyPrimitives.
	out, ok := partTLS(payload, at)
	if !ok {
		return false, nil
	}
	if err := writeChunks(c, out, []int{5 + at}); err != nil {
		return true, err
	}
	return true, nil
}

// partTLS — byeDPI part_tls: один TLS record → два подряд в том же TCP-буфере (+5 байт).
// contentPos — длина content первого record (байты handshake после 5-байтного hdr).
func partTLS(payload []byte, contentPos int) ([]byte, bool) {
	n := len(payload)
	if n < 3 || contentPos < 0 || contentPos+5 > n {
		return payload, false
	}
	if payload[0] != 0x16 {
		return payload, false
	}
	rSz := int(payload[3])<<8 | int(payload[4])
	if rSz < contentPos {
		return payload, false
	}
	out := make([]byte, n+5)
	copy(out[0:3], payload[0:3])
	out[3] = byte(contentPos >> 8)
	out[4] = byte(contentPos)
	copy(out[5:5+contentPos], payload[5:5+contentPos])
	copy(out[5+contentPos:5+contentPos+3], payload[0:3])
	secondLen := rSz - contentPos
	out[5+contentPos+3] = byte(secondLen >> 8)
	out[5+contentPos+4] = byte(secondLen)
	copy(out[5+contentPos+5:], payload[5+contentPos:n])
	return out, true
}

// tlsRecContentPos — byeDPI gen_offset + pos-=5 для -rN[+s][+e].
func tlsRecContentPos(payload []byte, p Primitive) int {
	at := p.TlsRecAt
	if p.TlsRecSNI {
		_, _, hostPos, hostLen := parseTLSClientHelloSNI(payload)
		if hostPos < 0 || hostLen <= 0 {
			return -1
		}
		base := hostPos
		if p.TlsRecEnd {
			base = hostPos + hostLen
		}
		pos := at + base
		// byeDPI: if (part.pos < 0 || part.flag) pos -= 5;
		if at < 0 || p.TlsRecSNI {
			pos -= 5
		}
		return pos
	}
	if at < 0 {
		at = -at
	}
	if at <= 0 {
		at = 3
	}
	return at
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
		case "disorder":
			if err := writeDisorder(up, payload, firstPos(p.Positions, 1)); err != nil {
				return err
			}
			wrote = true
			return nil
		case "oob":
			if err := writeOOB(up, payload, firstPos(p.Positions, 1), oobChar(p.OOBChar)); err != nil {
				log.Printf("desync: oob failed host=%s err=%v; fallback split", host, err)
				if err2 := writeChunks(up, payload, []int{firstPos(p.Positions, 1)}); err2 != nil {
					return err2
				}
			}
			wrote = true
			return nil
		case "disoob":
			if err := writeDisOOB(up, payload, firstPos(p.Positions, 1), oobChar(p.OOBChar)); err != nil {
				log.Printf("desync: disoob failed host=%s err=%v; fallback disorder", host, err)
				if err2 := writeDisorder(up, payload, firstPos(p.Positions, 1)); err2 != nil {
					return err2
				}
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
			// byeDPI: tamp-буфер до send-метода — не пишем на wire, не ставим wrote.
			contentPos := tlsRecContentPos(payload, p)
			if contentPos < 0 {
				continue
			}
			out, ok := partTLS(payload, contentPos)
			if !ok {
				continue
			}
			payload = out
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
