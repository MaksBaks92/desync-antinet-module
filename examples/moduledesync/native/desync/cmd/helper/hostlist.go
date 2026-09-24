// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
)

//go:embed lists/list-general.txt
var listGeneralRaw string

//go:embed lists/list-google.txt
var listGoogleRaw string

//go:embed lists/list-exclude.txt
var listExcludeRaw string

type hostLists struct {
	general []string
	google  []string
	exclude []string
}

var (
	defaultLists     hostLists
	defaultListsOnce sync.Once
)

func loadDefaultLists() hostLists {
	defaultListsOnce.Do(func() {
		defaultLists = hostLists{
			general: parseHostlist(listGeneralRaw),
			google:  parseHostlist(listGoogleRaw),
			exclude: parseHostlist(listExcludeRaw),
		}
	})
	return defaultLists
}

func parseHostlist(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return out
}

// hostMatch — Flowseal-style: ^prefix = exact/suffix-anchored domain match helper;
// иначе substring/suffix match на FQDN (host или *.host).
func hostMatch(host string, patterns []string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		exact := false
		if strings.HasPrefix(p, "^") {
			exact = true
			p = p[1:]
		}
		p = strings.ToLower(strings.TrimSuffix(p, "."))
		if p == "" {
			continue
		}
		if exact {
			if h == p || strings.HasSuffix(h, "."+p) {
				return true
			}
			continue
		}
		if h == p || strings.HasSuffix(h, "."+p) || strings.Contains(h, p) {
			return true
		}
	}
	return false
}

func (hl hostLists) excluded(host string) bool {
	return hostMatch(host, hl.exclude)
}

func (hl hostLists) inGeneral(host string) bool {
	return hostMatch(host, hl.general)
}

func (hl hostLists) inGoogle(host string) bool {
	return hostMatch(host, hl.google)
}

func (hl hostLists) isDiscord(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "discord") || hostMatch(host, []string{
		"discord.com", "discordapp.com", "discord.gg", "discord.media",
		"discordcdn.com", "discordapp.net",
	})
}

func (hl hostLists) isYoutube(host string) bool {
	return hl.inGoogle(host) || hostMatch(host, []string{
		"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
		"youtube-nocookie.com", "ggpht.com",
	})
}

// matchBucket — какую «корзину» Flowseal-правила применять к host.
type matchBucket int

const (
	bucketNone matchBucket = iota
	bucketExclude
	bucketGoogle
	bucketDiscord
	bucketGeneral
	bucketAll // без hostlist (ipset-all аналог на SOCKS: любой хост)
)

func (hl hostLists) classify(host string) matchBucket {
	if hl.excluded(host) {
		return bucketExclude
	}
	if hl.isDiscord(host) {
		return bucketDiscord
	}
	if hl.inGoogle(host) || hl.isYoutube(host) {
		return bucketGoogle
	}
	if hl.inGeneral(host) {
		return bucketGeneral
	}
	return bucketNone
}

// readFirstPayload — первый клиентский кусок после SOCKS CONNECT success.
// Ждём хотя бы 1 байт (дедлайн на conn снаружи), забираем всё уже буферизованное,
// затем коротко добираем хвост ClientHello, если он доехал отдельным сегментом.
func readFirstPayload(br *bufio.Reader, max int) ([]byte, error) {
	if max <= 0 {
		max = 16 * 1024
	}
	if _, err := br.Peek(1); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	for len(out) < max {
		n := br.Buffered()
		if n <= 0 {
			break
		}
		if n > len(tmp) {
			n = len(tmp)
		}
		if n > max-len(out) {
			n = max - len(out)
		}
		got, err := br.Read(tmp[:n])
		if got > 0 {
			out = append(out, tmp[:got]...)
		}
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
	}
	if len(out) == 0 {
		got, err := br.Read(tmp[:min(len(tmp), max)])
		if got > 0 {
			return tmp[:got], nil
		}
		return nil, err
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
