// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	_ "embed"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed lists/list-general.txt
var listGeneralRaw string

//go:embed lists/list-google.txt
var listGoogleRaw string

//go:embed lists/list-exclude.txt
var listExcludeRaw string

//go:embed lists/builtin-youtube.txt
var builtinYoutubeRaw string

//go:embed lists/builtin-googlevideo.txt
var builtinGooglevideoRaw string

//go:embed lists/builtin-discord.txt
var builtinDiscordRaw string

//go:embed lists/builtin-telegram.txt
var builtinTelegramRaw string

//go:embed lists/builtin-social.txt
var builtinSocialRaw string

//go:embed lists/builtin-cloudflare.txt
var builtinCloudflareRaw string

//go:embed lists/builtin-general.txt
var builtinGeneralRaw string

type hostLists struct {
	general []string
	google  []string
	exclude []string
	// filter — объединённый список для hostsMode whitelist/blacklist
	// (builtin + userDomains + profileDir/user-hosts.txt).
	filter []string
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

var builtinListRaw = map[string]string{
	"youtube":     builtinYoutubeRaw,
	"googlevideo": builtinGooglevideoRaw,
	"discord":     builtinDiscordRaw,
	"telegram":    builtinTelegramRaw,
	"social":      builtinSocialRaw,
	"cloudflare":  builtinCloudflareRaw,
	"general":     builtinGeneralRaw,
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

func parseBuiltinListIDs(csv string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		id := strings.ToLower(strings.TrimSpace(p))
		if id == "" || seen[id] {
			continue
		}
		if _, ok := builtinListRaw[id]; !ok {
			log.Printf("desync: unknown builtin list %q (known: youtube,googlevideo,discord,telegram,social,cloudflare,general)", id)
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// buildFilterHosts — ByeByeDPI-like: активные builtin + SETTING_userDomains + user-hosts.txt.
func buildFilterHosts(builtinCSV, userDomains, profileDir string) []string {
	var parts []string
	for _, id := range parseBuiltinListIDs(builtinCSV) {
		parts = append(parts, parseHostlist(builtinListRaw[id])...)
	}
	parts = append(parts, parseHostlist(userDomains)...)
	if profileDir != "" {
		path := filepath.Join(profileDir, "user-hosts.txt")
		ensureUserHostsFile(path)
		if b, err := os.ReadFile(path); err == nil {
			parts = append(parts, parseHostlist(string(b))...)
		}
	}
	return uniqHosts(parts)
}

func uniqHosts(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func ensureUserHostsFile(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	header := `# user-hosts.txt — свои домены (по одному на строку).
# Работает вместе с настройкой «Свои домены» и режимом Хосты (whitelist/blacklist).
# При hostsMode=all этот файл не фильтрует: desync на весь TLS/HTTP, как ByeByeDPI по умолчанию.
#
# Примеры:
# youtube.com
# discord.com
`
	_ = os.WriteFile(path, []byte(header), 0o644)
}

// hostMatch — Flowseal-style: ^prefix = exact/suffix-anchored;
// иначе substring/suffix match на FQDN.
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

func (hl hostLists) inFilter(host string) bool {
	return hostMatch(host, hl.filter)
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

// matchBucket — корзина Flowseal-правила.
type matchBucket int

const (
	bucketNone matchBucket = iota
	bucketExclude
	bucketGoogle
	bucketDiscord
	bucketGeneral
	bucketAll
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

// hostsModeGate — аналог ByeByeDPI HostsMode.
// all: как Disable — desync на всё подходящее по протоколу.
// whitelist: только host из filter.
// blacklist: всё, кроме filter.
func hostsModeGate(mode, host string, lists hostLists) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if lists.excluded(host) {
		return false
	}
	switch mode {
	case "whitelist":
		return lists.inFilter(host)
	case "blacklist":
		return !lists.inFilter(host)
	default: // all / disable / ""
		return true
	}
}

// readFirstPayload — первый клиентский кусок после SOCKS CONNECT success.
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
