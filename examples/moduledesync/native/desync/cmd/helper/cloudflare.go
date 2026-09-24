// SPDX-License-Identifier: MIT
package main

import (
	"net"
	"strings"
	"sync"
)

// Cloudflare published IPv4/IPv6 ranges (https://www.cloudflare.com/ips/).
// На SOCKS-пути tlsrec+OOB даёт RST на CF anycast/ECH — детектим по IP,
// даже когда SNI не содержит «cloudflare» (pages.dev, чужой домен за CF).
var (
	cloudflareNetsOnce sync.Once
	cloudflareNets     []*net.IPNet
)

func cloudflareCIDRs() []*net.IPNet {
	cloudflareNetsOnce.Do(func() {
		cidrs := []string{
			"173.245.48.0/20",
			"103.21.244.0/22",
			"103.22.200.0/22",
			"103.31.4.0/22",
			"141.101.64.0/18",
			"108.162.192.0/18",
			"190.93.240.0/20",
			"188.114.96.0/20",
			"197.234.240.0/22",
			"198.41.128.0/17",
			"162.158.0.0/15",
			"104.16.0.0/13",
			"104.24.0.0/14",
			"172.64.0.0/13",
			"131.0.72.0/22",
			"2400:cb00::/32",
			"2606:4700::/32",
			"2803:f800::/32",
			"2405:b500::/32",
			"2405:8100::/32",
			"2a06:98c0::/29",
			"2c0f:f248::/32",
		}
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			cloudflareNets = append(cloudflareNets, n)
		}
	})
	return cloudflareNets
}

func isCloudflareIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range cloudflareCIDRs() {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isCloudflareHost — SNI/hostname указывает на инфраструктуру CF.
func isCloudflareHost(host string) bool {
	return hostMatch(host, []string{
		"cloudflare.net",
		"cloudflare.com",
		"cloudflarecn.net",
		"cloudflare-ech.com",
		"pages.dev",
		"workers.dev",
		"r2.dev",
		"trycloudflare.com",
		"cfargotunnel.com",
		"cloudflareinsights.com",
		"cloudflarestream.com",
		"cloudflareclient.com",
		"cloudflare-dns.com",
	})
}

func isCloudflareTarget(host, dialIP string) bool {
	if isCloudflareHost(host) {
		return true
	}
	if dialIP != "" && isCloudflareIP(dialIP) {
		return true
	}
	// SOCKS target уже IP (без SNI-матча).
	if isCloudflareIP(host) {
		return true
	}
	return false
}

// isYoutubeImageHost — только превью CDN (ggpht/ytimg).
// googleusercontent.com целиком НЕ матчим: passthrough ломал прочий Google-трафик (YT «хуже»).
func isYoutubeImageHost(host string) bool {
	return hostMatch(host, []string{
		"ggpht.com",
		"ytimg.com",
	})
}

// isGooglevideoHost — video CDN YouTube (rrN---sn-*.googlevideo.com, redirector).
func isGooglevideoHost(host string) bool {
	return hostMatch(host, []string{
		"googlevideo.com",
	})
}
