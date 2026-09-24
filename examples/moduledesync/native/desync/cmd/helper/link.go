// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"net/url"
	"strings"
)

// desyncLink — разобранная ссылка desync://.
//
// Формы:
//
//	desync://general
//	desync://alt#MyName
//	desync://auto?auto=1
//	desync://passthrough
type desyncLink struct {
	Preset   string // general|alt|alt2|youtube|discord|safe|auto|passthrough
	Name     string // fragment
	Auto     bool   // ?auto=1 или preset=auto
	Explicit bool   // путь ссылки непустой (не дефолт general «от пустоты»)
	Raw      string
}

func parseDesyncLink(raw string) (desyncLink, bool) {
	t := strings.TrimSpace(raw)
	out := desyncLink{Raw: t, Preset: "general"}
	if !strings.HasPrefix(strings.ToLower(t), "desync://") {
		return out, false
	}
	rest := t[len("desync://"):]
	frag := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		frag = strings.TrimSpace(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	path := strings.Trim(strings.TrimSpace(rest), "/")
	if path != "" {
		out.Preset = strings.ToLower(path)
		out.Explicit = true
	}
	out.Name = frag
	if query != "" {
		q, err := url.ParseQuery(query)
		if err == nil {
			if v := strings.TrimSpace(q.Get("auto")); v == "1" || strings.EqualFold(v, "true") {
				out.Auto = true
			}
			if p := strings.TrimSpace(q.Get("preset")); p != "" {
				out.Preset = strings.ToLower(p)
				out.Explicit = true
			}
		}
	}
	if out.Preset == "auto" {
		out.Auto = true
	}
	if !knownPreset(out.Preset) {
		out.Preset = "general"
		out.Explicit = false
	}
	return out, true
}

func summarizeDesync(link string) (name, server string) {
	dl, ok := parseDesyncLink(link)
	if !ok {
		return "", ""
	}
	name = dl.Name
	if name == "" {
		name = dl.Preset
	}
	server = dl.Preset
	if dl.Auto && dl.Preset != "auto" {
		server = dl.Preset + "+auto"
	}
	return name, server
}

// normalizeDesync — bare desync:preset / JSON {"desync":…,"name":…} → канон desync://.
// Уже desync:// / пусто / чужой формат → "".
func normalizeDesync(raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" || strings.HasPrefix(strings.ToLower(t), "desync://") {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(t), "desync:") {
		label := strings.TrimSpace(t[len("desync:"):])
		if label == "" {
			return ""
		}
		return "desync://" + label
	}
	if strings.HasPrefix(t, "{") {
		var m map[string]interface{}
		if json.Unmarshal([]byte(t), &m) != nil {
			return ""
		}
		label, _ := m["desync"].(string)
		label = strings.TrimSpace(label)
		if label == "" {
			return ""
		}
		name, _ := m["name"].(string)
		name = strings.TrimSpace(name)
		if name != "" {
			return "desync://" + label + "#" + name
		}
		return "desync://" + label
	}
	return ""
}
