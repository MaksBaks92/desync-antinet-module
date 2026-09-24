// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"testing"
)

func TestRewriteTLSClientHelloSNI(t *testing.T) {
	orig := buildTLSClientHello("nmclub.to")
	got := rewriteTLSClientHelloSNI(orig, "www.google.com")
	if len(got) == 0 {
		t.Fatal("rewrite returned empty")
	}
	name := extractTLSServerName(got)
	if name != "www.google.com" {
		t.Fatalf("SNI=%q want www.google.com", name)
	}
	// session id len byte preserved (dupsid) — offset 43
	if orig[43] != got[43] {
		t.Fatalf("session id len changed: %d → %d", orig[43], got[43])
	}
	// lengths consistent with parser
	_, _, hostPos, hostLen, _ := parseTLSClientHelloSNI(got)
	if hostPos < 0 || hostLen != len("www.google.com") {
		t.Fatalf("parse after rewrite hostPos=%d hostLen=%d", hostPos, hostLen)
	}
	if !bytes.Equal(got[hostPos:hostPos+hostLen], []byte("www.google.com")) {
		t.Fatalf("hostname bytes mismatch")
	}
	// same-length rewrite
	same := rewriteTLSClientHelloSNI(buildTLSClientHello("example.com"), "ooooooo.com")
	if extractTLSServerName(same) != "ooooooo.com" {
		t.Fatalf("same-len SNI=%q", extractTLSServerName(same))
	}
}

// TestRewriteSNINotFirstExtension — Chrome/ECH: SNI не первое расширение.
// Старый totOff=sniExt-2 давал garbage → nil → size=77 в логах.
func TestRewriteSNINotFirstExtension(t *testing.T) {
	orig := buildTLSClientHelloSNINotFirst("nnmclub.to")
	_, sniExt, _, _, extTot := parseTLSClientHelloSNI(orig)
	if sniExt < 0 || extTot < 0 {
		t.Fatal("parse failed")
	}
	if sniExt == extTot+2 {
		t.Fatal("SNI unexpectedly first extension — test fixture broken")
	}
	got := rewriteTLSClientHelloSNI(orig, "www.google.com")
	if len(got) == 0 {
		t.Fatal("rewrite returned empty (extTotOff bug?)")
	}
	if extractTLSServerName(got) != "www.google.com" {
		t.Fatalf("SNI=%q", extractTLSServerName(got))
	}
	// size must stay near orig (not collapse to ~77B minimal hello)
	if len(got) < len(orig)-20 {
		t.Fatalf("rewritten too small: orig=%d got=%d", len(orig), len(got))
	}
}

func TestMakeTLSFakeWhiteSNI(t *testing.T) {
	orig := padTLSClientHello(buildTLSClientHelloSNINotFirst("blocked.example"), 500)
	fake := makeTLSFake(orig, Primitive{FakeSNI: "www.google.com", FakeSize: 1200})
	if extractTLSServerName(fake) != "www.google.com" {
		t.Fatalf("fake SNI=%q", extractTLSServerName(fake))
	}
	if len(fake) < 1000 {
		t.Fatalf("fake too small size=%d (want pad to FakeSize≥1200 after rewrite)", len(fake))
	}
	// rewrite miss → fallback must still pad (1.2.8 bug: size≈77)
	tiny := makeTLSFake([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}, Primitive{FakeSNI: "www.google.com", FakeSize: 1200})
	if extractTLSServerName(tiny) != "www.google.com" {
		t.Fatalf("fallback SNI=%q", extractTLSServerName(tiny))
	}
	if len(tiny) < 1000 {
		t.Fatalf("fallback too small size=%d", len(tiny))
	}
}

// buildTLSClientHelloSNINotFirst — ClientHello с dummy-расширением перед SNI.
func buildTLSClientHelloSNINotFirst(serverName string) []byte {
	base := buildTLSClientHello(serverName)
	_, sniExt, _, _, extTot := parseTLSClientHelloSNI(base)
	if sniExt < 0 || extTot < 0 {
		return base
	}
	dummy := []byte{0x00, 0x17, 0x00, 0x00} // extended_master_secret, empty
	out := make([]byte, 0, len(base)+len(dummy))
	out = append(out, base[:sniExt]...)
	out = append(out, dummy...)
	out = append(out, base[sniExt:]...)
	delta := len(dummy)
	tot := int(out[extTot])<<8 | int(out[extTot+1])
	tot += delta
	out[extTot] = byte(tot >> 8)
	out[extTot+1] = byte(tot)
	hs := int(out[6])<<16 | int(out[7])<<8 | int(out[8])
	hs += delta
	out[6] = byte(hs >> 16)
	out[7] = byte(hs >> 8)
	out[8] = byte(hs)
	rec := int(out[3])<<8 | int(out[4])
	rec += delta
	out[3] = byte(rec >> 8)
	out[4] = byte(rec)
	return out
}
