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
	_, _, hostPos, hostLen := parseTLSClientHelloSNI(got)
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

func TestMakeTLSFakeWhiteSNI(t *testing.T) {
	orig := buildTLSClientHello("blocked.example")
	fake := makeTLSFake(orig, Primitive{FakeSNI: "www.google.com"})
	if extractTLSServerName(fake) != "www.google.com" {
		t.Fatalf("fake SNI=%q", extractTLSServerName(fake))
	}
}
