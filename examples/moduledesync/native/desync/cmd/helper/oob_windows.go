// SPDX-License-Identifier: MIT
//go:build windows

package main

import (
	"fmt"
	"net"
)

// sendTCPOOB — на Windows urgent/OOB в SOCKS-пути ненадёжен; вызывающий откатывается к split.
func sendTCPOOB(c net.Conn, b byte) error {
	_ = c
	_ = b
	return fmt.Errorf("TCP OOB unsupported on windows helper; use split/fake")
}
