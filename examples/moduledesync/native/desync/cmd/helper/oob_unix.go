// SPDX-License-Identifier: MIT
//go:build unix

package main

import (
	"fmt"
	"net"
	"syscall"
)

// sendTCPOOB — TCP urgent (MSG_OOB), аналог byeDPI -e / -o.
func sendTCPOOB(c net.Conn, b byte) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return fmt.Errorf("conn does not support SyscallConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		_, sendErr = syscall.SendmsgN(int(fd), []byte{b}, nil, nil, syscall.MSG_OOB)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sendErr
}
