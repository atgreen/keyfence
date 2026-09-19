// SPDX-License-Identifier: MIT

//go:build unix

package activation

import "syscall"

// setCloseOnExec keeps an activated descriptor out of any child's hands.
func setCloseOnExec(fd int) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		syscall.F_SETFD, syscall.FD_CLOEXEC); errno != 0 {
		return errno
	}
	return nil
}
