// SPDX-License-Identifier: MIT

// Package activation accepts listening sockets passed in by systemd.
//
// With socket activation, systemd holds the listening sockets and starts
// KeyFence on the first connection to any of them. That means a broker can be
// enabled without running: no process, no memory, and no open ports owned by
// anything but systemd until something actually wants a token swapped. It also
// removes the startup race, because the socket is already accepting before the
// service is asked to exist.
//
// The protocol is the one sd_listen_fds(3) implements. systemd sets LISTEN_PID
// to the pid it started, LISTEN_FDS to how many descriptors it passed, and
// LISTEN_FDNAMES to their names -- FileDescriptorName= in each .socket unit --
// separated by colons. The descriptors themselves start at 3.
//
// This is a dozen lines rather than a dependency because that is all it is.
package activation

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// listenFdsStart is the first file descriptor systemd passes, by convention.
const listenFdsStart = 3

// Listeners returns the sockets systemd passed, keyed by the name the .socket
// unit gave them. It returns an empty map when KeyFence was not started by
// socket activation, which is the ordinary case and not an error.
//
// The environment variables are removed once read, as sd_listen_fds does, so
// that nothing inherited by a child process believes the descriptors are its.
func Listeners() (map[string][]net.Listener, error) {
	defer func() {
		_ = os.Unsetenv("LISTEN_PID")
		_ = os.Unsetenv("LISTEN_FDS")
		_ = os.Unsetenv("LISTEN_FDNAMES")
	}()

	listeners := make(map[string][]net.Listener)

	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		// Not for us. A LISTEN_PID naming another process is how an inherited
		// environment looks, and inheriting someone else's descriptor numbers
		// would mean listening on whatever happens to be open at 3.
		return listeners, nil
	}

	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || count <= 0 {
		return listeners, nil
	}

	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")

	for i := 0; i < count; i++ {
		fd := listenFdsStart + i

		// Keep the descriptors out of any child's hands.
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
			syscall.F_SETFD, syscall.FD_CLOEXEC); errno != 0 {
			return nil, fmt.Errorf("marking activated fd %d close-on-exec: %w", fd, errno)
		}

		name := fmt.Sprintf("fd%d", fd)
		if i < len(names) && names[i] != "" {
			name = names[i]
		}

		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			return nil, fmt.Errorf("activated fd %d is not usable", fd)
		}

		listener, err := net.FileListener(file)
		// FileListener dups the descriptor, so the original is ours to close
		// either way.
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("activated socket %q (fd %d) is not a listening socket: %w",
				name, fd, err)
		}

		listeners[name] = append(listeners[name], listener)
	}

	return listeners, nil
}

// Take removes and returns the first listener stored under name, or nil when
// there is none. Callers use it to ask "did systemd give me this one?" and fall
// back to listening for themselves when the answer is no.
func Take(listeners map[string][]net.Listener, name string) net.Listener {
	found := listeners[name]
	if len(found) == 0 {
		return nil
	}
	listeners[name] = found[1:]
	return found[0]
}
