// SPDX-License-Identifier: MIT

//go:build !unix

package activation

import "errors"

// setCloseOnExec answers that there is nothing to do this to. Socket activation
// is the sd_listen_fds(3) protocol, so the loop that calls this is reachable
// only where systemd passed the descriptors in -- but a build for a platform
// without the call still has to say what it would do, rather than not build.
func setCloseOnExec(int) error {
	return errors.New("socket activation is not available on this platform")
}
