// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Anthony Green <green@moxielogic.com>

package main

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

const (
	programName      = "keyfence"
	programAuthor    = "Anthony Green <green@moxielogic.com>"
	programCopyright = "Copyright (c) 2026 Anthony Green"
	programLicense   = "MIT"
)

// Set by release builds with -ldflags. Go's embedded VCS information supplies
// the revision and source date for ordinary builds from a repository.
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

func handleInformationalCommand(args []string, stdout, stderr io.Writer) (handled bool, status int) {
	if len(args) == 0 {
		return false, 0
	}

	switch args[0] {
	case "-h", "--help":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "%s: help does not take arguments\n\n", programName)
			rootUsage(stderr)
			return true, 2
		}
		rootUsage(stdout)
		return true, 0

	case "-V", "--version", "version":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "%s: version does not take arguments\n", programName)
			return true, 2
		}
		printVersion(stdout)
		return true, 0

	case "help":
		switch {
		case len(args) == 1:
			rootUsage(stdout)
			return true, 0
		case args[1] == "credential" && len(args) == 2:
			credentialUsage(stdout)
			return true, 0
		case args[1] == "credential" && len(args) == 3 && isCredentialCommand(args[2]):
			credentialCommandUsage(stdout, args[2])
			return true, 0
		default:
			fmt.Fprintf(stderr, "%s help: unknown topic %q\n\n", programName, strings.Join(args[1:], " "))
			rootUsage(stderr)
			return true, 2
		}
	}

	return false, 0
}

func rootUsage(w io.Writer) {
	fmt.Fprintf(w, `KeyFence securely swaps short-lived tokens for credentials used by AI agents.

Usage:
  keyfence [options]
  keyfence credential <command> [options]
  keyfence version

Commands:
  credential   Add, list, or remove named credentials
  version      Show version and build information
  help         Show this help, or help for a command

Network options:
  --proxy ADDRESS              HTTPS proxy address (default 127.0.0.1:10210)
  --ssh ADDRESS                SSH bastion address (default 127.0.0.1:10211)
  --api ADDRESS                Control API address (default 127.0.0.1:10212)
  --passthrough HOSTS          Comma-separated hosts allowed without a token
  --no-reuse-connections       Close each tunnel after one request

Credential and TLS options:
  --credentials-dir DIR        Directory of named credentials
  --keyring                    Also resolve credentials from the OS keyring
  --data-dir DIR               Data directory (default %s)
  --certs-dir DIR              Export the public CA certificate to DIR
  --ssh-known-hosts FILE       File used to authenticate upstream SSH hosts
  --ssh-insecure-host-keys     Accept any upstream SSH host key (unsafe)

Control API options:
  --api-key-file FILE          Read the control API bearer key from FILE
  --api-key KEY                Bearer key in argv (prefer --api-key-file)
  --insecure-api               Run the TCP control API without a key (unsafe)
  --api-allow-uid UID          Allow a Unix-socket peer UID (repeatable)
  --api-allow-group GID        Allow a Unix-socket primary GID (repeatable)

General options:
  -h, --help                   Show help
  -V, --version                Show version and build information

Examples:
  keyfence --api-key-file ~/.keyfence/api-key
  keyfence --api unix:$XDG_RUNTIME_DIR/keyfence-control.sock \
    --api-allow-uid "$(id -u)"
  gh auth token | keyfence credential add github

Author: %s
%s
License: %s
Project: https://github.com/atgreen/keyfence
`, defaultDataDir(), programAuthor, programCopyright, programLicense)
}

func printVersion(w io.Writer) {
	release, revision, revisionDate, dirty := resolvedBuildInfo()
	if dirty && revision != "unknown" {
		revision += " (modified)"
	}
	fmt.Fprintf(w, `%s %s
commit: %s
revision date: %s
built: %s
go: %s %s/%s
author: %s
%s
license: %s
`, programName, release, revision, revisionDate, valueOrUnknown(buildDate),
		runtime.Version(), runtime.GOOS, runtime.GOARCH, programAuthor,
		programCopyright, programLicense)
}

func resolvedBuildInfo() (release, revision, revisionDate string, dirty bool) {
	release = version
	revision = commit

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return valueOrDev(release), valueOrUnknown(revision), "unknown", false
	}
	if (release == "" || release == "dev") && info.Main.Version != "" && info.Main.Version != "(devel)" {
		release = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if revision == "" {
				revision = setting.Value
			}
		case "vcs.time":
			revisionDate = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return valueOrDev(release), valueOrUnknown(revision), valueOrUnknown(revisionDate), dirty
}

func valueOrDev(value string) string {
	if value == "" {
		return "dev"
	}
	return value
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
