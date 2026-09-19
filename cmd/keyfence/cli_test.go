// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStandardHelpFormsUseStdout(t *testing.T) {
	for _, form := range []string{"-h", "--help", "help"} {
		t.Run(form, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			handled, status := handleInformationalCommand([]string{form}, &stdout, &stderr)
			if !handled || status != 0 {
				t.Fatalf("handled = %t, status = %d", handled, status)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			for _, want := range []string{
				"Usage:", "Commands:", "Network options:", "--proxy ADDRESS",
				"Examples:", programAuthor, programCopyright, "License: " + programLicense,
			} {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("help does not contain %q", want)
				}
			}
		})
	}
}

func TestStandardVersionFormsUseStdout(t *testing.T) {
	for _, form := range []string{"-V", "--version", "version"} {
		t.Run(form, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			handled, status := handleInformationalCommand([]string{form}, &stdout, &stderr)
			if !handled || status != 0 {
				t.Fatalf("handled = %t, status = %d", handled, status)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			for _, want := range []string{
				programName + " ", "commit:", "revision date:", "built:",
				"go:", "author: " + programAuthor, programCopyright, "license: " + programLicense,
			} {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("version output does not contain %q", want)
				}
			}
		})
	}
}

func TestHelpTopicsAndUsageErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		status int
		want   string
	}{
		{"credential", []string{"help", "credential"}, 0, "keyfence credential <command>"},
		{"credential add", []string{"help", "credential", "add"}, 0, "keyfence credential add"},
		{"unknown", []string{"help", "wat"}, 2, `unknown topic "wat"`},
		{"extra version argument", []string{"--version", "wat"}, 2, "does not take arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			handled, status := handleInformationalCommand(test.args, &stdout, &stderr)
			if !handled || status != test.status {
				t.Fatalf("handled = %t, status = %d", handled, status)
			}
			output := stdout.String() + stderr.String()
			if !strings.Contains(output, test.want) {
				t.Fatalf("output %q does not contain %q", output, test.want)
			}
			if test.status == 0 && stderr.Len() != 0 {
				t.Fatalf("successful help wrote stderr: %q", stderr.String())
			}
			if test.status != 0 && stdout.Len() != 0 {
				t.Fatalf("usage error wrote stdout: %q", stdout.String())
			}
		})
	}
}

func TestNoArgumentsContinueToTheBroker(t *testing.T) {
	handled, status := handleInformationalCommand(nil, &bytes.Buffer{}, &bytes.Buffer{})
	if handled || status != 0 {
		t.Fatalf("handled = %t, status = %d", handled, status)
	}
}

func TestCredentialHelpFormsAndUsageErrors(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		status int
		want   string
	}{
		{"help flag", []string{"credential", "--help"}, 0, "keyfence credential <command>"},
		{"help command", []string{"credential", "help"}, 0, "keyfence credential <command>"},
		{"add help", []string{"credential", "add", "-h"}, 0, "credential add [--file PATH] NAME"},
		{"nested help", []string{"credential", "help", "list"}, 0, "credential list [options]"},
		{"missing command", []string{"credential"}, 2, "keyfence credential <command>"},
		{"unknown command", []string{"credential", "wat"}, 2, `unknown command "wat"`},
		{"irrelevant option", []string{"credential", "list", "--file", "secret"}, 2, "flag provided but not defined"},
		{"extra list argument", []string{"credential", "list", "wat"}, 2, "does not take arguments"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			handled, status := runCredentialCommandWithIO(test.args, &stdout, &stderr)
			if !handled || status != test.status {
				t.Fatalf("handled = %t, status = %d", handled, status)
			}
			output := stdout.String() + stderr.String()
			if !strings.Contains(output, test.want) {
				t.Fatalf("output %q does not contain %q", output, test.want)
			}
			if test.status == 0 && stderr.Len() != 0 {
				t.Fatalf("successful help wrote stderr: %q", stderr.String())
			}
			if test.status != 0 && stdout.Len() != 0 {
				t.Fatalf("usage error wrote stdout: %q", stdout.String())
			}
		})
	}
}
