// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCredentialFileReplacesPermissiveFileSecurely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("old secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeCredentialFile(path, "new secret"); err != nil {
		t.Fatalf("writing credential: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new secret" {
		t.Fatalf("contents = %q; want %q", contents, "new secret")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("permissions = %04o; want 0600", permissions)
	}
}

func TestWriteCredentialFileDoesNotFollowDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if err := writeCredentialFile(path, "secret"); err != nil {
		t.Fatalf("writing credential: %v", err)
	}

	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "do not replace" {
		t.Fatalf("symlink target contents = %q; want unchanged target", contents)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("replacement mode = %v; want regular file", info.Mode())
	}
}

func TestWriteCredentialFileCleansTemporaryFileAfterRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := writeCredentialFile(path, "secret"); err == nil {
		t.Fatal("writing over a directory succeeded")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "credential" {
		t.Fatalf("directory entries after failure = %v; want only credential", entries)
	}
}
