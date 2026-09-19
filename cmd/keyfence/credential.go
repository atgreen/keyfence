// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The credential subcommands exist because setting one up used to mean knowing
// things nobody should have to know: that the keyring attributes are
// "service keyfence credential <name>", that a file under the credentials
// directory has to be mode 0600 without a trailing newline, and -- worst -- that
// the only way to see what was registered was to ask for a name that did not
// exist and read the list of alternatives out of the error.
//
//	keyfence credential add github      # secret on stdin
//	keyfence credential list
//	keyfence credential rm github
//
// Nothing here ever prints a secret.

func credentialUsage(w io.Writer) {
	fmt.Fprint(w, `Manage credentials by name without exposing their values.

Usage:
  keyfence credential <command> [options]

Commands:
  add NAME        Store the secret read from stdin
  list            List registered credential names
  rm NAME         Forget a credential

General options:
  -h, --help      Show help

Run "keyfence help credential <command>" for command-specific help.

A credential is referenced by name in a token request or sandbox policy:

  {"credential_ref": "github", "destinations": ["api.github.com"]}
`)
}

func credentialCommandUsage(w io.Writer, command string) {
	switch command {
	case "add":
		fmt.Fprint(w, `Store a named credential, reading the secret from stdin.

Usage:
  keyfence credential add [--file PATH] NAME

Options:
  --file PATH      Write to PATH instead of the OS keyring
  -h, --help       Show help

Example:
  gh auth token | keyfence credential add github
`)
	case "list":
		fmt.Fprint(w, `List the credential names registered with a running broker.

Usage:
  keyfence credential list [options]

Options:
  --api ADDRESS        Control API address (default 127.0.0.1:10212)
  --api-key-file FILE  Control API key file (default ~/.keyfence/api-key)
  -h, --help           Show help
`)
	case "rm":
		fmt.Fprint(w, `Forget a named credential.

Usage:
  keyfence credential rm [--file PATH] NAME

Options:
  --file PATH      Remove PATH instead of an OS keyring entry
  -h, --help       Show help
`)
	}
}

func isCredentialCommand(command string) bool {
	return command == "add" || command == "list" || command == "rm"
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

// runCredentialCommand handles "keyfence credential ..." and answers whether it
// did, so that main can carry on starting servers when it did not.
func runCredentialCommand(args []string) (handled bool, status int) {
	return runCredentialCommandWithIO(args, os.Stdout, os.Stderr)
}

func runCredentialCommandWithIO(args []string, stdout, stderr io.Writer) (handled bool, status int) {
	if len(args) == 0 || args[0] != "credential" {
		return false, 0
	}
	if len(args) == 1 {
		credentialUsage(stderr)
		return true, 2
	}
	if args[1] == "help" || args[1] == "-h" || args[1] == "--help" {
		if len(args) == 2 {
			credentialUsage(stdout)
			return true, 0
		}
		if len(args) == 3 && isCredentialCommand(args[2]) {
			credentialCommandUsage(stdout, args[2])
			return true, 0
		}
		fmt.Fprintf(stderr, "keyfence credential help: unknown command %q\n\n", strings.Join(args[2:], " "))
		credentialUsage(stderr)
		return true, 2
	}

	command := args[1]
	if !isCredentialCommand(command) {
		fmt.Fprintf(stderr, "keyfence credential: unknown command %q\n\n", command)
		credentialUsage(stderr)
		return true, 2
	}
	if hasHelpFlag(args[2:]) {
		credentialCommandUsage(stdout, command)
		return true, 0
	}

	set := flag.NewFlagSet("credential", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var file string
	var apiAddr string
	var apiKeyFile string
	switch command {
	case "add", "rm":
		set.StringVar(&file, "file", "", "")
	case "list":
		set.StringVar(&apiAddr, "api", "127.0.0.1:10212", "")
		set.StringVar(&apiKeyFile, "api-key-file", defaultAPIKeyFile(), "")
	}

	rest := args[2:]
	if err := set.Parse(rest); err != nil {
		fmt.Fprintf(stderr, "keyfence credential %s: %v\n\n", command, err)
		credentialCommandUsage(stderr, command)
		return true, 2
	}
	positional := set.Args()

	switch command {
	case "add":
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "keyfence credential add: expected exactly one NAME")
			fmt.Fprintln(stderr)
			credentialCommandUsage(stderr, command)
			return true, 2
		}
		if err := credentialAdd(positional[0], file); err != nil {
			fmt.Fprintf(stderr, "keyfence credential add: %v\n", err)
			return true, 1
		}
		return true, 0

	case "list":
		if len(positional) != 0 {
			fmt.Fprintln(stderr, "keyfence credential list: does not take arguments")
			fmt.Fprintln(stderr)
			credentialCommandUsage(stderr, command)
			return true, 2
		}
		if err := credentialList(apiAddr, apiKeyFile); err != nil {
			fmt.Fprintf(stderr, "keyfence credential list: %v\n", err)
			return true, 1
		}
		return true, 0

	case "rm":
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "keyfence credential rm: expected exactly one NAME")
			fmt.Fprintln(stderr)
			credentialCommandUsage(stderr, command)
			return true, 2
		}
		if err := credentialRemove(positional[0], file); err != nil {
			fmt.Fprintf(stderr, "keyfence credential rm: %v\n", err)
			return true, 1
		}
		return true, 0
	}
	return true, 2
}

func defaultAPIKeyFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".keyfence", "api-key")
}

// readSecretFromStdin takes the whole of stdin as the secret, less the newline a
// shell or an editor leaves on the end.
func readSecretFromStdin() (string, error) {
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "reading the secret from stdin; end it with ^D")
	}
	contents, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return "", err
	}
	secret := strings.TrimRight(string(contents), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("nothing on stdin; pipe the secret in, for example: gh auth token | keyfence credential add github")
	}
	return secret, nil
}

func credentialAdd(name, file string) error {
	secret, err := readSecretFromStdin()
	if err != nil {
		return err
	}

	if file != "" {
		// 0600, and no trailing newline, which is what the resolver expects.
		if err := writeCredentialFile(file, secret); err != nil {
			return err
		}
		fmt.Printf("stored %s in %s (plaintext on disk; the keyring keeps it encrypted)\n", name, file)
		return nil
	}

	tool, err := exec.LookPath("secret-tool")
	if err != nil {
		return fmt.Errorf("no keyring available (secret-tool is not installed): " +
			"pass --file PATH to store it in a file instead")
	}
	store := exec.Command(tool, "store", "--label", "keyfence: "+name,
		"service", "keyfence", "credential", name)
	store.Stdin = strings.NewReader(secret)
	store.Stderr = os.Stderr
	if err := store.Run(); err != nil {
		return fmt.Errorf("storing in the keyring: %w", err)
	}
	fmt.Printf("stored %s in the keyring; reference it as {\"credential_ref\": %q}\n", name, name)
	return nil
}

func credentialList(apiAddr, apiKeyFile string) error {
	request, err := http.NewRequest("GET", "http://"+apiAddr+"/credentials", nil)
	if err != nil {
		return err
	}
	if apiKeyFile != "" {
		if key, err := os.ReadFile(apiKeyFile); err == nil {
			request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(key)))
		}
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("asking the broker on %s: %w (is it running?)", apiAddr, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("the broker refused the control key from %s", apiKeyFile)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the broker answered %d", response.StatusCode)
	}

	var answer struct {
		Credentials []string `json:"credentials"`
		Sources     []string `json:"sources"`
		Keyring     bool     `json:"keyring"`
	}
	if err := json.NewDecoder(response.Body).Decode(&answer); err != nil {
		return err
	}

	if len(answer.Credentials) == 0 {
		fmt.Println("no credentials registered")
	}
	for _, name := range answer.Credentials {
		fmt.Println(name)
	}
	where := append([]string(nil), answer.Sources...)
	if answer.Keyring {
		where = append(where, "the OS keyring")
	}
	if len(where) > 0 {
		fmt.Fprintf(os.Stderr, "\nfrom: %s\n", strings.Join(where, ", "))
	}
	return nil
}

// writeCredentialFile replaces path atomically with a freshly created file.
// os.WriteFile's mode applies only when it creates a file, so using it directly
// could leave a replaced credential with the old file's permissive mode. The
// rename also avoids following a symlink at path and exposing the secret in its
// target.
func writeCredentialFile(path, secret string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(dir, ".keyfence-credential-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, secret); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func credentialRemove(name, file string) error {
	if file != "" {
		if err := os.Remove(file); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", file)
		return nil
	}
	tool, err := exec.LookPath("secret-tool")
	if err != nil {
		return fmt.Errorf("no keyring available (secret-tool is not installed)")
	}
	clear := exec.Command(tool, "clear", "service", "keyfence", "credential", name)
	clear.Stderr = os.Stderr
	if err := clear.Run(); err != nil {
		return fmt.Errorf("clearing the keyring entry: %w", err)
	}
	fmt.Printf("forgot %s\n", name)
	return nil
}
