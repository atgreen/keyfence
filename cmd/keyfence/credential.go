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

func credentialUsage() {
	fmt.Fprint(os.Stderr, `usage: keyfence credential <command>

  add NAME        store the secret read from stdin, in the OS keyring
  list            what is registered, by name
  rm NAME         forget one

  --file PATH     with add: write to this file instead of the keyring
  --api ADDRESS   with list: the control API to ask (default 127.0.0.1:10212)
  --api-key-file  with list: where the control API key is
                  (default ~/.keyfence/api-key)

A credential is referenced by name, in a token request or in a sandbox policy:

  {"credential_ref": "github", "destinations": ["api.github.com"]}
`)
}

// runCredentialCommand handles "keyfence credential ..." and answers whether it
// did, so that main can carry on starting servers when it did not.
func runCredentialCommand(args []string) (handled bool, status int) {
	if len(args) == 0 || args[0] != "credential" {
		return false, 0
	}
	if len(args) == 1 {
		credentialUsage()
		return true, 2
	}

	set := flag.NewFlagSet("credential", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	file := set.String("file", "", "")
	apiAddr := set.String("api", "127.0.0.1:10212", "")
	apiKeyFile := set.String("api-key-file", defaultAPIKeyFile(), "")

	command := args[1]
	rest := args[2:]
	if err := set.Parse(rest); err != nil {
		fmt.Fprintf(os.Stderr, "keyfence credential: %v\n", err)
		credentialUsage()
		return true, 2
	}
	positional := set.Args()

	switch command {
	case "add":
		if len(positional) != 1 {
			fmt.Fprintln(os.Stderr, "keyfence credential add NAME  (the secret is read from stdin)")
			return true, 2
		}
		if err := credentialAdd(positional[0], *file); err != nil {
			fmt.Fprintf(os.Stderr, "keyfence credential add: %v\n", err)
			return true, 1
		}
		return true, 0

	case "list":
		if err := credentialList(*apiAddr, *apiKeyFile); err != nil {
			fmt.Fprintf(os.Stderr, "keyfence credential list: %v\n", err)
			return true, 1
		}
		return true, 0

	case "rm":
		if len(positional) != 1 {
			fmt.Fprintln(os.Stderr, "keyfence credential rm NAME")
			return true, 2
		}
		if err := credentialRemove(positional[0], *file); err != nil {
			fmt.Fprintf(os.Stderr, "keyfence credential rm: %v\n", err)
			return true, 1
		}
		return true, 0

	default:
		credentialUsage()
		return true, 2
	}
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
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
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
