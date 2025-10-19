package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestParseOptionsDefaults(t *testing.T) {
	t.Setenv("TINYGOIDC_USERS", "")
	t.Setenv("USERS", "")
	t.Setenv("TINYGOIDC_HOST", "")
	t.Setenv("HOST", "")
	t.Setenv("TINYGOIDC_PORT", "")
	t.Setenv("PORT", "")

	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"tinygoidc"}

	opts := parseOptions()
	if opts.usersPath != "users.yaml" {
		t.Fatalf("expected default users path, got %q", opts.usersPath)
	}
	if opts.host != "0.0.0.0" {
		t.Fatalf("expected default host, got %q", opts.host)
	}
	if opts.port != "9999" {
		t.Fatalf("expected default port, got %q", opts.port)
	}
	if opts.usersFromEnv {
		t.Fatalf("usersFromEnv should be false when no env is set")
	}
	if opts.usersFromFlag {
		t.Fatalf("usersFromFlag should be false when no flag is set")
	}
}

func TestParseOptionsEnvAndFlags(t *testing.T) {
	t.Setenv("TINYGOIDC_USERS", "/env/users.yaml")
	t.Setenv("TINYGOIDC_HOST", "127.0.0.1")
	t.Setenv("TINYGOIDC_PORT", "7777")

	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = []string{"tinygoidc"}

	opts := parseOptions()
	if opts.usersPath != "/env/users.yaml" || !opts.usersFromEnv {
		t.Fatalf("expected env users, got %+v", opts)
	}
	if opts.host != "127.0.0.1" {
		t.Fatalf("expected env host, got %q", opts.host)
	}
	if opts.port != "7777" {
		t.Fatalf("expected env port, got %q", opts.port)
	}

	os.Args = []string{"tinygoidc", "--users", "/flag/users.yaml", "--host", "192.0.2.10", "--port", "8888"}
	opts = parseOptions()
	if opts.usersPath != "/flag/users.yaml" || !opts.usersFromFlag {
		t.Fatalf("expected flag users override, got %+v", opts)
	}
	if opts.host != "192.0.2.10" {
		t.Fatalf("expected flag host override, got %q", opts.host)
	}
	if opts.port != "8888" {
		t.Fatalf("expected flag port override, got %q", opts.port)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	result := firstNonEmpty("", "", "value", "other")
	if result != "value" {
		t.Fatalf("expected first non empty to be %q, got %q", "value", result)
	}
	if res := firstNonEmpty("", ""); res != "" {
		t.Fatalf("expected empty result, got %q", res)
	}
}

func TestPrintBanner(t *testing.T) {
	origStdout := os.Stdout
	defer func() { os.Stdout = origStdout }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	printBanner("0.0.0.0", "4242")

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy: %v", err)
	}
	r.Close()

	output := buf.String()
	if !strings.Contains(output, "ready at http://localhost:4242") {
		t.Fatalf("expected friendly message, got %q", output)
	}
	if !strings.Contains(output, "--users <path>") {
		t.Fatalf("expected tips section, got %q", output)
	}
	if !strings.Contains(output, "https://github.com/jonasbg/") {
		t.Fatalf("expected repo link, got %q", output)
	}
}
