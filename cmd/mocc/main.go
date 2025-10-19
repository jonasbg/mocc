package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"

	"mocc/internal/config"
	"mocc/internal/oidc"
	"mocc/internal/server"
)

type options struct {
	usersPath     string
	host          string
	port          string
	usersFromEnv  bool
	usersFromFlag bool
}

func main() {
	opts := parseOptions()

	users, err := config.LoadUsers(opts.usersPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !opts.usersFromEnv && !opts.usersFromFlag && config.HasEmbeddedUsers() {
			users, err = config.LoadEmbeddedUsers()
			if err != nil {
				log.Fatalf("failed to load embedded users: %v", err)
			}
		} else {
			log.Fatalf("failed to load users (%s): %v", opts.usersPath, err)
		}
	}

	keys := oidc.GenerateKeySet()
	s := server.New(users, keys)

	addr := net.JoinHostPort(opts.host, opts.port)
	s.Engine.SetTrustedProxies(nil)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}

	printBanner(opts.host, opts.port)
	log.Fatal(s.Engine.RunListener(ln))
}

func parseOptions() options {
	const (
		defaultUsersPath = "users.yaml"
		defaultHost      = "0.0.0.0"
		defaultPort      = "9999"
	)

	opts := options{
		usersPath: defaultUsersPath,
		host:      defaultHost,
		port:      defaultPort,
	}

	if val := firstNonEmpty(os.Getenv("MOCC_USERS"), os.Getenv("USERS")); val != "" {
		opts.usersPath = val
		opts.usersFromEnv = true
	}
	if val := firstNonEmpty(os.Getenv("MOCC_HOST"), os.Getenv("HOST")); val != "" {
		opts.host = val
	}
	if val := firstNonEmpty(os.Getenv("MOCC_PORT"), os.Getenv("PORT")); val != "" {
		opts.port = val
	}

	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.Usage = func() {
		out := flagSet.Output()
		fmt.Fprintf(out, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintln(out, "mocc is a mock OIDC provider useful for local development.")
		fmt.Fprintln(out, "Configuration precedence: flags > environment variables > defaults.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Environment variables:")
		fmt.Fprintln(out, "  MOCC_USERS, USERS — path to users YAML (default: users.yaml)")
		fmt.Fprintln(out, "  MOCC_HOST, HOST   — address to bind (default: 0.0.0.0)")
		fmt.Fprintln(out, "  MOCC_PORT, PORT   — port to bind (default: 9999)")
		fmt.Fprintln(out)
		flagSet.PrintDefaults()
	}

	flagSet.StringVar(&opts.usersPath, "users", opts.usersPath, "Path to the users YAML file")
	flagSet.StringVar(&opts.host, "host", opts.host, "Host/IP address to bind to")
	flagSet.StringVar(&opts.port, "port", opts.port, "Port to listen on")

	_ = flagSet.Parse(os.Args[1:])

	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == "users" {
			opts.usersFromFlag = true
		}
	})

	return opts
}

func firstNonEmpty(values ...string) string {
	for _, val := range values {
		if val != "" {
			return val
		}
	}
	return ""
}

func printBanner(host, port string) {
	const banner = `
┌──────────────────────────────────────────────┐
│                                              │
│    ███╗   ███╗ ██████╗  ██████╗  ██████╗     │
│    ████╗ ████║██╔═══██╗██╔═══██╗██╔═══██╗    │
│    ██╔████╔██║██║   ██║██║      ██║          │
│    ██║╚██╔╝██║██║   ██║██║   ██║██║   ██║    │
│    ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝╚██████╔╝    │
│    ╚═╝     ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝     │
│                                              │
│    MOCC — Minimal OpenID Connect Core        │
│    https://github.com/jonasbg/mocc           │
│                                              │
└──────────────────────────────────────────────┘


`
	displayHost := host
	if displayHost == "" || displayHost == "0.0.0.0" || displayHost == "::" {
		displayHost = "localhost"
	}
	fmt.Print(banner)
	fmt.Printf("MOCC ready at http://%s:%s — happy moccing!\n", displayHost, port)
	fmt.Println()
	fmt.Println("Quick tips:")
	fmt.Println("  • --users <path>    override the bundled users list (env: MOCC_USERS / USERS)")
	fmt.Println("  • --host <address>  change bind address (env: MOCC_HOST / HOST)")
	fmt.Println("  • --port <port>     pick a different port (env: MOCC_PORT / PORT)")
	fmt.Println("  • Flags win over env vars; env vars win over built-in defaults.")
	fmt.Println()
	fmt.Println("Docs & updates: https://github.com/jonasbg/mocc")
	fmt.Println()
}
