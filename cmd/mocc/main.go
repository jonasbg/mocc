package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"mocc/internal/moccconfig"
	"mocc/internal/oidc"
	"mocc/internal/server"
)

var version = "dev"

type options struct {
	usersPath     string
	host          string
	port          string
	usersFromEnv  bool
	usersFromFlag bool
	showVersion   bool
}

func main() {
	opts := parseOptions()

	if opts.showVersion {
		fmt.Println(version)
		return
	}

	config, err := moccconfig.LoadConfig(opts.usersPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !opts.usersFromEnv && !opts.usersFromFlag && moccconfig.HasEmbeddedUsers() {
			config, err = moccconfig.LoadEmbeddedUsers()
			if err != nil {
				log.Fatalf("failed to load embedded users: %v", err)
			}
		} else {
			log.Fatalf("failed to load users (%s): %v", opts.usersPath, err)
		}
	}

	keys := oidc.GenerateKeySet()
	s := server.New(config, keys)

	addr := net.JoinHostPort(opts.host, opts.port)
	s.Engine.SetTrustedProxies(nil)

	printBanner(opts.host, opts.port)

	httpServ := &http.Server{
		Addr:    addr,
		Handler: s.Engine,
	}
	chanHttpErr := make(chan error)

	go func() {
		err = httpServ.ListenAndServe()
		if err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				chanHttpErr <- err
			}
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	select {
	// if we are toldt to abort, initate gracefull shutdown of the http
	// server
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = httpServ.Shutdown(ctx)
		if err != nil {
			log.Println("error during shutdown:", err)
			os.Exit(1)
		}

		fmt.Println("\nWork done? Well MOCC again tomorrow!")
		os.Exit(0)
	// handle unexpected errors from the http server
	case <-chanHttpErr:
		log.Println("server closed unexpectedly:", err)
		os.Exit(1)
	}

}

func parseOptions() options {
	const (
		defaultUsersPath = "users.yaml"
		defaultHost      = "127.0.0.1"
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
		fmt.Fprintln(out, "  MOCC_HOST, HOST   — address to bind (default: 127.0.0.1, use 0.0.0.0 for network)")
		fmt.Fprintln(out, "  MOCC_PORT, PORT   — port to bind (default: 9999)")
		fmt.Fprintln(out)
		flagSet.PrintDefaults()
	}

	flagSet.StringVar(&opts.usersPath, "users", opts.usersPath, "Path to the users YAML file")
	flagSet.StringVar(&opts.host, "host", opts.host, "Host/IP address to bind to")
	flagSet.StringVar(&opts.port, "port", opts.port, "Port to listen on")
	flagSet.BoolVar(&opts.showVersion, "version", false, "Show MOCC version and exit")

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
`
	fmt.Print(banner)
	fmt.Println(buildFooterLine(banner, version))
	fmt.Println()
	fmt.Println("MOCC ready — happy moccing!")
	fmt.Println()

	// Determine if we're exposed to the network
	isNetworkExposed := host == "0.0.0.0" || host == "::"

	if isNetworkExposed {
		// Show both Local and Network URLs
		fmt.Printf("  ➜  Local:   http://localhost:%s\n", port)
		if networkIP := getLocalIP(); networkIP != "" {
			fmt.Printf("  ➜  Network: http://%s:%s\n", networkIP, port)
		}
	} else {
		// Show single URL for localhost-only or specific IP
		displayHost := host
		if displayHost == "" || displayHost == "127.0.0.1" {
			displayHost = "localhost"
		}
		fmt.Printf("  ➜  Local:   http://%s:%s\n", displayHost, port)
	}
	fmt.Println()
	fmt.Println("Quick tips:")
	fmt.Println("  • --users <path>    override the bundled users list (env: MOCC_USERS / USERS)")
	fmt.Println("  • --host 0.0.0.0    expose to network (default: localhost only, env: MOCC_HOST / HOST)")
	fmt.Println("  • --port <port>     pick a different port (env: MOCC_PORT / PORT)")
	fmt.Println("  • Flags win over env vars; env vars win over built-in defaults.")
	fmt.Println()
	fmt.Println("Docs & updates: https://github.com/jonasbg/mocc")
	fmt.Println()
}

// getLocalIP returns the first non-loopback IPv4 address found on the machine.
// Returns empty string if no suitable address is found.
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// buildFooterLine returns a line like:
// [spaces]└────── version ──────┘
// - total width ≤ 130
// - centered under the banner width
func buildFooterLine(banner, version string) string {
	bannerWidth := measureBannerWidth(banner)    // width of the top box line
	const maxWidth = 130                         // hard cap
	footerWidth := minInt(bannerWidth, maxWidth) // we won't exceed 130
	innerWidth := footerWidth - 2                // minus corners
	content := " " + version + " "
	contentLen := utf8.RuneCountInString(content)

	// If content is too wide, trim version to fit (keep room for single spaces if possible).
	if contentLen > innerWidth {
		// leave at least 0 dashes; trim to innerWidth
		content = trimRunes(content, innerWidth)
		contentLen = utf8.RuneCountInString(content)
	}

	dashTotal := innerWidth - contentLen
	if dashTotal < 0 {
		dashTotal = 0
	}
	leftDashes := dashTotal / 2
	rightDashes := dashTotal - leftDashes

	line := "└" + strings.Repeat("─", leftDashes) + content + strings.Repeat("─", rightDashes) + "┘"

	// If the banner is wider than the footer, left-pad spaces so the footer is centered.
	leftPad := 0
	if bannerWidth > footerWidth {
		leftPad = (bannerWidth - footerWidth) / 2
	}

	return strings.Repeat(" ", leftPad) + line
}

func measureBannerWidth(b string) int {
	// Use the first non-empty line; the top frame line is perfect.
	lines := strings.Split(b, "\n")
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			return utf8.RuneCountInString(ln)
		}
	}
	return 80 // fallback
}

func trimRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	// prefer keeping a trailing space if limit allows
	return string(runes[:limit])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
