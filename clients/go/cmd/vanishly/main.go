// Command vanishly is the command line client of Vanishly. End-to-end
// encrypted by default: the secret and the key never reach the server.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"

	vanishly "github.com/DennisPohlmann/vanishly/clients/go/v3"
)

const usage = `vanishly - one-time secrets, end-to-end encrypted

usage: vanishly [global flags] <command> [flags]

commands:
  share [SECRET|-]   encrypt here and store a secret; prints the link
                     (no SECRET or -: asks for it on a terminal, without
                     echo, else reads standard input, e.g. < file)
  open LINK          open a link: takes one view, decrypts here
  meta LINK|ID       state of a secret without using a view
  status LINK|ID     status of a secret for its sender (status link)
  burn LINK|ID       destroy a secret now (status link)
  config             limits and options of the server
  me                 who is signed in
  downloads          the clients the server offers, with checksums
  api METHOD PATH    any API call, e.g. api GET /v1/tokens
  version            print the version

global flags (before the command):
  --url URL          server, e.g. https://ots.example.com (VANISHLY_URL)
  --token TOKEN      API token vnly_... (VANISHLY_TOKEN)
  --json             print the whole answer as JSON
  --run-id ID, --audit-comment TEXT, --on-behalf-of WHO   for the audit log

share flags: --ttl S --views N --recipient X --recipient-group G
  --responsible X --responsible-group G (all repeatable) --comment TEXT
  --confirm --server-side
share/open flags: --passphrase P | --passphrase-file F | --ask
  (or VANISHLY_PASSPHRASE), --server-side (the server sees the secret)
api flags: --data JSON|@file|- --query key=value (repeatable)

examples:
  export VANISHLY_URL=https://ots.example.com
  vanishly share --ttl 3600 --views 1       # asks for the secret
  vanishly share --ttl 3600 < secret.txt
  vanishly open 'https://ots.example.com/s/<id>#<key>'
`

var (
	receiptRe = regexp.MustCompile(`^(https?://[^#]+?)/r/([A-Za-z0-9_-]{22})(?:#.*)?$`)
	secretRe  = regexp.MustCompile(`^(https?://[^#]+?)/s/([A-Za-z0-9_-]{22})(?:#.*)?$`)
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	errUsage  = errors.New("usage")
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// parse allows flags before and after the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, errUsage
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type global struct {
	url, token, runID, comment, onBehalf string
	json                                 bool
	client                               *vanishly.Client
}

func (g *global) make(base string) (*vanishly.Client, error) {
	if base == "" {
		return nil, fmt.Errorf("no server: use --url or VANISHLY_URL")
	}
	c, err := vanishly.New(base, g.token)
	if err != nil {
		return nil, err
	}
	c.ClientName = "cli"
	c.RunID, c.Comment, c.OnBehalfOf = g.runID, g.comment, g.onBehalf
	g.client = c
	return c, nil
}

func (g *global) print(v any, text string) {
	if g.json || text == "" {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Println(text)
}

type pass struct {
	value, file string
	ask         bool
}

func (p *pass) add(fs *flag.FlagSet) {
	fs.StringVar(&p.value, "passphrase", "", "the passphrase (visible in the process list)")
	fs.StringVar(&p.file, "passphrase-file", "", "read the passphrase from this file")
	fs.BoolVar(&p.ask, "ask", false, "ask for the passphrase")
}

func (p *pass) read() (string, error) {
	switch {
	case p.value != "":
		return p.value, nil
	case p.file != "":
		b, err := os.ReadFile(p.file)
		return strings.TrimRight(string(b), "\r\n"), err
	case p.ask:
		fmt.Fprint(os.Stderr, "Passphrase: ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	return os.Getenv("VANISHLY_PASSPHRASE"), nil
}

func baseAndID(ref string, re *regexp.Regexp, fallback string) (string, string, error) {
	if m := re.FindStringSubmatch(strings.TrimSpace(ref)); m != nil {
		return m[1], m[2], nil
	}
	if idRe.MatchString(ref) {
		if fallback == "" {
			return "", "", fmt.Errorf("an id needs --url (or VANISHLY_URL)")
		}
		return fallback, ref, nil
	}
	return "", "", fmt.Errorf("not a link or id: %s", ref)
}

func run(args []string) error {
	g := &global{}
	fs := flag.NewFlagSet("vanishly", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&g.url, "url", os.Getenv("VANISHLY_URL"), "")
	fs.StringVar(&g.token, "token", os.Getenv("VANISHLY_TOKEN"), "")
	fs.BoolVar(&g.json, "json", false, "")
	fs.StringVar(&g.runID, "run-id", "", "")
	fs.StringVar(&g.comment, "audit-comment", "", "")
	fs.StringVar(&g.onBehalf, "on-behalf-of", "", "")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() == 0 {
		return errUsage
	}
	ctx := context.Background()
	cmd, rest := fs.Arg(0), fs.Args()[1:]
	defer func() {
		if g.client != nil && g.client.RecommendedVersion != "" {
			fmt.Fprintf(os.Stderr, "vanishly: a newer client is recommended (%s, this is %s): %s/downloads\n",
				g.client.RecommendedVersion, vanishly.Version, g.client.BaseURL)
		}
	}()
	sub := flag.NewFlagSet(cmd, flag.ContinueOnError)
	sub.SetOutput(io.Discard)
	switch cmd {
	case "share":
		var o vanishly.Options
		var rcp, rg, rs, rsg list
		var p pass
		var server bool
		p.add(sub)
		sub.IntVar(&o.TTL, "ttl", 0, "")
		sub.IntVar(&o.Views, "views", 0, "")
		sub.Var(&rcp, "recipient", "")
		sub.Var(&rg, "recipient-group", "")
		sub.Var(&rs, "responsible", "")
		sub.Var(&rsg, "responsible-group", "")
		sub.StringVar(&o.Comment, "comment", "", "")
		sub.BoolVar(&o.Confirmed, "confirm", false, "")
		sub.BoolVar(&server, "server-side", false, "")
		pos, err := parse(sub, rest)
		if err != nil || len(pos) > 1 {
			return errUsage
		}
		o.Recipients, o.RecipientGroups, o.Responsible, o.ResponsibleGroups = rcp, rg, rs, rsg
		secret := "-"
		if len(pos) == 1 {
			secret = pos[0]
		}
		if secret == "-" && term.IsTerminal(int(os.Stdin.Fd())) {
			// Typed in: no echo, and not in the shell history.
			fmt.Fprint(os.Stderr, "Secret: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return err
			}
			secret = string(b)
		} else if secret == "-" {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			secret = string(b)
		}
		if secret == "" {
			return fmt.Errorf("the secret is empty")
		}
		pw, err := p.read()
		if err != nil {
			return err
		}
		c, err := g.make(g.url)
		if err != nil {
			return err
		}
		var res vanishly.Map
		if server {
			res, err = c.Share(ctx, secret, pw, o)
		} else {
			res, err = c.Create(ctx, secret, pw, o)
		}
		if err != nil {
			return err
		}
		g.print(res, fmt.Sprint(res["shareUrl"]))
		if r, ok := res["receiptUrl"].(string); ok && r != "" && !g.json {
			fmt.Fprintln(os.Stderr, "status: "+r)
		}
	case "open":
		var p pass
		var server bool
		p.add(sub)
		sub.BoolVar(&server, "server-side", false, "")
		pos, err := parse(sub, rest)
		if err != nil || len(pos) != 1 {
			return errUsage
		}
		base, _, _, err := vanishly.ParseLink(pos[0])
		if err != nil {
			return err
		}
		pw, err := p.read()
		if err != nil {
			return err
		}
		c, err := g.make(base)
		if err != nil {
			return err
		}
		if server {
			res, err := c.OpenOnServer(ctx, pos[0], pw)
			if err != nil {
				return err
			}
			g.print(res, fmt.Sprint(res["secret"]))
			return nil
		}
		s, left, err := c.Open(ctx, pos[0], pw)
		if err != nil {
			return err
		}
		g.print(vanishly.Map{"secret": s, "viewsLeft": left}, s)
	case "meta", "status", "burn":
		pos, err := parse(sub, rest)
		if err != nil || len(pos) != 1 {
			return errUsage
		}
		re := receiptRe
		if cmd == "meta" {
			re = secretRe
		}
		base, id, err := baseAndID(pos[0], re, g.url)
		if err != nil {
			return err
		}
		c, err := g.make(base)
		if err != nil {
			return err
		}
		var res vanishly.Map
		switch cmd {
		case "meta":
			res, err = c.SecretMeta(ctx, id)
		case "status":
			res, err = c.Receipt(ctx, id)
		default:
			res, err = c.Burn(ctx, id)
		}
		if err != nil {
			return err
		}
		g.print(res, "")
	case "config", "me", "downloads":
		c, err := g.make(g.url)
		if err != nil {
			return err
		}
		var res vanishly.Map
		switch cmd {
		case "config":
			res, err = c.Config(ctx)
		case "me":
			res, err = c.Me(ctx)
		default:
			res, err = c.Downloads(ctx)
		}
		if err != nil {
			return err
		}
		g.print(res, "")
	case "api":
		var data string
		var query list
		sub.StringVar(&data, "data", "", "")
		sub.Var(&query, "query", "")
		pos, err := parse(sub, rest)
		if err != nil || len(pos) != 2 {
			return errUsage
		}
		var body any
		if data != "" {
			raw := []byte(data)
			if data == "-" {
				raw, err = io.ReadAll(os.Stdin)
			} else if strings.HasPrefix(data, "@") {
				raw, err = os.ReadFile(data[1:])
			}
			if err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				return fmt.Errorf("--data is not JSON: %w", err)
			}
		}
		q := url.Values{}
		for _, kv := range query {
			k, v, _ := strings.Cut(kv, "=")
			q.Add(k, v)
		}
		path := pos[1]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		c, err := g.make(g.url)
		if err != nil {
			return err
		}
		text, err := c.Request(ctx, pos[0], path, body, q, nil)
		if err != nil {
			return err
		}
		fmt.Println(text)
	case "version", "--version":
		fmt.Printf("vanishly %s (go)\n", vanishly.Version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		return errUsage
	}
	return nil
}

func main() {
	err := run(os.Args[1:])
	var api *vanishly.APIError
	switch {
	case err == nil:
		return
	case errors.Is(err, errUsage):
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	case errors.As(err, &api):
		fmt.Fprintf(os.Stderr, "vanishly: %v\n", api)
		if u, ok := api.Body["downloadUrl"].(string); ok && api.Status == 426 {
			fmt.Fprintf(os.Stderr, "vanishly: download a newer client: %s\n", u)
		}
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "vanishly: %v\n", err)
		os.Exit(1)
	}
}
