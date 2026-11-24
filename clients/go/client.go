package vanishly

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Version of this client; the build sets it (-X ...vanishly.Version=).
var Version = "4.0.0"

var linkRe = regexp.MustCompile(`^(https?://[^#]+?)/s/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})$`)

// APIError is an answer other than 2xx.
type APIError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
	Body    map[string]any
}

func (e *APIError) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

// ParseLink splits https://host/s/<id>#<key> into base URL, id and key.
func ParseLink(link string) (base, id, key string, err error) {
	m := linkRe.FindStringSubmatch(strings.TrimSpace(link))
	if m == nil {
		return "", "", "", fmt.Errorf("not a secret link: https://.../s/<id>#<key>")
	}
	return m[1], m[2], m[3], nil
}

// Client talks to one Vanishly server.
type Client struct {
	BaseURL string
	// Token: a personal API token (vnly_...) or a provider token.
	Token string
	// Name/version sent as X-Vanishly-Client (CLIENT_MIN_VERSION, CLIENT_RECOMMENDED_VERSION).
	ClientName string
	// RunID, Comment, OnBehalfOf: X-Run-Id, X-Audit-Comment, X-On-Behalf-Of for the audit log.
	RunID, Comment, OnBehalfOf string
	HTTP                       *http.Client
	// RecommendedVersion is set when the server recommends a newer client.
	RecommendedVersion string
}

// New returns a client for baseURL (https://ots.example.com).
func New(baseURL, token string) (*Client, error) {
	if !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://") {
		return nil, fmt.Errorf("the server URL must start with https:// or http://")
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, ClientName: "go", HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

// Request makes any API call; path is below /api ("/v1/config"). With out
// nil the body is returned as text (e.g. audit CSV).
func (c *Client) Request(ctx context.Context, method, path string, body any, query url.Values, out any) (string, error) {
	u := c.BaseURL + "/api" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), u, rd)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vanishly-"+c.ClientName+"/"+Version)
	req.Header.Set("X-Vanishly-Client", c.ClientName+"/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.RunID != "" {
		req.Header.Set("X-Run-Id", c.RunID)
	}
	if c.Comment != "" {
		req.Header.Set("X-Audit-Comment", url.PathEscape(c.Comment))
	}
	if c.OnBehalfOf != "" {
		req.Header.Set("X-On-Behalf-Of", c.OnBehalfOf)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if r := res.Header.Get("X-Vanishly-Client-Recommended"); r != "" {
		c.RecommendedVersion = r
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return "", err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := &APIError{Status: res.StatusCode, Code: "http_error", Message: res.Status}
		_ = json.Unmarshal(data, e)
		_ = json.Unmarshal(data, &e.Body)
		return "", e
	}
	if out != nil && len(data) > 0 {
		return "", json.Unmarshal(data, out)
	}
	return string(data), nil
}

// Map is a JSON object.
type Map = map[string]any

// Options of a new secret; zero values are left out.
type Options struct {
	TTL               int      `json:"ttl,omitempty"`
	Views             int      `json:"views,omitempty"`
	Confirmed         bool     `json:"confirmed,omitempty"`
	Recipients        []string `json:"recipients,omitempty"`
	RecipientGroups   []string `json:"recipientGroups,omitempty"`
	Responsible       []string `json:"responsible,omitempty"`
	ResponsibleGroups []string `json:"responsibleGroups,omitempty"`
	Comment           string   `json:"comment,omitempty"`
}

func merge(parts ...any) Map {
	out := Map{}
	for _, p := range parts {
		b, _ := json.Marshal(p)
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func seg(s string) string { return url.PathEscape(s) }

func (c *Client) get(ctx context.Context, path string, q url.Values) (Map, error) {
	var m Map
	_, err := c.Request(ctx, "GET", path, nil, q, &m)
	return m, err
}

func (c *Client) post(ctx context.Context, path string, body any) (Map, error) {
	if body == nil {
		body = Map{}
	}
	var m Map
	_, err := c.Request(ctx, "POST", path, body, nil, &m)
	return m, err
}

// Create encrypts here and stores the secret (POST /v1/secrets). The answer
// gets shareUrl and receiptUrl with the key; the server never sees it.
func (c *Client) Create(ctx context.Context, secret, passphrase string, o Options) (Map, error) {
	key, p, err := EncryptSecret(secret, passphrase)
	if err != nil {
		return nil, err
	}
	res, err := c.CreateSecret(ctx, merge(p, o))
	if err != nil {
		return nil, err
	}
	res["shareUrl"] = fmt.Sprintf("%s%v#%s", c.BaseURL, res["secretPath"], key)
	if rp, ok := res["receiptPath"].(string); ok && rp != "" {
		res["receiptUrl"] = c.BaseURL + rp + "#" + key
	} else {
		res["receiptUrl"] = nil
	}
	return res, nil
}

// Open takes one view of a link and decrypts here. Returns the secret and the views left.
func (c *Client) Open(ctx context.Context, link, passphrase string) (string, int, error) {
	base, id, key, err := ParseLink(link)
	if err != nil {
		return "", 0, err
	}
	if base != c.BaseURL {
		return "", 0, fmt.Errorf("the link belongs to %s, not to %s", base, c.BaseURL)
	}
	var pk []byte
	verifier := ""
	if passphrase != "" {
		meta, err := c.SecretMeta(ctx, id)
		if err != nil {
			return "", 0, err
		}
		if has, _ := meta["passphrase"].(bool); has {
			salt, _ := meta["salt"].(string)
			it, _ := meta["iterations"].(float64)
			if pk, err = UnlockKey(passphrase, salt, int(it)); err != nil {
				return "", 0, err
			}
			if verifier, err = VerifierFor(pk, salt); err != nil {
				return "", 0, err
			}
		}
	}
	var r struct {
		Payload
		ViewsLeft int `json:"viewsLeft"`
	}
	body := Map{}
	if verifier != "" {
		body["verifier"] = verifier
	}
	if _, err := c.Request(ctx, "POST", "/v1/secrets/"+seg(id)+"/reveal", body, nil, &r); err != nil {
		return "", 0, err
	}
	s, err := DecryptSecret(r.Payload, key, pk)
	return s, r.ViewsLeft, err
}

// One method per endpoint.

func (c *Client) Index(ctx context.Context) (Map, error)     { return c.get(ctx, "/v1", nil) }
func (c *Client) Config(ctx context.Context) (Map, error)    { return c.get(ctx, "/v1/config", nil) }
func (c *Client) Downloads(ctx context.Context) (Map, error) { return c.get(ctx, "/v1/downloads", nil) }
func (c *Client) CreateSecret(ctx context.Context, payload Map) (Map, error) {
	return c.post(ctx, "/v1/secrets", payload)
}

// Share lets the server encrypt (POST /v1/share): the server sees the secret.
func (c *Client) Share(ctx context.Context, secret, passphrase string, o Options) (Map, error) {
	b := merge(o)
	b["secret"] = secret
	if passphrase != "" {
		b["passphrase"] = passphrase
	}
	return c.post(ctx, "/v1/share", b)
}

// OpenOnServer lets the server decrypt (POST /v1/open): the server sees key and secret.
func (c *Client) OpenOnServer(ctx context.Context, link, passphrase string) (Map, error) {
	b := Map{"link": link}
	if passphrase != "" {
		b["passphrase"] = passphrase
	}
	return c.post(ctx, "/v1/open", b)
}
func (c *Client) SecretMeta(ctx context.Context, id string) (Map, error) {
	return c.get(ctx, "/v1/secrets/"+seg(id), nil)
}
func (c *Client) Reveal(ctx context.Context, id, verifier string) (Map, error) {
	b := Map{}
	if verifier != "" {
		b["verifier"] = verifier
	}
	return c.post(ctx, "/v1/secrets/"+seg(id)+"/reveal", b)
}
func (c *Client) Receipt(ctx context.Context, id string) (Map, error) {
	return c.get(ctx, "/v1/receipts/"+seg(id), nil)
}
func (c *Client) Burn(ctx context.Context, id string) (Map, error) {
	return c.post(ctx, "/v1/receipts/"+seg(id)+"/burn", nil)
}
func (c *Client) Me(ctx context.Context) (Map, error) { return c.get(ctx, "/v1/me", nil) }
func (c *Client) MySecrets(ctx context.Context, q url.Values) (Map, error) {
	return c.get(ctx, "/v1/me/secrets", q)
}
func (c *Client) MySecret(ctx context.Context, ref string) (Map, error) {
	return c.get(ctx, "/v1/me/secrets/"+seg(ref), nil)
}
func (c *Client) BurnMySecret(ctx context.Context, ref string) (Map, error) {
	return c.post(ctx, "/v1/me/secrets/"+seg(ref)+"/burn", nil)
}
func (c *Client) Groups(ctx context.Context, q string) (Map, error) {
	return c.get(ctx, "/v1/groups", url.Values{"q": {q}})
}
func (c *Client) People(ctx context.Context, q string) (Map, error) {
	return c.get(ctx, "/v1/people", url.Values{"q": {q}})
}
func (c *Client) Tokens(ctx context.Context) (Map, error) { return c.get(ctx, "/v1/tokens", nil) }
func (c *Client) CreateToken(ctx context.Context, body Map) (Map, error) {
	return c.post(ctx, "/v1/tokens", body)
}
func (c *Client) RevokeToken(ctx context.Context, id string) (Map, error) {
	return c.post(ctx, "/v1/tokens/"+seg(id)+"/revoke", nil)
}

// Admin.

func (c *Client) AdminStatus(ctx context.Context) (Map, error) {
	return c.get(ctx, "/v1/admin/status", nil)
}
func (c *Client) AdminTokens(ctx context.Context) (Map, error) {
	return c.get(ctx, "/v1/admin/tokens", nil)
}
func (c *Client) AdminRevokeToken(ctx context.Context, id string) (Map, error) {
	return c.post(ctx, "/v1/admin/tokens/"+seg(id)+"/revoke", nil)
}

// Audit returns the audit log as text (format json, csv or jsonl in q).
func (c *Client) Audit(ctx context.Context, q url.Values) (string, error) {
	return c.Request(ctx, "GET", "/v1/admin/audit", nil, q, nil)
}
func (c *Client) AuditVerify(ctx context.Context) (Map, error) {
	return c.get(ctx, "/v1/admin/audit/verify", nil)
}
func (c *Client) TokenPolicies(ctx context.Context) (Map, error) {
	return c.get(ctx, "/v1/admin/token-policies", nil)
}
func (c *Client) SetTokenPolicy(ctx context.Context, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/token-policies", body)
}
func (c *Client) AdminSecrets(ctx context.Context, q url.Values) (Map, error) {
	return c.get(ctx, "/v1/admin/secrets", q)
}
func (c *Client) AdminSecret(ctx context.Context, ref string) (Map, error) {
	return c.get(ctx, "/v1/admin/secrets/"+seg(ref), nil)
}
func (c *Client) AdminBurn(ctx context.Context, ref string) (Map, error) {
	return c.post(ctx, "/v1/admin/secrets/"+seg(ref)+"/burn", nil)
}
func (c *Client) ServiceAccounts(ctx context.Context) (Map, error) {
	return c.get(ctx, "/v1/admin/service-accounts", nil)
}
func (c *Client) CreateServiceAccount(ctx context.Context, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/service-accounts", body)
}
func (c *Client) ChangeServiceAccount(ctx context.Context, name string, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/service-accounts/"+seg(name), body)
}
func (c *Client) DeleteServiceAccount(ctx context.Context, name string) (Map, error) {
	return c.post(ctx, "/v1/admin/service-accounts/"+seg(name)+"/delete", nil)
}
func (c *Client) ServiceAccountTokens(ctx context.Context, name string) (Map, error) {
	return c.get(ctx, "/v1/admin/service-accounts/"+seg(name)+"/tokens", nil)
}
func (c *Client) IssueServiceAccountToken(ctx context.Context, name string, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/service-accounts/"+seg(name)+"/tokens", body)
}
func (c *Client) RotateServiceAccountToken(ctx context.Context, name, id string, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/service-accounts/"+seg(name)+"/tokens/"+seg(id)+"/rotate", body)
}
func (c *Client) Users(ctx context.Context) (Map, error) { return c.get(ctx, "/v1/admin/users", nil) }
func (c *Client) CreateUser(ctx context.Context, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/users", body)
}
func (c *Client) ChangeUser(ctx context.Context, user string, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/users/"+seg(user), body)
}
func (c *Client) ResetUserPassword(ctx context.Context, user string, body Map) (Map, error) {
	return c.post(ctx, "/v1/admin/users/"+seg(user)+"/password", body)
}
func (c *Client) DeleteUser(ctx context.Context, user string) (Map, error) {
	return c.post(ctx, "/v1/admin/users/"+seg(user)+"/delete", nil)
}
