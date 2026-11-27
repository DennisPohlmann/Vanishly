# vanishly (Go)

Go library and command line client for
[Vanishly](https://github.com/DennisPohlmann/Vanishly), one-time secrets.

Full documentation: [docs/CLIENTS.md](https://github.com/DennisPohlmann/Vanishly/blob/main/docs/CLIENTS.md). End-to-end encrypted (crypto format v1, the same as the web pages): the secret, the key and the passphrase never reach the server; the key is only in the link's `#` part.

```bash
go install github.com/DennisPohlmann/vanishly/clients/go/v4/cmd/vanishly@latest
# or a ready binary for Windows, macOS, Linux, FreeBSD: <your server>/downloads
```

```go
import vanishly "github.com/DennisPohlmann/vanishly/clients/go/v4"

c, err := vanishly.New("https://ots.example.com", "") // token vnly_... with sign-in
res, err := c.Create(ctx, "s3cret", "", vanishly.Options{TTL: 3600, Views: 1})
fmt.Println(res["shareUrl"], res["receiptUrl"])
secret, viewsLeft, err := c.Open(ctx, res["shareUrl"].(string), "")
```

Every endpoint has a method (`Receipt`, `Burn`, `Me`, `Tokens`, `Audit`,
...); `Request` calls any other. API errors are `*vanishly.APIError`.
`build.sh` builds the binaries for all 14 platforms reproducibly.
