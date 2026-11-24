# vanishly (Go)

Go library for
[Vanishly](https://github.com/DennisPohlmann/vanishly), one-time secrets.

Full documentation: [docs/CLIENTS.md](https://github.com/DennisPohlmann/vanishly/blob/main/docs/CLIENTS.md). End-to-end encrypted (crypto format v1, the same as the web pages): the secret, the key and the passphrase never reach the server; the key is only in the link's `#` part.

```bash
go get github.com/DennisPohlmann/vanishly/clients/go/v3
```

```go
import vanishly "github.com/DennisPohlmann/vanishly/clients/go/v3"

c, err := vanishly.New("https://ots.example.com", "") // token vnly_... with sign-in
res, err := c.Create(ctx, "s3cret", "", vanishly.Options{TTL: 3600, Views: 1})
fmt.Println(res["shareUrl"], res["receiptUrl"])
secret, viewsLeft, err := c.Open(ctx, res["shareUrl"].(string), "")
```

Every endpoint has a method (`Receipt`, `Burn`, `Me`, `Tokens`, `Audit`,
...); `Request` calls any other. API errors are `*vanishly.APIError`.
