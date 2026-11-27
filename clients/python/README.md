# vanishly (Python)

Client for [Vanishly](https://github.com/DennisPohlmann/Vanishly), one-time
secrets: the whole API as a library and the command line tool `vanishly`.

Full documentation: [docs/CLIENTS.md](https://github.com/DennisPohlmann/Vanishly/blob/main/docs/CLIENTS.md). End-to-end encrypted (crypto format v1, the same as the web pages): the secret, the key and the passphrase never reach the server; the key is only in the link's `#` part.

```bash
pip install vanishly
vanishly share 's3cret' --url https://ots.example.com --ttl 3600
vanishly share --url https://ots.example.com --ttl 3600   # asks for the secret, prints the link
vanishly open 'https://ots.example.com/s/<id>#<key>'
```

```python
from vanishly import Client

c = Client("https://ots.example.com", token=None)  # token: vnly_... with sign-in
res = c.create("s3cret", passphrase="", ttl=3600, views=1)
print(res["shareUrl"], res["receiptUrl"])
print(c.open(res["shareUrl"])["secret"])
```

Every endpoint has a method (`c.receipt(id)`, `c.burn(id)`, `c.me()`,
`c.tokens()`, `c.audit()`, ...); `c.request(method, path, body)` calls any
other. Errors raise `vanishly.ApiError` (`status`, `error`, `message`).
Needs Python 3.9+ and `cryptography`.
