# vanishly (JavaScript / TypeScript)

Client for [Vanishly](https://github.com/DennisPohlmann/vanishly), one-time
secrets, for browsers, Node.js 20+, Deno and Bun (Web Crypto, `fetch`, no
dependencies; types included).

Full documentation: [docs/CLIENTS.md](https://github.com/DennisPohlmann/vanishly/blob/main/docs/CLIENTS.md). End-to-end encrypted (crypto format v1, the same as the web pages): the secret, the key and the passphrase never reach the server; the key is only in the link's `#` part.

```bash
npm install vanishly
```

```js
import { Client } from 'vanishly';

const c = new Client('https://ots.example.com', { token: undefined }); // vnly_... with sign-in
const res = await c.create('s3cret', '', { ttl: 3600, views: 1 });
console.log(res.shareUrl, res.receiptUrl);
const { secret, viewsLeft } = await c.open(res.shareUrl);
```

Every endpoint has a method (`receipt`, `burn`, `me`, `tokens`, `audit`,
...); `request(method, path, body)` calls any other. Errors are `ApiError`
(`status`, `error`, `message`). `vanishly/crypto` is the crypto alone.
