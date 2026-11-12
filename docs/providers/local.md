# Local accounts (`AUTH_PROVIDER=local`)

Vanishly keeps its own users in Redis; nobody needs an identity provider.
People sign in on `/auth/login` with their **e-mail address** (the sign-in
name, also what senders type as a recipient) and a password. Admins manage
the users on the **Users** tab of `/admin`. Sessions, recipients, groups,
admins, API tokens, "My secrets" and the audit log work as with a provider.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `AUTH_PROVIDER` | | `local` |
| `BASE_URL` | | required: the sign-in form is accepted only from this origin; `https:` makes the cookie `__Host-` and `Secure` |
| `AUTH_SECRET` / `_FILE` | | required, 32+ characters (recipient hashes, as with every provider) |
| `LOCAL_ADMIN_USERNAME` | | the first admin's e-mail address |
| `LOCAL_ADMIN_PASSWORD` / `_FILE` | | its password |
| `LOCAL_PASSWORD_MIN_LENGTH` | `12` | 8 to 128; every password set later must be this long (at most 1024) |
| `LOCAL_LOGIN_ATTEMPTS` | `5` | sign-ins (and "Change password" checks) per account and `RATE_LIMIT_WINDOW`; then the account is locked for the rest of the window; a success clears the count |

**The first admin** is created at the start only while Redis holds **no
users at all**. Once there is one, `LOCAL_ADMIN_*` are ignored: a password
changed in Vanishly is never overwritten, and a deleted admin does not come
back on a restart. Remove the password from `.env` after the first sign-in.
With no users and no `LOCAL_ADMIN_USERNAME`/`LOCAL_ADMIN_PASSWORD` the start
fails (exit 78).

Also with `local`: `RECIPIENTS`, `RECIPIENT_GROUPS=Name=<group>,...` (the
group names an admin gives the users), `RECIPIENT_DOMAINS`, `ADMIN_USERS`,
`ADMIN_GROUPS` (besides the role `admin`), `AUTH_SESSION_TTL`,
`AUTH_CREATE`, all `API_TOKEN*`, `ADMIN_*`, `MY_SECRETS`, `AUDIT_*`.

**Not with `local`** (each one stops the start with
`<NAME> does not apply to AUTH_PROVIDER=local`): every `ENTRA_*`, `OIDC_*`
and `DIRECTORY_*` setting, `AUTH_ALLOWED_DOMAINS`, `AUTH_LOGOUT` (the
sign-out is always local), `AUTH_AUTO_LOGIN`, `AUTH_API_AUDIENCE` (scripts
use Vanishly's own API tokens, `API_TOKENS=true`), `RECIPIENT_USER_GROUP`
and `RECIPIENTS_DIRECTORY_ONLY` (no directory), and `RECIPIENT_GROUPS=*`
(no group search). The other way round, a `LOCAL_*` setting with another
`AUTH_PROVIDER` stops the start too.

**Redis must keep its data** (append-only file or snapshots on a volume):
the users have no expiry. `/admin` warns when Redis has no persistence.
`docker-compose/local` sets this up; the Helm chart refuses
`config.AUTH_PROVIDER=local` with its bundled Redis unless
`redis.persistence.enabled=true`.

## Users

On `/admin` → **Users** (admins only; the API is `/api/v1/admin/users`,
see `/api/docs`): create (e-mail address, display name, role `user` or
`admin`, groups, password), change name, role and groups, disable and
enable, reset the password, delete.

- The last active admin cannot be demoted, disabled or deleted; nobody can
  delete, disable or demote themselves.
- Disabling, deleting or a new password ends the user's sessions at once;
  disabling and deleting also revokes their API tokens.
- Role and groups count from the next request on.
- Everyone changes their own password under their name → **Change
  password** (the current one is needed); their other sessions end.

## Security

- Passwords are hashed with scrypt (N=2^15, r=8, p=3, 16-byte random salt;
  the parameters are stored with the hash) and compared in constant time.
  An unknown address costs the same hash as a wrong password, and the
  answer is the same, so the form does not tell which addresses exist.
- The forms are accepted only from this site (`Sec-Fetch-Site`, `Origin`);
  each sign-in makes a new session id. Failed attempts count per account
  (`LOCAL_LOGIN_ATTEMPTS`) and per IP (`RATE_LIMIT_READ` on `/auth/*`).
  Note that someone who knows an address can keep that account locked by
  failing on purpose; the lock ends with the window.
- Audit events: `auth.login`, `auth.failed` (`bad_credentials`, `disabled`,
  `locked`, `wrong_password`; with the address only when the account
  exists), `auth.password_changed`, `admin.user_created`,
  `admin.user_changed`, `admin.user_disabled`, `admin.user_enabled`,
  `admin.user_password_reset`, `admin.user_deleted`. Passwords never.

## Keys in Redis

`luser:<address>` (hash: name, scrypt hash, role, groups, disabled,
created, updated, session version) and `luser:all` (set of addresses),
below `REDIS_PREFIX`, without expiry. Failed sign-ins:
`rl:login:<HMAC of the address>`.

## Troubleshooting

- `AUTH_PROVIDER=local has no users yet: set LOCAL_ADMIN_USERNAME and
  LOCAL_ADMIN_PASSWORD`: a first start (or Redis lost its data) without
  the first admin.
- Everybody must sign in again after a Redis restart and the users are
  gone: Redis keeps nothing on disk; switch on persistence.
- The only admin's password is lost: no setting resets it. Keep a second
  admin. As a last resort stop Vanishly, delete the `luser:*` keys with
  `redis-cli` (all accounts go) and start again with `LOCAL_ADMIN_*`.
