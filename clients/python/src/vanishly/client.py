"""HTTP client for the Vanishly API (/api/v1), standard library only."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .crypto import decrypt_secret, encrypt_secret, unlock_key, verifier_for

_LINK = re.compile(r"^(https?://[^#]+?)/s/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})$")


class ApiError(Exception):
    """An answer other than 2xx: status, error code, message and the whole body."""

    def __init__(self, status: int, error: str, message: str, body=None):
        super().__init__(f"{status} {error}: {message}")
        self.status = status
        self.error = error
        self.message = message
        self.body = body if body is not None else {}


def parse_link(link: str):
    """Splits https://host/s/<id>#<key> into (base_url, id, key)."""
    m = _LINK.match(link.strip())
    if not m:
        raise ValueError("not a secret link: https://.../s/<id>#<key>")
    return m.group(1), m.group(2), m.group(3)


def _seg(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")


class Client:
    """One Vanishly server. token: a personal API token (vnly_...) or a
    provider token. run_id, comment and on_behalf_of go into the audit log
    (X-Run-Id, X-Audit-Comment, X-On-Behalf-Of)."""

    def __init__(self, base_url: str, token: str | None = None, *, timeout: float = 30,
                 run_id: str | None = None, comment: str | None = None, on_behalf_of: str | None = None,
                 client_name: str = "python"):
        if not re.match(r"^https?://", base_url or ""):
            raise ValueError("base_url must start with https:// or http://")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.headers = {
            "User-Agent": f"vanishly-python/{__version__}",
            "Accept": "application/json",
            # CLIENT_MIN_VERSION / CLIENT_RECOMMENDED_VERSION of the server check this.
            "X-Vanishly-Client": f"{client_name}/{__version__}",
        }
        # Set when the server recommends a newer client (X-Vanishly-Client-Recommended).
        self.recommended_version: str | None = None
        if run_id:
            self.headers["X-Run-Id"] = run_id
        if comment:
            self.headers["X-Audit-Comment"] = urllib.parse.quote(comment, safe=" ")
        if on_behalf_of:
            self.headers["X-On-Behalf-Of"] = on_behalf_of

    # -- transport -------------------------------------------------------

    def request(self, method: str, path: str, body=None, query: dict | None = None, *, raw: bool = False):
        """Any API call; path is below /api, e.g. "/v1/config". Returns the
        decoded JSON (or the text with raw=True, e.g. audit CSV)."""
        url = f"{self.base_url}/api{path}"
        q = {k: v for k, v in (query or {}).items() if v is not None and v != ""}
        if q:
            url += "?" + urllib.parse.urlencode(q)
        headers = dict(self.headers)
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                self._note(res.headers)
                text = res.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            self._note(err.headers)
            text = err.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = {}
            if not isinstance(parsed, dict):
                parsed = {}
            raise ApiError(err.code, parsed.get("error", "http_error"), parsed.get("message", err.reason or ""), parsed) from None
        if raw:
            return text
        return json.loads(text) if text else None

    def _note(self, headers):
        rec = headers.get("X-Vanishly-Client-Recommended") if headers else None
        if rec:
            self.recommended_version = rec

    # -- end-to-end (the key never leaves this process) --------------------

    def create(self, secret: str, passphrase: str = "", **options) -> dict:
        """Encrypts here and stores it (POST /v1/secrets). options: ttl, views,
        confirmed, recipients, recipientGroups, responsible, responsibleGroups,
        comment. Returns the server's answer plus shareUrl and receiptUrl."""
        key, payload = encrypt_secret(secret, passphrase)
        res = self.create_secret({**payload, **_options(options)})
        res["shareUrl"] = f"{self.base_url}{res['secretPath']}#{key}"
        res["receiptUrl"] = f"{self.base_url}{res['receiptPath']}#{key}" if res.get("receiptPath") else None
        return res

    def open(self, link: str, passphrase: str = "") -> dict:
        """Opens a link here: takes one view and decrypts locally. Returns
        {"secret", "viewsLeft"}. The link must belong to this client's server."""
        base, sid, key = parse_link(link)
        if base.rstrip("/") != self.base_url:
            raise ValueError(f"the link belongs to {base}, not to {self.base_url}")
        pk = b""
        verifier = None
        if passphrase:
            # Needs salt and iterations first (ENABLE_SECRET_META_API).
            meta = self.secret_meta(sid)
            if meta.get("passphrase"):
                pk = unlock_key(passphrase, meta["salt"], meta["iterations"])
                verifier = verifier_for(pk, meta["salt"])
        payload = self.reveal(sid, verifier)
        return {"secret": decrypt_secret(payload, key, pk), "viewsLeft": payload.get("viewsLeft")}

    # -- one method per endpoint -------------------------------------------

    def index(self):
        return self.request("GET", "/v1")

    def config(self):
        return self.request("GET", "/v1/config")

    def downloads(self):
        return self.request("GET", "/v1/downloads")

    def create_secret(self, payload: dict):
        return self.request("POST", "/v1/secrets", payload)

    def share(self, secret: str, passphrase: str = "", **options):
        """Server-side encryption (POST /v1/share): the server sees the secret."""
        body = {"secret": secret, **_options(options)}
        if passphrase:
            body["passphrase"] = passphrase
        return self.request("POST", "/v1/share", body)

    def open_on_server(self, link: str, passphrase: str = ""):
        """Server-side reveal (POST /v1/open): the server sees key and secret."""
        body = {"link": link}
        if passphrase:
            body["passphrase"] = passphrase
        return self.request("POST", "/v1/open", body)

    def secret_meta(self, secret_id: str):
        return self.request("GET", f"/v1/secrets/{_seg(secret_id)}")

    def reveal(self, secret_id: str, verifier: str | None = None):
        return self.request("POST", f"/v1/secrets/{_seg(secret_id)}/reveal", {"verifier": verifier} if verifier else {})

    def receipt(self, receipt_id: str):
        return self.request("GET", f"/v1/receipts/{_seg(receipt_id)}")

    def burn(self, receipt_id: str):
        return self.request("POST", f"/v1/receipts/{_seg(receipt_id)}/burn", {})

    def me(self):
        return self.request("GET", "/v1/me")

    def my_secrets(self, **query):
        return self.request("GET", "/v1/me/secrets", query=query)

    def my_secret(self, ref: str):
        return self.request("GET", f"/v1/me/secrets/{_seg(ref)}")

    def burn_my_secret(self, ref: str):
        return self.request("POST", f"/v1/me/secrets/{_seg(ref)}/burn", {})

    def groups(self, q: str = ""):
        return self.request("GET", "/v1/groups", query={"q": q})

    def people(self, q: str = ""):
        return self.request("GET", "/v1/people", query={"q": q})

    def tokens(self):
        return self.request("GET", "/v1/tokens")

    def create_token(self, **body):
        return self.request("POST", "/v1/tokens", body)

    def revoke_token(self, token_id: str):
        return self.request("POST", f"/v1/tokens/{_seg(token_id)}/revoke", {})

    # admin

    def admin_status(self):
        return self.request("GET", "/v1/admin/status")

    def admin_tokens(self):
        return self.request("GET", "/v1/admin/tokens")

    def admin_revoke_token(self, token_id: str):
        return self.request("POST", f"/v1/admin/tokens/{_seg(token_id)}/revoke", {})

    def audit(self, **query):
        """query: type, outcome, actor, recipient, runId, q, from, to, limit,
        format (json, csv, jsonl; csv and jsonl come back as text)."""
        fmt = query.get("format")
        return self.request("GET", "/v1/admin/audit", query=query, raw=fmt in ("csv", "jsonl"))

    def audit_verify(self):
        return self.request("GET", "/v1/admin/audit/verify")

    def token_policies(self):
        return self.request("GET", "/v1/admin/token-policies")

    def set_token_policy(self, **body):
        return self.request("POST", "/v1/admin/token-policies", body)

    def admin_secrets(self, **query):
        return self.request("GET", "/v1/admin/secrets", query=query)

    def admin_secret(self, ref: str):
        return self.request("GET", f"/v1/admin/secrets/{_seg(ref)}")

    def admin_burn(self, ref: str):
        return self.request("POST", f"/v1/admin/secrets/{_seg(ref)}/burn", {})

    def service_accounts(self):
        return self.request("GET", "/v1/admin/service-accounts")

    def create_service_account(self, **body):
        return self.request("POST", "/v1/admin/service-accounts", body)

    def change_service_account(self, name: str, **body):
        return self.request("POST", f"/v1/admin/service-accounts/{_seg(name)}", body)

    def delete_service_account(self, name: str):
        return self.request("POST", f"/v1/admin/service-accounts/{_seg(name)}/delete", {})

    def service_account_tokens(self, name: str):
        return self.request("GET", f"/v1/admin/service-accounts/{_seg(name)}/tokens")

    def issue_service_account_token(self, name: str, **body):
        return self.request("POST", f"/v1/admin/service-accounts/{_seg(name)}/tokens", body)

    def rotate_service_account_token(self, name: str, token_id: str, **body):
        return self.request("POST", f"/v1/admin/service-accounts/{_seg(name)}/tokens/{_seg(token_id)}/rotate", body)

    def users(self):
        return self.request("GET", "/v1/admin/users")

    def create_user(self, **body):
        return self.request("POST", "/v1/admin/users", body)

    def change_user(self, user: str, **body):
        return self.request("POST", f"/v1/admin/users/{_seg(user)}", body)

    def reset_user_password(self, user: str, **body):
        return self.request("POST", f"/v1/admin/users/{_seg(user)}/password", body)

    def delete_user(self, user: str):
        return self.request("POST", f"/v1/admin/users/{_seg(user)}/delete", {})


def _options(options: dict) -> dict:
    allowed = {"ttl", "views", "confirmed", "recipients", "recipientGroups", "responsible", "responsibleGroups", "comment"}
    unknown = set(options) - allowed
    if unknown:
        raise TypeError(f"unknown option(s): {', '.join(sorted(unknown))}")
    return {k: v for k, v in options.items() if v is not None}
