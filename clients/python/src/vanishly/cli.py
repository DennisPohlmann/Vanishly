"""vanishly - command line client. End-to-end encrypted by default: the
secret and the key never reach the server. Same commands as the vanishly
binary of the Go client."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys

from . import __version__
from .client import ApiError, Client, parse_link
from .crypto import DecryptError

_RECEIPT = re.compile(r"^(https?://[^#]+?)/r/([A-Za-z0-9_-]{22})(?:#.*)?$")
_SECRET = re.compile(r"^(https?://[^#]+?)/s/([A-Za-z0-9_-]{22})(?:#.*)?$")

HELP = """examples:
  export VANISHLY_URL=https://ots.example.com
  vanishly share --ttl 3600 --views 1       # asks for the secret
  vanishly share --ttl 3600 < secret.txt
  vanishly open 'https://ots.example.com/s/<id>#<key>'
  vanishly status 'https://ots.example.com/r/<receipt id>'
  vanishly api GET /v1/me/secrets --query limit=10

environment: VANISHLY_URL, VANISHLY_TOKEN, VANISHLY_PASSPHRASE"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vanishly", description="Vanishly client: one-time secrets, end-to-end encrypted.",
                                epilog=HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=os.environ.get("VANISHLY_URL"), help="server, e.g. https://ots.example.com (VANISHLY_URL)")
    p.add_argument("--token", default=os.environ.get("VANISHLY_TOKEN"), help="API token vnly_... (VANISHLY_TOKEN)")
    p.add_argument("--json", action="store_true", help="print the whole answer as JSON")
    p.add_argument("--run-id", help="X-Run-Id for the audit log")
    p.add_argument("--audit-comment", help="X-Audit-Comment for the audit log")
    p.add_argument("--on-behalf-of", help="X-On-Behalf-Of for the audit log")
    p.add_argument("--version", action="version", version=f"vanishly {__version__} (python)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def passphrase(sp):
        g = sp.add_mutually_exclusive_group()
        g.add_argument("--passphrase", help="the passphrase (visible in the process list: prefer --ask or VANISHLY_PASSPHRASE)")
        g.add_argument("--passphrase-file", help="read the passphrase from this file")
        g.add_argument("--ask", action="store_true", help="ask for the passphrase")

    s = sub.add_parser("share", help="encrypt here and store a secret; prints the link")
    s.add_argument("secret", nargs="?", default="-", help="the secret; - or nothing: asked for on a terminal (no echo), else read from standard input")
    passphrase(s)
    s.add_argument("--ttl", type=int, help="seconds until it expires")
    s.add_argument("--views", type=int, help="how often it can be opened")
    s.add_argument("--recipient", action="append", help="who may open it (sign-in), repeatable")
    s.add_argument("--recipient-group", action="append", help="group that may open it, repeatable")
    s.add_argument("--responsible", action="append", help="responsible person, repeatable")
    s.add_argument("--responsible-group", action="append", help="responsible group, repeatable")
    s.add_argument("--comment", help="what the secret is for (AUDIT_COMMENT)")
    s.add_argument("--confirm", action="store_true", help='send "confirmed": true (CONFIRM_CHECKBOX)')
    s.add_argument("--server-side", action="store_true", help="let the server encrypt (POST /v1/share, ENABLE_SERVER_CREATE)")

    o = sub.add_parser("open", help="open a link: takes one view, decrypts here")
    o.add_argument("link")
    passphrase(o)
    o.add_argument("--server-side", action="store_true", help="let the server decrypt (POST /v1/open, ENABLE_SERVER_OPEN)")

    for name, text in (("meta", "state of a secret without using a view"), ("status", "status of a secret for its sender"),
                       ("burn", "destroy a secret now")):
        c = sub.add_parser(name, help=text)
        c.add_argument("ref", help="the link (secret link for meta, status link for status and burn) or the id")

    for name, text in (("config", "limits and options of the server"), ("me", "who is signed in"),
                       ("downloads", "the clients the server offers, with checksums")):
        sub.add_parser(name, help=text)

    a = sub.add_parser("api", help="any API call, e.g. api GET /v1/tokens")
    a.add_argument("method")
    a.add_argument("path", help="below /api, e.g. /v1/admin/audit")
    a.add_argument("--data", help="JSON body; @file reads it from a file, - from standard input")
    a.add_argument("--query", action="append", default=[], help="key=value, repeatable")
    return p


def _read_passphrase(args) -> str:
    if getattr(args, "passphrase", None):
        return args.passphrase
    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, encoding="utf-8") as f:
            return f.read().rstrip("\r\n")
    if getattr(args, "ask", False):
        return getpass.getpass("Passphrase: ")
    return os.environ.get("VANISHLY_PASSPHRASE", "")


def _base_and_id(ref: str, pattern: re.Pattern, url: str | None):
    m = pattern.match(ref.strip())
    if m:
        return m.group(1), m.group(2)
    if re.match(r"^[A-Za-z0-9_-]{22}$", ref):
        if not url:
            raise ValueError("an id needs --url (or VANISHLY_URL)")
        return url, ref
    raise ValueError(f"not a link or id: {ref}")


def _out(args, data, text=None):
    if args.json or text is None:
        print(json.dumps(data, indent=2, ensure_ascii=False) if not isinstance(data, str) else data)
    else:
        print(text)


def run(argv=None) -> int:
    args = _parser().parse_args(argv)
    client = None
    try:
        def make(url):
            nonlocal client
            if not url:
                raise ValueError("no server: use --url or VANISHLY_URL")
            client = Client(url, args.token, run_id=args.run_id, comment=args.audit_comment, on_behalf_of=args.on_behalf_of)
            return client

        if args.cmd == "share":
            if args.secret != "-":
                secret = args.secret
            else:
                # Typed in on a terminal: no echo, not in the shell history.
                secret = getpass.getpass("Secret: ") if sys.stdin.isatty() else sys.stdin.read()
            if not secret:
                raise ValueError("the secret is empty")
            opts = {"ttl": args.ttl, "views": args.views, "recipients": args.recipient,
                    "recipientGroups": args.recipient_group, "responsible": args.responsible,
                    "responsibleGroups": args.responsible_group, "comment": args.comment,
                    "confirmed": True if args.confirm else None}
            c = make(args.url)
            pw = _read_passphrase(args)
            res = c.share(secret, pw, **opts) if args.server_side else c.create(secret, pw, **opts)
            _out(args, res, res["shareUrl"])
            if not args.json and res.get("receiptUrl"):
                print(f"status: {res['receiptUrl']}", file=sys.stderr)
        elif args.cmd == "open":
            base, _sid, _key = parse_link(args.link)
            c = make(base)
            pw = _read_passphrase(args)
            res = c.open_on_server(args.link, pw) if args.server_side else c.open(args.link, pw)
            _out(args, res, res["secret"])
        elif args.cmd == "meta":
            base, sid = _base_and_id(args.ref, _SECRET, args.url)
            _out(args, make(base).secret_meta(sid))
        elif args.cmd in ("status", "burn"):
            base, rid = _base_and_id(args.ref, _RECEIPT, args.url)
            c = make(base)
            _out(args, c.receipt(rid) if args.cmd == "status" else c.burn(rid))
        elif args.cmd in ("config", "me", "downloads"):
            _out(args, getattr(make(args.url), args.cmd)())
        elif args.cmd == "api":
            body = None
            if args.data:
                raw = sys.stdin.read() if args.data == "-" else open(args.data[1:], encoding="utf-8").read() if args.data.startswith("@") else args.data
                body = json.loads(raw)
            query = dict(q.split("=", 1) for q in args.query)
            res = make(args.url).request(args.method, args.path if args.path.startswith("/") else f"/{args.path}", body, query, raw=True)
            print(res)
        return 0
    except ApiError as err:
        print(f"vanishly: {err.status} {err.error}: {err.message}", file=sys.stderr)
        if err.status == 426 and err.body.get("downloadUrl"):
            print(f"vanishly: download a newer client: {err.body['downloadUrl']}", file=sys.stderr)
        return 1
    except (ValueError, DecryptError, OSError) as err:
        print(f"vanishly: {err}", file=sys.stderr)
        return 2 if isinstance(err, ValueError) else 1
    finally:
        if client and client.recommended_version:
            print(f"vanishly: a newer client is recommended ({client.recommended_version}, this is {__version__}): "
                  f"{client.base_url}/downloads", file=sys.stderr)


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
