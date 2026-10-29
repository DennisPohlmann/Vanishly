# Amazon Cognito

`AUTH_PROVIDER=cognito`. Issuer:
`https://cognito-idp.<region>.amazonaws.com/<user pool id>`.

## Sign-in app client

1. In the user pool: **App integration → App clients → Create**:
   **Confidential client**, with a client secret.
2. **Managed login / Hosted UI**: a domain for the pool; allowed callback
   URL `https://ots.example.com/auth/callback`; OAuth grant
   **Authorization code**; scopes `openid`, `profile`, `email`.
3. Users need a verified `email` attribute.

## Groups

Cognito puts the user's groups into `cognito:groups`, the preset's
default. `RECIPIENT_GROUPS=Finance=finance,IT=it` (the group names), or
`*` with the directory.

## Directory (search)

An IAM identity with this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["cognito-idp:ListUsersInGroup", "cognito-idp:ListGroups"],
    "Resource": "arn:aws:cognito-idp:<region>:<account>:userpool/<user pool id>"
  }]
}
```

Credentials come from the standard AWS variables: `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` (`AWS_SESSION_TOKEN` too for temporary keys), or on
EKS with IAM roles for service accounts `AWS_ROLE_ARN` and
`AWS_WEB_IDENTITY_TOKEN_FILE`, which EKS sets itself. Instance profiles
and the shared credentials file are not read.

`RECIPIENT_USER_GROUP` is the name of the group whose members the form
suggests.

## API tokens

Cognito access tokens carry no `aud` and no e-mail address. With
`AUTH_API_AUDIENCE=<app client id>` Vanishly accepts them (it checks
`client_id` and `token_use: access`), but treats them like app tokens:
they can create secrets, not open restricted ones.

## Example (`.env` or Compose)

Required: `AUTH_PROVIDER`, `BASE_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET` (or `_FILE`) and `AUTH_SECRET` (or `_FILE`). The
same lines go into `.env` next to `docker-compose.yml`
([docker-compose/standalone](../../docker-compose/standalone/docker-compose.yml))
or into its `environment:` block.

```bash
AUTH_PROVIDER=cognito
BASE_URL=https://ots.example.com
OIDC_ISSUER=https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_Example
OIDC_CLIENT_ID=change-me
OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc_client_secret
AUTH_SECRET_FILE=/run/secrets/auth_secret
RECIPIENT_GROUPS=*
DIRECTORY_API=true
RECIPIENT_USER_GROUP=staff
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, or the EKS role variables
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Start stops: `DIRECTORY_API=true with AUTH_PROVIDER=cognito needs AWS credentials` | Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, or the EKS role variables |
| Log `auth: people search failed: Cognito answered 400` | The IAM policy lacks `ListUsersInGroup` / `ListGroups` for this pool, or the group name is wrong |
| Log `auth: people search failed: STS answered 403` | The role cannot be assumed with the web identity token (trust policy) |
| Sign-in refused: no e-mail address | The user's `email` attribute is not verified, or the app client lacks the `email` scope |

General problems: [providers/README.md](README.md#troubleshooting).
