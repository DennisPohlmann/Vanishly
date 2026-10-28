# Own templates (docker compose)

`docker-compose.yml` mounts this folder at `/var/lib/vanishly/templates`.
Put a template folder here (copy `../templates/default`, rename it), then set
`TEMPLATE=<folder name>` in `.env` and restart: `docker compose up -d`.
See [templates/README.md](../templates/README.md).
