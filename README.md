# harboor

Small helper CLI to provision nginx hosts and SSL certificates on a server that already has `acme.sh` and nginx installed.

## Installation

```
pip install .
```

## Usage

- Issue certificates (DNS validation): `harboor certs create "example.com,www.example.com" cloudflare`
- Remove certificates and files: `harboor certs revoke example.com`
- Create proxy host: `harboor host create api.example.com -p 8001`
- Create static host and data dir: `harboor host create app.example.com --static`
- Remove host (and static data): `harboor host remove app.example.com --static`

Use `--help` on any command for extra options (paths, reload commands, etc.).
