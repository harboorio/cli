from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List

import click

from .templates import PROXY_TEMPLATE, STATIC_TEMPLATE

DEFAULT_CONF_DIR = "/etc/nginx/conf.d"
DEFAULT_SSL_DIR = "/etc/nginx/ssl"
DEFAULT_DATA_ROOT = "/usr/share/nginx"


def _run_command(command: List[str]) -> None:
    """Execute a shell command and raise a friendly error when it fails."""
    click.echo(f"$ {' '.join(shlex.quote(part) for part in command)}")
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        raise click.ClickException(f"Command not found: {command[0]}")
    except subprocess.CalledProcessError as exc:
        raise click.ClickException(f"Command failed with exit code {exc.returncode}")


def _replace_placeholders(template: str, mapping: dict[str, str]) -> str:
    rendered = template
    for key, value in mapping.items():
        rendered = rendered.replace(f"__{key}__", value)
    return rendered


def _slugify_upstream(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9]+", "_", name)
    return safe.strip("_") or "upstream"


def _parse_domains(raw: str) -> List[str]:
    domains = [part.strip() for part in raw.replace(",", " ").split() if part.strip()]
    if not domains:
        raise click.ClickException("At least one domain is required.")
    return domains


def _unique_names(primary: str, aliases: Iterable[str]) -> List[str]:
    seen = set()
    names: List[str] = []
    for name in [primary, *aliases]:
        if name and name not in seen:
            names.append(name)
            seen.add(name)
    return names


def _render_proxy_config(
    primary_domain: str,
    server_names: list[str],
    ssl_dir: str,
    upstream_host: str,
    upstream_port: int,
) -> str:
    upstream_name = _slugify_upstream(primary_domain)
    mapping = {
        "SERVER_NAMES": " ".join(server_names),
        "PRIMARY_DOMAIN": primary_domain,
        "SSL_DIR": ssl_dir,
        "UPSTREAM_NAME": upstream_name,
        "UPSTREAM_HOST": upstream_host,
        "UPSTREAM_PORT": str(upstream_port),
    }
    return _replace_placeholders(PROXY_TEMPLATE, mapping)


def _render_static_config(
    primary_domain: str,
    server_names: list[str],
    ssl_dir: str,
    static_root: Path,
) -> str:
    mapping = {
        "SERVER_NAMES": " ".join(server_names),
        "PRIMARY_DOMAIN": primary_domain,
        "SSL_DIR": ssl_dir,
        "STATIC_ROOT": str(static_root),
    }
    return _replace_placeholders(STATIC_TEMPLATE, mapping)


def _write_config(path: Path, content: str, force: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        raise click.ClickException(f"{path} already exists. Use --force to overwrite.")
    path.write_text(content)
    click.echo(f"Wrote nginx config: {path}")


def _ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    click.echo(f"Ensured directory: {path}")


def _remove_path(path: Path) -> None:
    if path.is_file():
        path.unlink()
        click.echo(f"Removed file: {path}")
    elif path.is_dir():
        shutil.rmtree(path)
        click.echo(f"Removed directory: {path}")
    else:
        click.echo(f"Nothing to remove at {path}")


@click.group()
def harboor() -> None:
    """Harboor: small helper CLI for nginx hosts and certificates."""


@harboor.group()
def certs() -> None:
    """Manage SSL certificates via acme.sh."""


@certs.command("create")
@click.argument("domains")
@click.argument("dns_provider")
@click.option(
    "--acme-bin",
    default="acme.sh",
    show_default=True,
    help="Path to the acme.sh executable.",
)
@click.option(
    "--ssl-dir",
    default=DEFAULT_SSL_DIR,
    show_default=True,
    help="Base directory where certificates will be installed.",
)
@click.option(
    "--dnssleep",
    default=120,
    show_default=True,
    help="Seconds acme.sh should wait for DNS propagation.",
)
@click.option(
    "--reload-cmd",
    default="service nginx force-reload",
    show_default=True,
    help="Command run by acme.sh after installing certificates.",
)
def create_certs(
    domains: str,
    dns_provider: str,
    acme_bin: str,
    ssl_dir: str,
    dnssleep: int,
    reload_cmd: str,
) -> None:
    """
    Issue and install certificates for DOMAINS using DNS_PROVIDER.

    DOMAINS can be a comma or space separated list (primary first).
    """

    domain_list = _parse_domains(domains)
    primary_domain, *extra_domains = domain_list

    domain_args = [flag for domain in domain_list for flag in ("-d", domain)]
    _run_command(
        [
            acme_bin,
            "--issue",
            *domain_args,
            "--dns",
            dns_provider,
            "--dnssleep",
            str(dnssleep),
        ]
    )

    target_dir = Path(ssl_dir) / primary_domain
    target_dir.mkdir(parents=True, exist_ok=True)
    _run_command(
        [
            acme_bin,
            "--install-cert",
            "-d",
            primary_domain,
            "--key-file",
            str(target_dir / "key.pem"),
            "--fullchain-file",
            str(target_dir / "fullchain.pem"),
            "--reloadcmd",
            reload_cmd,
        ]
    )

    click.echo(f"Certificates installed under {target_dir}")
    if extra_domains:
        click.echo(f"Extra domains: {', '.join(extra_domains)}")


@certs.command("revoke")
@click.argument("domain")
@click.option(
    "--acme-bin",
    default="acme.sh",
    show_default=True,
    help="Path to the acme.sh executable.",
)
@click.option(
    "--ssl-dir",
    default=DEFAULT_SSL_DIR,
    show_default=True,
    help="Base directory where certificates are stored.",
)
@click.option(
    "--purge/--keep",
    default=True,
    help="Remove files under the SSL directory after revocation.",
)
def revoke_cert(domain: str, acme_bin: str, ssl_dir: str, purge: bool) -> None:
    """Revoke and remove certificates for DOMAIN."""

    _run_command([acme_bin, "--remove", "-d", domain])
    if purge:
        _remove_path(Path(ssl_dir) / domain)


@harboor.group()
def host() -> None:
    """Manage nginx host definitions."""


@host.command("create")
@click.argument("domain")
@click.option(
    "-a",
    "--alias",
    "aliases",
    multiple=True,
    help="Additional domain aliases for the server_name directive.",
)
@click.option(
    "--static/--proxy",
    "is_static",
    default=False,
    help="Create a static host instead of a proxy host.",
)
@click.option(
    "-p",
    "--port",
    default=8000,
    show_default=True,
    help="Upstream port for proxy hosts.",
)
@click.option(
    "--upstream-host",
    default="127.0.0.1",
    show_default=True,
    help="Upstream host for proxy hosts.",
)
@click.option(
    "--conf-dir",
    default=DEFAULT_CONF_DIR,
    show_default=True,
    help="Where nginx .conf files are written.",
)
@click.option(
    "--ssl-dir",
    default=DEFAULT_SSL_DIR,
    show_default=True,
    help="Base directory where certificates are installed.",
)
@click.option(
    "--data-root",
    default=DEFAULT_DATA_ROOT,
    show_default=True,
    help="Base directory for static host data (only used with --static).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing nginx configuration file.",
)
def create_host(
    domain: str,
    aliases: Iterable[str],
    is_static: bool,
    port: int,
    upstream_host: str,
    conf_dir: str,
    ssl_dir: str,
    data_root: str,
    force: bool,
) -> None:
    """Create an nginx config for DOMAIN."""

    server_names = _unique_names(domain, aliases)
    config_path = Path(conf_dir) / f"{domain}.conf"

    if is_static:
        static_root = Path(data_root) / domain / "latest"
        _ensure_directory(static_root)
        content = _render_static_config(domain, server_names, ssl_dir, static_root)
    else:
        content = _render_proxy_config(
            domain, server_names, ssl_dir, upstream_host, port
        )

    _write_config(config_path, content, force)


@host.command("remove")
@click.argument("domain")
@click.option(
    "--static/--proxy",
    "is_static",
    default=False,
    help="Remove static data directories in addition to the nginx config.",
)
@click.option(
    "--conf-dir",
    default=DEFAULT_CONF_DIR,
    show_default=True,
    help="Where nginx .conf files are stored.",
)
@click.option(
    "--data-root",
    default=DEFAULT_DATA_ROOT,
    show_default=True,
    help="Base directory for static host data.",
)
@click.option(
    "--purge-data/--keep-data",
    default=True,
    help="Remove the static data directory when using --static.",
)
def remove_host(
    domain: str, is_static: bool, conf_dir: str, data_root: str, purge_data: bool
) -> None:
    """Remove nginx config (and optionally static data) for DOMAIN."""

    config_path = Path(conf_dir) / f"{domain}.conf"
    if config_path.exists():
        _remove_path(config_path)
    else:
        click.echo(f"No nginx config found at {config_path}")

    if is_static and purge_data:
        _remove_path(Path(data_root) / domain)


def main() -> None:
    harboor(prog_name="harboor")


if __name__ == "__main__":
    main()
