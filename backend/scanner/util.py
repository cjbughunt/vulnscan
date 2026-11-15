"""Shared helpers: target normalization and scope enforcement."""
import ipaddress
import socket
from urllib.parse import urlparse, urljoin

# Hosts that must never be scanned even if the user types them, to avoid
# accidentally hammering loopback/metadata/internal ranges unless explicitly allowed.
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal"}


def normalize_target(raw: str) -> str:
    """Turn user input into a canonical base URL (defaults to https)."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty target")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname:
        raise ValueError(f"Could not parse a host from: {raw!r}")
    if p.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {p.scheme}")
    port = f":{p.port}" if p.port else ""
    path = p.path or "/"
    return f"{p.scheme}://{p.hostname}{port}{path}"


def target_host(url: str) -> str:
    return urlparse(url).hostname or ""


def resolve(host: str):
    """Resolve host -> list of IPs. Returns [] on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return []


def is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def metadata_host(host: str, ips) -> bool:
    if host in _METADATA_HOSTS:
        return True
    return any(ip in _METADATA_HOSTS for ip in ips)


class Scope:
    """Keeps every request on the authorized host and (optionally) off internal IPs."""

    def __init__(self, base_url: str, allow_private: bool = False):
        self.base_url = base_url
        self.host = target_host(base_url)
        self.allow_private = allow_private

    def in_scope(self, url: str) -> bool:
        try:
            h = urlparse(url).hostname
        except Exception:
            return False
        if not h:
            return False
        # same host, or subdomain of the target host
        return h == self.host or h.endswith("." + self.host)

    def resolve_url(self, link: str, current_url: str) -> str | None:
        """Resolve a possibly-relative link against current_url; None if out of scope."""
        if not link:
            return None
        link = link.strip()
        if link.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            return None
        full = urljoin(current_url, link)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            return None
        return full if self.in_scope(full) else None
