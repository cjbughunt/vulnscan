"""TLS/certificate inspection (non-intrusive, read-only handshake checks)."""
import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def _blocking_tls(host: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return {
                "version": ssock.version(),
                "cipher": ssock.cipher(),
                "cert": ssock.getpeercert(binary_form=False) or {},
                "cert_der": ssock.getpeercert(binary_form=True),
            }


def _blocking_proto(host: str, port: int, proto) -> bool:
    """Return True if the server accepts a deprecated protocol version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = proto
        ctx.maximum_version = proto
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


async def run(ctx):
    p = urlparse(ctx.base_url)
    if p.scheme != "https":
        ctx.report(
            "medium", "Service not served over HTTPS",
            category="transport", location=ctx.base_url,
            description="The base URL uses plain HTTP; traffic can be read or modified in transit.",
            remediation="Serve the site exclusively over HTTPS and redirect HTTP to HTTPS.",
        )
        return

    host = p.hostname
    port = p.port or 443
    ctx.log("TLS: inspecting certificate and protocols")
    loop = asyncio.get_event_loop()
    try:
        info = await loop.run_in_executor(None, _blocking_tls, host, port)
    except Exception as e:
        ctx.log(f"TLS handshake failed: {e}", "warn")
        ctx.report("medium", "TLS handshake failed",
                   category="transport", location=ctx.base_url,
                   description=f"Could not complete a TLS handshake: {e}")
        return

    cert = info["cert"]
    ver = info["version"]
    cipher = info["cipher"][0] if info["cipher"] else "?"

    ctx.report(
        "info", "TLS configuration",
        category="transport", location=ctx.base_url,
        description=f"Negotiated {ver} with cipher {cipher}.",
        evidence=f"Protocol: {ver}\nCipher: {cipher}",
    )

    # Certificate expiry.
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                ctx.report("high", "TLS certificate expired",
                           category="transport", location=ctx.base_url,
                           description=f"The certificate expired {abs(days)} days ago.",
                           evidence=f"notAfter: {not_after}",
                           remediation="Renew the TLS certificate immediately.")
            elif days < 21:
                ctx.report("medium", "TLS certificate expiring soon",
                           category="transport", location=ctx.base_url,
                           description=f"The certificate expires in {days} days.",
                           evidence=f"notAfter: {not_after}",
                           remediation="Renew/automate certificate renewal.")
        except ValueError:
            pass

    # Deprecated protocol support.
    for label, proto in (("TLS 1.0", ssl.TLSVersion.TLSv1),
                         ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            accepted = await loop.run_in_executor(None, _blocking_proto, host, port, proto)
        except Exception:
            accepted = False
        if accepted:
            ctx.report(
                "medium", f"Deprecated protocol {label} supported",
                category="transport", location=ctx.base_url,
                description=f"The server negotiates {label}, which is deprecated and insecure.",
                remediation="Disable TLS 1.0/1.1; require TLS 1.2 or higher.",
            )
