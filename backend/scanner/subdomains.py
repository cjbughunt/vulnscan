"""Subdomain enumeration via DNS resolution of a wordlist (opt-in).

This only RESOLVES names to discover subdomains; it does not scan them, so the scan's
scope stays on the authorized target. Discovered hosts are reported for the operator to
add to scope if they are authorized to test them.
"""
import asyncio

from . import util

DEFAULT_WORDS = [
    "www", "mail", "webmail", "api", "api-dev", "dev", "development", "staging", "stage",
    "test", "qa", "uat", "admin", "portal", "vpn", "remote", "gateway", "blog", "shop",
    "store", "app", "apps", "m", "mobile", "cdn", "static", "assets", "img", "images",
    "media", "ftp", "sftp", "smtp", "imap", "ns1", "ns2", "dns", "mx", "autodiscover",
    "owa", "exchange", "git", "gitlab", "jenkins", "ci", "jira", "confluence", "wiki",
    "docs", "support", "help", "status", "monitor", "grafana", "kibana", "db", "sql",
    "internal", "intranet", "corp", "beta", "demo", "sandbox", "secure", "login", "auth",
    "sso", "id", "account", "my", "dashboard", "panel", "cpanel", "phpmyadmin", "adminer",
    "old", "new", "v1", "v2", "staging-api", "preprod",
]


def _registrable(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


async def run(ctx):
    if not ctx.opts.get("subdomain_enum"):
        return
    base = _registrable(ctx.scope.host)
    words = ctx.opts.get("subdomain_wordlist") or DEFAULT_WORDS
    ctx.log(f"Subdomains: resolving {len(words)} candidate names under {base}")

    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(20)

    async def check(word):
        host = f"{word}.{base}"
        async with sem:
            ips = await loop.run_in_executor(None, util.resolve, host)
        return (host, ips) if ips else None

    results = await asyncio.gather(*(check(w) for w in words))
    found = [r for r in results if r]

    if not found:
        ctx.log("Subdomains: none resolved")
        return

    evidence = "\n".join(f"{h}  ->  {', '.join(ips)}" for h, ips in sorted(found))
    ctx.report(
        "info", f"Subdomains discovered ({len(found)})",
        category="recon", location=base,
        description="DNS resolution found the following subdomains. Only scan those you are "
                    "authorized to test; add them as separate targets.",
        evidence=evidence,
        remediation="Review exposed subdomains; decommission or protect unneeded ones.",
    )
    ctx.log(f"Subdomains: {len(found)} resolved")
