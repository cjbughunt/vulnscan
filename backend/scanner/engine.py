"""Scan orchestrator: runs each stage against an authorized target with a shared context."""
import asyncio
import httpx

from .. import db
from . import (util, recon, tls_checks, http_checks, crawler, web_vulns, external,
               auth as auth_mod, cors_checks, ssrf_checks, jwt_checks, subdomains)

USER_AGENT = "VulnScan/1.0 (authorized security assessment)"


class ScanContext:
    """Shared state + throttled HTTP helpers passed to every stage."""

    def __init__(self, scan_id, base_url, scope, client, opts, ips):
        self.scan_id = scan_id
        self.base_url = base_url
        self.final_url = base_url
        self.scope = scope
        self.client = client
        self.opts = opts
        self.ips = ips
        # Collected during the scan.
        self.seeds = set()
        self.pages = []
        self.forms = []
        self.params_urls = []
        self.logout_patterns = list(opts.get("logout_patterns") or auth_mod.LOGOUT_DEFAULT)
        self._sem = asyncio.Semaphore(int(opts.get("concurrency", 6)))
        self._delay = float(opts.get("delay", 0.0))
        self._seen = set()

    # ---- reporting ----
    def report(self, severity, title, **kw):
        key = (title, kw.get("location"))
        if key in self._seen:
            return
        self._seen.add(key)
        db.add_finding(self.scan_id, severity, title, **kw)

    def log(self, message, level="info"):
        db.add_log(self.scan_id, message, level)

    # ---- throttled HTTP ----
    async def get(self, url, follow=True):
        return await self.request("GET", url, follow=follow)

    async def request(self, method, url, follow=True, **kw):
        # Enforce scope on every outbound request.
        if not self.scope.in_scope(url):
            raise ValueError(f"Refusing out-of-scope request: {url}")
        async with self._sem:
            if self._delay:
                await asyncio.sleep(self._delay)
            return await self.client.request(method, url, follow_redirects=follow, **kw)


# Stages run in order; progress is assigned evenly across whatever is enabled.
def _stages(opts):
    s = [("recon", recon.run), ("tls", tls_checks.run), ("http-checks", http_checks.run)]
    if opts.get("subdomain_enum"):
        s.append(("subdomains", subdomains.run))
    s += [
        ("crawl", crawler.run),
        ("web-vulns", web_vulns.run),
        ("cors", cors_checks.run),
        ("ssrf", ssrf_checks.run),
        ("jwt", jwt_checks.run),
    ]
    if opts.get("use_nmap", True):
        s.append(("nmap", external.run_nmap))
    if opts.get("use_nuclei", True):
        s.append(("nuclei", external.run_nuclei))
    n = len(s)
    return [(label, fn, min(98, int(10 + (i + 1) * (88 / n))))
            for i, (label, fn) in enumerate(s)]


async def run_scan(scan_id: int, auth: dict | None = None):
    scan = db.get_scan(scan_id)
    if not scan:
        return
    if not scan["authorized"]:
        db.update_scan(scan_id, status="refused",
                       error="Scan not authorized: target scope was not confirmed.")
        db.add_log(scan_id, "Refused: authorization flag not set.", "error")
        return

    import json
    opts = json.loads(scan["options"] or "{}")
    base_url = scan["target"]
    host = scan["host"]

    db.update_scan(scan_id, status="running", started_at=db.now(), progress=2,
                   current_stage="init")
    db.add_log(scan_id, f"Authorized scan of {base_url} (confirmed by "
                        f"{scan['authorized_by'] or 'operator'}) starting.")

    # Scope + safety: block internal/metadata targets unless explicitly allowed.
    ips = util.resolve(host)
    if util.metadata_host(host, ips):
        db.update_scan(scan_id, status="refused",
                       error="Refusing to scan a cloud metadata endpoint.")
        db.add_log(scan_id, "Refused: metadata endpoint.", "error")
        return
    if not opts.get("allow_private", False) and ips and all(
        util.is_private_or_reserved(ip) for ip in ips
    ):
        db.update_scan(scan_id, status="refused",
                       error="Target resolves only to private/reserved IPs. "
                             "Enable 'allow internal targets' to scan it.")
        db.add_log(scan_id, f"Refused: private IPs {ips}.", "error")
        return

    scope = util.Scope(base_url, allow_private=opts.get("allow_private", False))
    limits = httpx.Limits(max_connections=int(opts.get("concurrency", 6)))
    timeout = httpx.Timeout(float(opts.get("http_timeout", 15)))
    headers = {"User-Agent": USER_AGENT}

    try:
        async with httpx.AsyncClient(
            verify=False, headers=headers, limits=limits, timeout=timeout,
            follow_redirects=False,
        ) as client:
            ctx = ScanContext(scan_id, base_url, scope, client, opts, ips)

            # Authenticated scanning: configure the session before any stage runs.
            if auth and (auth.get("type") or "none") != "none":
                db.update_scan(scan_id, current_stage="auth")
                status = await auth_mod.authenticate(ctx, auth)
                if status.get("ok"):
                    ctx.report(
                        "info", f"Authenticated scan ({status['type']})",
                        category="auth", location=base_url,
                        description="Scan is running with an authenticated session; "
                                    "findings include content behind the login.",
                        evidence=status.get("detail", ""),
                    )
                else:
                    ctx.report(
                        "medium", f"Authentication failed ({status.get('type')})",
                        category="auth", location=base_url,
                        description="The configured authentication did not succeed; results "
                                    "likely reflect the UNauthenticated surface only.",
                        evidence=status.get("error") or status.get("detail", ""),
                        remediation="Check credentials, login URL, field names, or session cookie.",
                    )

            for label, fn, progress in _stages(opts):
                db.update_scan(scan_id, current_stage=label)
                db.add_log(scan_id, f"Stage: {label}")
                try:
                    await fn(ctx)
                except Exception as e:
                    db.add_log(scan_id, f"Stage {label} error: {e}", "error")
                db.update_scan(scan_id, progress=progress)
        db.update_scan(scan_id, status="completed", progress=100,
                       current_stage="done", finished_at=db.now())
        db.add_log(scan_id, "Scan completed.")
    except Exception as e:
        db.update_scan(scan_id, status="error", error=str(e), finished_at=db.now())
        db.add_log(scan_id, f"Scan failed: {e}", "error")
