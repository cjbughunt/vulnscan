"""Passive/low-touch HTTP checks: security headers, cookies, methods, exposed files."""
from urllib.parse import urljoin

SECURITY_HEADERS = {
    "strict-transport-security": (
        "medium", "Missing HSTS header",
        "Without Strict-Transport-Security, browsers may connect over HTTP, enabling downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "content-security-policy": (
        "medium", "Missing Content-Security-Policy",
        "No CSP means fewer defenses against XSS and data-injection attacks.",
        "Define a restrictive Content-Security-Policy.",
    ),
    "x-frame-options": (
        "low", "Missing X-Frame-Options / frame-ancestors",
        "The page may be framed by other sites, enabling clickjacking.",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
    ),
    "x-content-type-options": (
        "low", "Missing X-Content-Type-Options",
        "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
        "Set X-Content-Type-Options: nosniff",
    ),
    "referrer-policy": (
        "info", "Missing Referrer-Policy",
        "Referrer data may leak to third parties.",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
}

# Common sensitive files. Checked with GET; only flagged when clearly present.
SENSITIVE_PATHS = [
    (".env", "high", "Environment file"),
    (".git/config", "high", "Exposed .git repository"),
    (".git/HEAD", "high", "Exposed .git repository"),
    ("config.php.bak", "high", "Backup source file"),
    ("wp-config.php.bak", "high", "WordPress config backup"),
    ("backup.zip", "medium", "Backup archive"),
    ("backup.sql", "high", "Database dump"),
    ("db.sql", "high", "Database dump"),
    (".DS_Store", "low", "macOS directory metadata"),
    ("phpinfo.php", "medium", "phpinfo() exposure"),
    (".svn/entries", "medium", "Exposed .svn metadata"),
    ("server-status", "medium", "Apache server-status"),
    (".htaccess", "low", "Exposed .htaccess"),
]


async def run(ctx):
    url = getattr(ctx, "final_url", ctx.base_url)
    ctx.log("HTTP: checking security headers and cookies")
    try:
        resp = await ctx.get(url)
    except Exception as e:
        ctx.log(f"Header check skipped: {e}", "warn")
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    csp = headers.get("content-security-policy", "")

    for h, (sev, title, desc, fix) in SECURITY_HEADERS.items():
        if h == "x-frame-options" and "frame-ancestors" in csp:
            continue
        if h not in headers:
            ctx.report(sev, title, category="headers", location=url,
                       description=desc, remediation=fix)

    # Cookie flags.
    for raw in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") \
            else [resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = [f for f in ("httponly", "secure") if f not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            ctx.report(
                "low", f"Cookie '{name}' missing flags: {', '.join(missing)}",
                category="cookies", location=url,
                description="Cookies without HttpOnly/Secure/SameSite are more exposed to theft and CSRF.",
                evidence=raw[:200],
                remediation="Set HttpOnly, Secure, and SameSite on session cookies.",
            )

    # Dangerous HTTP methods.
    try:
        opt = await ctx.request("OPTIONS", url)
        allow = opt.headers.get("allow", "")
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
        if risky:
            ctx.report(
                "medium", f"Risky HTTP methods allowed: {', '.join(risky)}",
                category="http-methods", location=url,
                description="The server advertises state-changing or debug HTTP methods.",
                evidence=f"Allow: {allow}",
                remediation="Disable unused HTTP methods (PUT/DELETE/TRACE/CONNECT).",
            )
    except Exception:
        pass

    # Sensitive file probing (bounded; non-destructive GETs).
    if ctx.opts.get("check_sensitive_files", True):
        ctx.log("HTTP: probing for exposed sensitive files")
        # Soft-404 baseline: many servers return 200 + a page for unknown paths.
        # Fetch a random non-existent path and use it to reject false positives.
        baseline_len = None
        try:
            import random, string
            rand = "zzz-" + "".join(random.choices(string.ascii_lowercase, k=12)) + ".nope"
            br = await ctx.get(urljoin(ctx.base_url, rand))
            if br.status_code == 200:
                baseline_len = len(br.content)
                ctx.log(f"HTTP: soft-404 detected (unknown paths return 200, "
                        f"{baseline_len} bytes); filtering file findings")
        except Exception:
            pass

        for path, sev, label in SENSITIVE_PATHS:
            full = urljoin(ctx.base_url, path)
            try:
                r = await ctx.get(full)
            except Exception:
                continue
            if r.status_code != 200 or not r.content or _looks_like_404(r):
                continue
            # If the server soft-404s, only flag responses clearly different
            # from the baseline (>15% size delta), else it's almost certainly noise.
            if baseline_len is not None:
                delta = abs(len(r.content) - baseline_len)
                if delta <= max(40, baseline_len * 0.15):
                    continue
            ctx.report(
                sev, f"{label} exposed: /{path}",
                category="exposure", location=full,
                description=f"A sensitive resource ({label}) is publicly accessible.",
                evidence=r.text[:400],
                remediation="Remove the file from the web root or block access to it.",
            )

    # Directory listing.
    try:
        r = await ctx.get(ctx.base_url)
        if "Index of /" in r.text and "<title>Index of" in r.text:
            ctx.report("low", "Directory listing enabled",
                       category="exposure", location=ctx.base_url,
                       description="The server returns an auto-generated directory index.",
                       remediation="Disable directory listing (e.g. Options -Indexes).")
    except Exception:
        pass


def _looks_like_404(resp) -> bool:
    t = resp.text.lower()
    return "not found" in t[:600] or "404" in (resp.headers.get("x-error", ""))
