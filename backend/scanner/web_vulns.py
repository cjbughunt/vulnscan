"""Active, low-risk injection heuristics against discovered parameters and forms.

These are detection probes, not exploits: they inject benign markers and look for
reflected output, SQL error signatures, or redirect behavior. Non-destructive.
"""
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

XSS_MARKER = "vsx9z1k7q"
XSS_PAYLOAD = f"<{XSS_MARKER}>"
SQLI_PAYLOAD = "'"
REDIRECT_PAYLOAD = "https://example.org/vulnscan-probe"

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query():", "psql: error", "sqlite3.operationalerror",
    "ora-01756", "sqlstate[", "odbc sql server driver",
]

REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_uri", "return", "returnurl",
                   "dest", "destination", "continue", "goto", "r", "u"}


def _with_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[key] = [value]
    flat = urlencode({k: v[-1] for k, v in qs.items()})
    return urlunparse(p._replace(query=flat))


async def run(ctx):
    if not ctx.opts.get("active_web_tests", True):
        ctx.log("Active web tests disabled; skipping injection heuristics")
        return
    ctx.log("Web vulns: testing parameters for reflection / SQL errors / open redirect")

    # ---- GET parameters ----
    for url, params in ctx.params_urls:
        for key in params:
            await _test_param_get(ctx, url, key)

    # ---- Forms ----
    for form in ctx.forms:
        await _test_form(ctx, form)


async def _test_param_get(ctx, url, key):
    # Reflected XSS marker.
    try:
        r = await ctx.get(_with_param(url, key, XSS_PAYLOAD))
        if XSS_PAYLOAD in r.text:
            ctx.report(
                "high", f"Reflected input (possible XSS) in '{key}'",
                category="injection", location=url,
                description=f"The parameter '{key}' is reflected unencoded in the response, "
                            "indicating a likely cross-site scripting vector.",
                evidence=f"Injected {XSS_PAYLOAD} and it appeared verbatim in the HTML.",
                remediation="Context-aware output encoding and input validation.",
            )
    except Exception:
        pass

    # Error-based SQLi.
    try:
        base = await ctx.get(_with_param(url, key, "1"))
        inj = await ctx.get(_with_param(url, key, "1" + SQLI_PAYLOAD))
        found = _sql_error(inj.text) and not _sql_error(base.text)
        if found:
            ctx.report(
                "high", f"SQL error signature in '{key}'",
                category="injection", location=url,
                description=f"Injecting a single quote into '{key}' produced a database error, "
                            "indicating possible SQL injection.",
                evidence=found,
                remediation="Use parameterized queries / prepared statements.",
            )
    except Exception:
        pass

    # Open redirect.
    if key.lower() in REDIRECT_PARAMS:
        try:
            r = await ctx.get(_with_param(url, key, REDIRECT_PAYLOAD), follow=False)
            loc = r.headers.get("location", "")
            if loc.startswith(REDIRECT_PAYLOAD) or loc == REDIRECT_PAYLOAD:
                ctx.report(
                    "medium", f"Open redirect via '{key}'",
                    category="redirect", location=url,
                    description=f"The '{key}' parameter redirects to an attacker-controlled URL.",
                    evidence=f"Location: {loc}",
                    remediation="Allow-list redirect destinations; reject absolute external URLs.",
                )
        except Exception:
            pass


async def _test_form(ctx, form):
    fields = {f["name"]: "1" for f in form["fields"]
              if f["type"] not in ("submit", "button", "hidden", "file")}
    if not fields:
        return
    target = form["action"]
    method = form["method"]

    # XSS via first text-like field.
    data = dict(fields)
    first = next(iter(data))
    data[first] = XSS_PAYLOAD
    try:
        if method == "POST":
            r = await ctx.request("POST", target, data=data)
        else:
            r = await ctx.get(_with_param(target, first, XSS_PAYLOAD))
        if XSS_PAYLOAD in r.text:
            ctx.report(
                "high", f"Reflected input in form field '{first}'",
                category="injection", location=target,
                description=f"Form field '{first}' ({method} {target}) is reflected unencoded.",
                evidence=f"Injected {XSS_PAYLOAD}; reflected verbatim.",
                remediation="Context-aware output encoding on all user input.",
            )
    except Exception:
        pass

    # SQLi via same field.
    data[first] = "1" + SQLI_PAYLOAD
    try:
        if method == "POST":
            r = await ctx.request("POST", target, data=data)
        else:
            r = await ctx.get(_with_param(target, first, "1" + SQLI_PAYLOAD))
        sig = _sql_error(r.text)
        if sig:
            ctx.report(
                "high", f"SQL error signature in form field '{first}'",
                category="injection", location=target,
                description=f"Form field '{first}' ({method} {target}) triggered a DB error.",
                evidence=sig,
                remediation="Use parameterized queries / prepared statements.",
            )
    except Exception:
        pass


def _sql_error(text: str):
    low = text.lower()
    for sig in SQL_ERRORS:
        if sig in low:
            return sig
    return None
