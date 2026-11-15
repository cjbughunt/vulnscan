"""SSRF surface mapping.

Blind SSRF usually needs an out-of-band (OAST) callback to confirm, which this tool
does not host. So by default it maps the SSRF attack surface: parameters/fields whose
names suggest they take a URL, flagged for manual testing. If the operator supplies an
`ssrf_callback` host (their own Burp Collaborator / interactsh / webhook), probes are
injected pointing at it so hits can be observed out-of-band.
"""
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

URL_PARAM_HINTS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "next", "continue", "return", "returnurl", "callback", "webhook",
    "feed", "rss", "image", "img", "imageurl", "file", "path", "proxy", "fetch",
    "load", "domain", "host", "site", "page", "out", "go", "target", "remote", "to",
}


def _with_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query)
    qs[key] = [value]
    flat = urlencode({k: v[-1] for k, v in qs.items()})
    return urlunparse(p._replace(query=flat))


async def run(ctx):
    # Collect unique URL-like parameter names across query strings and forms.
    sinks = {}  # key -> (example_location, kind)
    for url, params in ctx.params_urls:
        for k in params:
            if k.lower() in URL_PARAM_HINTS:
                sinks.setdefault(k.lower(), (url, "query", url, k))
    for form in ctx.forms:
        for f in form["fields"]:
            if f["name"].lower() in URL_PARAM_HINTS:
                sinks.setdefault(f["name"].lower(), (form["action"], "form", form["action"], f["name"]))

    if not sinks:
        return

    callback = ctx.opts.get("ssrf_callback")
    ctx.log(f"SSRF: {len(sinks)} URL-like parameter(s) found"
            + (f"; probing callback {callback}" if callback else " (surface only)"))

    for key, (loc, kind, real_url, real_key) in sinks.items():
        if callback:
            probe = f"http://{callback}/ssrf-{ctx.scan_id}-{real_key}"
            try:
                if kind == "query":
                    await ctx.get(_with_param(real_url, real_key, probe))
                else:
                    await ctx.request("POST", real_url, data={real_key: probe})
            except Exception:
                pass
            ctx.report(
                "medium", f"SSRF probe sent via '{real_key}' — check your callback host",
                category="ssrf", location=loc,
                description="A probe pointing at your out-of-band callback host was injected into "
                            "a URL-like parameter. An inbound hit confirms server-side request "
                            "forgery.",
                evidence=f"Injected: {probe}",
                remediation="Validate and allow-list outbound request destinations; block "
                            "internal/metadata ranges.",
            )
        else:
            ctx.report(
                "low", f"Potential SSRF sink: parameter '{real_key}' takes URL-like input",
                category="ssrf", location=loc,
                description="This parameter name suggests it accepts a URL. If the server fetches "
                            "it, it may be vulnerable to SSRF. Confirm with an out-of-band probe "
                            "(set an SSRF callback host in scan options).",
                evidence=f"Parameter: {real_key} ({kind})",
                remediation="Validate and allow-list outbound destinations; block internal/"
                            "metadata IP ranges; disable unused URL fetching.",
            )
