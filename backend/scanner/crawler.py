"""Same-origin crawler. Collects pages, links with query params, and forms.

Uses regex HTML parsing to avoid heavy dependencies. Bounded by max_pages.
"""
import re
from collections import deque
from urllib.parse import urlparse, parse_qs

from .auth import is_logout_url

_LINK_RE = re.compile(r"""<a\s[^>]*?href\s*=\s*["']?([^"'\s>]+)""", re.I)
_FORM_RE = re.compile(r"<form\b(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""action\s*=\s*["']?([^"'\s>]+)""", re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?([^"'\s>]+)""", re.I)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b([^>]*)>", re.I)
_NAME_RE = re.compile(r"""name\s*=\s*["']?([^"'\s>]+)""", re.I)
_TYPE_RE = re.compile(r"""type\s*=\s*["']?([^"'\s>]+)""", re.I)


async def run(ctx):
    max_pages = int(ctx.opts.get("max_pages", 40))
    ctx.log(f"Crawler: mapping the site (up to {max_pages} pages)")

    start = getattr(ctx, "final_url", ctx.base_url)
    logout = getattr(ctx, "logout_patterns", None)
    queue = deque([start, *ctx.seeds])
    seen = set()

    while queue and len(ctx.pages) < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        # Never follow logout/sign-out links: they would destroy the auth session.
        if is_logout_url(url, logout):
            continue
        try:
            resp = await ctx.get(url)
        except Exception:
            continue
        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype.lower():
            continue
        html = resp.text
        ctx.pages.append(url)

        # Record parameterized URLs for injection testing.
        q = urlparse(url).query
        if q:
            ctx.params_urls.append((url, {k: v[0] for k, v in parse_qs(q).items()}))

        # Extract forms.
        for fbody in _FORM_RE.findall(html):
            action = _ACTION_RE.search(fbody)
            method = _METHOD_RE.search(fbody)
            action_url = ctx.scope.resolve_url(action.group(1), url) if action else url
            if not action_url:
                continue
            fields = []
            for inp in _INPUT_RE.findall(fbody):
                nm = _NAME_RE.search(inp)
                tp = _TYPE_RE.search(inp)
                if nm:
                    fields.append({"name": nm.group(1),
                                   "type": tp.group(1).lower() if tp else "text"})
            ctx.forms.append({
                "url": url,
                "action": action_url,
                "method": (method.group(1).upper() if method else "GET"),
                "fields": fields,
            })

        # Follow links.
        for href in _LINK_RE.findall(html):
            nxt = ctx.scope.resolve_url(href, url)
            if nxt and nxt not in seen:
                queue.append(nxt)

    ctx.log(f"Crawler: {len(ctx.pages)} pages, {len(ctx.forms)} forms, "
            f"{len(ctx.params_urls)} parameterized URLs")
    ctx.report(
        "info", "Crawl summary",
        category="recon", location=ctx.base_url,
        description=f"Mapped {len(ctx.pages)} pages, {len(ctx.forms)} forms, "
                    f"{len(ctx.params_urls)} URLs with query parameters.",
        evidence="\n".join(ctx.pages[:60]),
    )
