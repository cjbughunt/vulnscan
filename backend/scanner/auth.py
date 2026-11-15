"""Authentication for authenticated scanning.

Three modes, all driven by config the operator supplies for their own target:
  - header : attach an Authorization (or custom) header / bearer token
  - cookie : attach a raw Cookie string (e.g. copied session cookies)
  - form   : submit a login form, auto-handling CSRF hidden fields, keep the session

Secrets (passwords, tokens, cookies) are held in memory for the scan only and are
never written to the database (see app.py / engine.py).
"""
import re
from http.cookies import SimpleCookie
from urllib.parse import urljoin

_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.I)
_NAME_RE = re.compile(r"""name\s*=\s*["']?([^"'\s>]+)""", re.I)
_VALUE_RE = re.compile(r"""value\s*=\s*["']([^"']*)["']""", re.I)
_TYPE_RE = re.compile(r"""type\s*=\s*["']?([^"'\s>]+)""", re.I)
_FORM_RE = re.compile(r"<form\b(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""action\s*=\s*["']?([^"'\s>]+)""", re.I)

CSRF_HINTS = ("csrf", "token", "authenticity", "nonce", "verificationtoken", "_token")
LOGOUT_DEFAULT = ["logout", "signout", "sign-out", "sign_out", "log-out", "log_out", "/exit"]


def is_logout_url(url: str, patterns) -> bool:
    low = url.lower()
    return any(p in low for p in (patterns or LOGOUT_DEFAULT))


def _hidden_fields(html: str) -> dict:
    """Collect hidden inputs (incl. CSRF tokens) from the first form on the page."""
    form = _FORM_RE.search(html)
    scope = form.group(1) if form else html
    out = {}
    for raw in _INPUT_RE.findall(scope):
        nm = _NAME_RE.search(raw)
        if not nm:
            continue
        tp = (_TYPE_RE.search(raw).group(1).lower() if _TYPE_RE.search(raw) else "text")
        val = _VALUE_RE.search(raw)
        val = val.group(1) if val else ""
        name = nm.group(1)
        if tp == "hidden" or any(h in name.lower() for h in CSRF_HINTS):
            out[name] = val
    return out


def _form_action(html: str, login_url: str) -> str:
    form = _FORM_RE.search(html)
    if form:
        act = _ACTION_RE.search(form.group(1))
        if act and act.group(1):
            return urljoin(login_url, act.group(1))
    return login_url


async def authenticate(ctx, auth: dict) -> dict:
    """Configure ctx.client for authenticated requests. Returns a status dict."""
    atype = (auth or {}).get("type") or "none"
    if atype == "none":
        return {"ok": True, "type": "none"}

    if atype == "header":
        name = auth.get("header_name") or "Authorization"
        value = auth.get("header_value") or ""
        if not value:
            return {"ok": False, "type": "header", "error": "No header value provided."}
        ctx.client.headers[name] = value
        ctx.log(f"Auth: attached '{name}' header to all requests")
        return {"ok": True, "type": "header", "detail": f"header {name}"}

    if atype == "cookie":
        raw = auth.get("cookie") or ""
        if not raw:
            return {"ok": False, "type": "cookie", "error": "No cookie string provided."}
        jar = SimpleCookie()
        jar.load(raw)
        host = ctx.scope.host
        for k, morsel in jar.items():
            ctx.client.cookies.set(k, morsel.value, domain=host)
        ctx.log(f"Auth: loaded {len(jar)} cookie(s) for {host}")
        return {"ok": True, "type": "cookie", "detail": f"{len(jar)} cookies"}

    if atype == "form":
        return await _form_login(ctx, auth)

    return {"ok": False, "type": atype, "error": f"Unknown auth type: {atype}"}


async def _form_login(ctx, auth: dict) -> dict:
    login_url = auth.get("login_url")
    if not login_url:
        return {"ok": False, "type": "form", "error": "No login_url provided."}
    login_url = ctx.scope.resolve_url(login_url, ctx.base_url) or login_url
    if not ctx.scope.in_scope(login_url):
        return {"ok": False, "type": "form", "error": "login_url is out of scope."}

    ufield = auth.get("username_field") or "username"
    pfield = auth.get("password_field") or "password"
    username = auth.get("username") or ""
    password = auth.get("password") or ""

    # GET the login page first: captures initial cookies + CSRF hidden fields.
    data = {}
    action = login_url
    try:
        page = await ctx.get(login_url, follow=True)
        data.update(_hidden_fields(page.text))
        action = _form_action(page.text, login_url)
    except Exception as e:
        ctx.log(f"Auth: could not load login page: {e}", "warn")

    data[ufield] = username
    data[pfield] = password
    for k, v in (auth.get("extra_fields") or {}).items():
        data[k] = v

    try:
        resp = await ctx.request("POST", action, follow=True, data=data)
    except Exception as e:
        return {"ok": False, "type": "form", "error": f"Login POST failed: {e}"}

    # Verify.
    have_cookies = len(ctx.client.cookies) > 0
    indicator = auth.get("success_indicator")
    ok = have_cookies
    detail = f"{len(ctx.client.cookies)} session cookie(s)"
    if indicator:
        try:
            check = await ctx.get(auth.get("verify_url") or ctx.base_url, follow=True)
            ok = indicator.lower() in check.text.lower()
            detail = f"indicator '{indicator}' {'found' if ok else 'NOT found'}"
        except Exception:
            ok = False
            detail = "verify request failed"

    ctx.log(f"Auth: form login -> {'success' if ok else 'uncertain'} ({detail})",
            "info" if ok else "warn")
    return {"ok": ok, "type": "form", "detail": detail}
