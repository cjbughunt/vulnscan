"""JWT weakness checks: alg:none, weak HMAC secrets, expiry, sensitive claims.

Tokens are harvested from session cookies, any configured Authorization header, and
Set-Cookie headers on the base response. Decoding is local and non-destructive.
"""
import base64
import hashlib
import hmac
import json
import re
import time

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Small list of notoriously common HMAC secrets to test (offline, no requests).
WEAK_SECRETS = [
    "secret", "password", "changeme", "jwt", "key", "admin", "test", "123456",
    "secretkey", "your-256-bit-secret", "supersecret", "jwtsecret", "s3cr3t",
    "qwerty", "token", "private", "default", "example", "abc123",
]


def _b64url(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode(token: str):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except Exception:
        return None
    return header, payload, parts


def _harvest(ctx) -> set:
    tokens = set()
    # Session cookies in the client jar.
    try:
        for cookie in ctx.client.cookies.jar:
            if cookie.value:
                tokens.update(JWT_RE.findall(cookie.value))
    except Exception:
        pass
    # Configured Authorization header (e.g. bearer token auth).
    authz = ctx.client.headers.get("authorization", "")
    tokens.update(JWT_RE.findall(authz))
    return tokens


async def run(ctx):
    ctx.log("JWT: inspecting tokens for weaknesses")
    tokens = _harvest(ctx)
    # Also look at Set-Cookie on the base response.
    try:
        r = await ctx.get(getattr(ctx, "final_url", ctx.base_url))
        for raw in (r.headers.get_list("set-cookie")
                    if hasattr(r.headers, "get_list") else []):
            tokens.update(JWT_RE.findall(raw))
    except Exception:
        pass

    if not tokens:
        return
    ctx.log(f"JWT: analyzing {len(tokens)} token(s)")
    for tok in tokens:
        _analyze(ctx, tok)


def _analyze(ctx, token: str):
    dec = _decode(token)
    if not dec:
        return
    header, payload, parts = dec
    alg = (header.get("alg") or "").lower()
    short = token[:24] + "…"

    if alg in ("none", ""):
        ctx.report(
            "high", "JWT accepts 'alg: none' (unsigned token)",
            category="jwt", location=ctx.base_url,
            description="A JWT uses the 'none' algorithm, meaning it is unsigned and can be "
                        "forged by anyone.",
            evidence=f"Header: {json.dumps(header)}\nToken: {short}",
            remediation="Reject 'none'; enforce a strong signing algorithm server-side.",
        )

    if alg.startswith("hs") and len(parts) == 3:
        cracked = _crack_hmac(token, alg)
        if cracked is not None:
            ctx.report(
                "high", "JWT signed with a weak/guessable secret",
                category="jwt", location=ctx.base_url,
                description="The HMAC signing secret was recovered from a small common-secret "
                            "list, so tokens can be forged.",
                evidence=f"alg: {header.get('alg')}\nRecovered secret: {cracked!r}\nToken: {short}",
                remediation="Use a long, random, high-entropy signing secret and rotate it.",
            )

    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        ctx.report(
            "info", "JWT is expired",
            category="jwt", location=ctx.base_url,
            description="A harvested JWT is past its expiry; informational for session analysis.",
            evidence=f"exp: {exp}",
        )

    sensitive = [k for k in ("password", "pwd", "secret", "ssn", "credit_card", "api_key")
                 if k in {kk.lower() for kk in payload}]
    if sensitive:
        ctx.report(
            "medium", "Sensitive data in JWT payload",
            category="jwt", location=ctx.base_url,
            description="JWT payloads are only base64-encoded, not encrypted; sensitive claims "
                        "are readable by anyone holding the token.",
            evidence=f"Sensitive claim(s): {', '.join(sensitive)}",
            remediation="Do not place secrets in JWT payloads.",
        )


def _crack_hmac(token: str, alg: str):
    try:
        signing_input, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    try:
        want = _b64url(sig)
    except Exception:
        return None
    digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
              "hs512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    for secret in WEAK_SECRETS:
        mac = hmac.new(secret.encode(), signing_input.encode(), digest).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None
