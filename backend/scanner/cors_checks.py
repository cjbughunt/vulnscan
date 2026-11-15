"""CORS misconfiguration checks (non-destructive; GET with crafted Origin headers)."""

PROBE_ORIGIN = "https://vulnscan-cors-probe.example"


async def run(ctx):
    ctx.log("CORS: testing cross-origin resource sharing policy")
    targets = [getattr(ctx, "final_url", ctx.base_url)]
    for url, _ in ctx.params_urls[:6]:
        if url not in targets:
            targets.append(url)

    for url in targets:
        # 1) Reflected arbitrary origin.
        try:
            r = await ctx.request("GET", url, headers={"Origin": PROBE_ORIGIN})
        except Exception:
            continue
        h = {k.lower(): v for k, v in r.headers.items()}
        acao = h.get("access-control-allow-origin")
        creds = h.get("access-control-allow-credentials", "").lower() == "true"
        if not acao:
            continue

        if acao == PROBE_ORIGIN and creds:
            ctx.report(
                "high", "CORS reflects arbitrary origin with credentials",
                category="cors", location=url,
                description="The server reflects any Origin into Access-Control-Allow-Origin "
                            "AND allows credentials, letting a malicious site read authenticated "
                            "responses on behalf of a victim.",
                evidence=f"Origin: {PROBE_ORIGIN}\nAccess-Control-Allow-Origin: {acao}\n"
                         "Access-Control-Allow-Credentials: true",
                remediation="Never reflect arbitrary origins with credentials. Use a strict "
                            "allow-list of trusted origins.",
            )
        elif acao == PROBE_ORIGIN:
            ctx.report(
                "medium", "CORS reflects arbitrary origin",
                category="cors", location=url,
                description="The server reflects any Origin into Access-Control-Allow-Origin, "
                            "weakening the same-origin policy for this resource.",
                evidence=f"Origin: {PROBE_ORIGIN}\nAccess-Control-Allow-Origin: {acao}",
                remediation="Restrict Access-Control-Allow-Origin to a trusted allow-list.",
            )
        elif acao == "*" and creds:
            ctx.report(
                "low", "CORS wildcard origin with credentials flag",
                category="cors", location=url,
                description="Wildcard ACAO combined with allow-credentials is contradictory and "
                            "indicates a misconfigured CORS policy.",
                evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                remediation="Do not combine wildcard origins with credentials.",
            )

        # 2) 'null' origin acceptance (reachable from sandboxed iframes / redirects).
        try:
            r2 = await ctx.request("GET", url, headers={"Origin": "null"})
            h2 = {k.lower(): v for k, v in r2.headers.items()}
            if h2.get("access-control-allow-origin") == "null" and \
                    h2.get("access-control-allow-credentials", "").lower() == "true":
                ctx.report(
                    "medium", "CORS allows 'null' origin with credentials",
                    category="cors", location=url,
                    description="Accepting the 'null' origin with credentials is exploitable from "
                                "sandboxed iframes and some redirect chains.",
                    evidence="Origin: null -> Access-Control-Allow-Origin: null (credentials)",
                    remediation="Reject the 'null' origin; use a strict allow-list.",
                )
        except Exception:
            pass
