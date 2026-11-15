"""Reconnaissance: resolve host, probe the base URL, read robots/security.txt."""
from urllib.parse import urljoin


async def run(ctx):
    ctx.log("Recon: probing base URL")
    try:
        resp = await ctx.get(ctx.base_url)
    except Exception as e:
        ctx.log(f"Base URL unreachable: {e}", "error")
        ctx.report("info", "Target unreachable",
                   category="recon", location=ctx.base_url,
                   description=f"Could not fetch the base URL: {e}")
        return

    ctx.final_url = str(resp.url)
    server = resp.headers.get("server")
    powered = resp.headers.get("x-powered-by")
    tech = ", ".join(x for x in (server, powered) if x) or "unknown"
    ctx.log(f"Live. HTTP {resp.status_code}. Tech: {tech}")

    ctx.report(
        "info", "Target fingerprint",
        category="recon", location=ctx.final_url,
        description=f"HTTP {resp.status_code} from {ctx.final_url}",
        evidence=f"Server: {server or 'n/a'}\nX-Powered-By: {powered or 'n/a'}\n"
                 f"Resolved IPs: {', '.join(ctx.ips) or 'n/a'}",
    )

    # Disclose version banners (minor info leak worth flagging).
    for name, val in (("Server", server), ("X-Powered-By", powered)):
        if val and any(ch.isdigit() for ch in val):
            ctx.report(
                "low", f"Version disclosure via {name} header",
                category="info-leak", location=ctx.final_url,
                description=f"The {name} header reveals software version information "
                            "that aids targeted attacks.",
                evidence=f"{name}: {val}",
                remediation=f"Suppress or genericize the {name} response header.",
            )

    # robots.txt / security.txt / sitemap seeds for the crawler.
    for path in ("/robots.txt", "/.well-known/security.txt", "/sitemap.xml"):
        url = urljoin(ctx.base_url, path)
        try:
            r = await ctx.get(url)
        except Exception:
            continue
        if r.status_code == 200 and r.text.strip():
            ctx.log(f"Found {path}")
            if path == "/robots.txt":
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        p = line.split(":", 1)[1].strip()
                        if p and p != "/":
                            seed = ctx.scope.resolve_url(p, ctx.base_url)
                            if seed:
                                ctx.seeds.add(seed)
            ctx.report(
                "info", f"{path} present",
                category="recon", location=url,
                description=f"{path} is accessible and may reveal hidden paths.",
                evidence=r.text[:1500],
            )
