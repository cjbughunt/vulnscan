"""Optional hooks into external scanners (nuclei, nmap) when installed on PATH.

Each hook is best-effort: if the tool is absent, the stage is skipped cleanly.
"""
import asyncio
import json
import shutil
from urllib.parse import urlparse

NUCLEI_SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}


def available(tool: str) -> bool:
    return shutil.which(tool) is not None


async def _run_cmd(args, timeout):
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return b"", b"timeout"
    return out, err


async def run_nuclei(ctx):
    if not ctx.opts.get("use_nuclei", True) or not available("nuclei"):
        return
    ctx.log("nuclei: running template scan")
    timeout = int(ctx.opts.get("nuclei_timeout", 600))
    args = ["nuclei", "-u", ctx.base_url, "-jsonl", "-silent",
            "-severity", "low,medium,high,critical",
            "-timeout", "10", "-retries", "1"]
    if ctx.opts.get("nuclei_rate"):
        args += ["-rate-limit", str(ctx.opts["nuclei_rate"])]
    out, err = await _run_cmd(args, timeout)
    count = 0
    for line in out.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        sev = NUCLEI_SEV_MAP.get((info.get("severity") or "info").lower(), "info")
        ctx.report(
            sev, info.get("name") or obj.get("template-id", "nuclei finding"),
            category=",".join(info.get("tags", [])) or "nuclei",
            location=obj.get("matched-at") or obj.get("host") or ctx.base_url,
            description=info.get("description") or "",
            evidence=(obj.get("extracted-results") and str(obj["extracted-results"]))
                     or obj.get("matcher-name") or "",
            remediation=info.get("remediation") or "",
            source="nuclei",
        )
        count += 1
    ctx.log(f"nuclei: {count} findings")


async def run_nmap(ctx):
    if not ctx.opts.get("use_nmap", True) or not available("nmap"):
        return
    host = urlparse(ctx.base_url).hostname
    if not host:
        return
    ctx.log("nmap: scanning common ports")
    ports = ctx.opts.get("nmap_ports", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443")
    timeout = int(ctx.opts.get("nmap_timeout", 300))
    out, err = await _run_cmd(
        ["nmap", "-sV", "-Pn", "-T4", "--open", "-p", ports, "-oX", "-", host], timeout
    )
    text = out.decode(errors="ignore")
    # Light XML parse to avoid extra deps.
    import re
    open_ports = []
    for m in re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)">\s*<state state="open".*?'
        r'(?:<service name="([^"]*)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?)?',
        text, re.S,
    ):
        proto, port, svc, product, ver = m.groups()
        open_ports.append((port, proto, svc or "?", " ".join(x for x in (product, ver) if x)))
    if open_ports:
        evidence = "\n".join(f"{p}/{pr}  {s}  {v}".strip() for p, pr, s, v in open_ports)
        ctx.report(
            "info", f"Open ports ({len(open_ports)})",
            category="network", location=host,
            description="nmap identified open TCP ports and services.",
            evidence=evidence, source="nmap",
            remediation="Close unnecessary ports; restrict exposure via firewall.",
        )
        ctx.log(f"nmap: {len(open_ports)} open ports")
