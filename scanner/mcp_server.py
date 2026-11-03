from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from scanner.events import finding_public
from scanner.lookups import LookupCache, default_cache
from scanner.report import scan as run_trustmap_scan
from scanner.tools import ToolContext, run as run_lookup

READONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)
CONFIRM = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)


def create_server(
    *,
    ctx: ToolContext | None = None,
    cache: LookupCache | None = None,
    client: Any | None = None,
    scan_fn: Callable[..., Any] | None = None,
) -> FastMCP:
    cache = cache or (ctx.cache if ctx is not None else default_cache())
    ctx = ctx or ToolContext(cache=cache)
    mcp = FastMCP("trustmap")

    async def dns(host: str) -> dict[str, Any]:
        """DNS lookup for a full host, including CNAME chain."""
        return await run_lookup("dns", {"host": host}, ctx)

    async def rdap(domain: str) -> dict[str, Any]:
        """RDAP whois for a registrable domain. Use the domain, not a hostname."""
        return await run_lookup("rdap", {"domain": domain}, ctx)

    async def bucket_probe(name: str, provider: str) -> dict[str, Any]:
        """HTTP GET probe of an S3, GCS, or Azure bucket. Never creates or writes."""
        return await run_lookup(
            "bucket_probe", {"name": name, "provider": provider}, ctx
        )

    async def cert_history(domain: str) -> dict[str, Any]:
        """Certificate transparency history for a domain via crt.sh."""
        return await run_lookup("cert_history", {"domain": domain}, ctx)

    async def wayback(url: str) -> dict[str, Any]:
        """Wayback Machine first and last snapshot for a URL."""
        return await run_lookup("wayback", {"url": url}, ctx)

    async def platform_takeover(
        host: str,
        cnames: list[str] | None = None,
        dns_status: str | None = None,
    ) -> dict[str, Any]:
        """Check whether a host matches a known dangling-CNAME platform fingerprint."""
        args: dict[str, Any] = {"host": host}
        if cnames is not None:
            args["cnames"] = cnames
        if dns_status is not None:
            args["dns_status"] = dns_status
        return await run_lookup("platform_takeover", args, ctx)

    async def github_owner(owner: str) -> dict[str, Any]:
        """Check whether a GitHub user or org exists. GET only. Never creates an account."""
        return await run_lookup("github_owner", {"owner": owner}, ctx)

    async def live_fetch(url: str) -> dict[str, Any]:
        """GET a URL and report parked/for-sale facts. Never executes JavaScript."""
        return await run_lookup("live_fetch", {"url": url}, ctx)

    async def scan(target: str) -> dict[str, Any]:
        """Scan a local path, GitHub URL, or website. Detection only; never claims names."""
        if scan_fn is not None:
            findings = await scan_fn(target)
        else:
            from scanner.llm import LiveModelClient

            findings = await run_trustmap_scan(
                target,
                client=client or LiveModelClient(),
                cache=cache,
                ctx=ctx,
            )
        return {"findings": [finding_public(item) for item in findings]}

    async def propose_fix(path: str) -> dict[str, Any]:
        """Build a Tether patch for a local repo. Does not push. Needs confirmation to apply."""
        from scanner.extract import extract_scan
        from scanner.fix import propose_fixes, write_pr_copy

        extracted = extract_scan(path)
        if scan_fn is not None:
            findings = await scan_fn(path)
        else:
            from scanner.llm import LiveModelClient
            from scanner.report import scan as run_scan

            findings = await run_scan(
                path,
                client=client or LiveModelClient(),
                cache=cache,
                ctx=ctx,
            )
        plan = propose_fixes(findings, extracted.file_texts)
        title, body = write_pr_copy(plan, findings, client=client)
        return {
            "title": title,
            "body": body,
            "patch": plan.patch,
            "edits": [edit.__dict__ for edit in plan.edits],
        }

    for fn in (
        dns,
        rdap,
        bucket_probe,
        cert_history,
        wayback,
        platform_takeover,
        github_owner,
        live_fetch,
        scan,
    ):
        mcp.add_tool(fn, annotations=READONLY)
    mcp.add_tool(propose_fix, annotations=CONFIRM)
    return mcp


def main() -> None:
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
