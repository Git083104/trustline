from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx

from scanner.config import (
    HTTP_TIMEOUT_S,
    WEBSITE_JS_MAX_BYTES,
    WEBSITE_MAX_JS_FILES,
    WEBSITE_PAGE_MAX_BYTES,
)
from scanner.extract import TRAILING_JUNK, URL_RE, _classify_http_url, drop_junk_refs
from scanner.models import Reference
from scanner.ssrf import (
    ScanBlockedError,
    allow_local_scan,
    host_header,
    ip_url,
    parse_public_url,
    refuse_blocked_ips,
    resolve_host,
)

USER_AGENT = "Trustmap/0.1 (security scan)"
PAGE_MAX_BYTES = WEBSITE_PAGE_MAX_BYTES
JS_MAX_BYTES = WEBSITE_JS_MAX_BYTES
MAX_REDIRECTS = 5
MAX_SAME_SITE_JS = WEBSITE_MAX_JS_FILES
LINK_RELS = frozenset({"stylesheet", "preload", "modulepreload", "icon"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
ResolveFn = Callable[[str], Any]
SendFn = Callable[..., Any]


@dataclass
class FetchResult:
    url: str
    status_code: int
    body: str
    content_type: str = ""
    redirect_chain: list[str] = field(default_factory=list)


@dataclass
class _TagHit:
    line: int
    tag: str
    attribute: str
    raw: str
    sri: bool | None
    loaded_by: str = "html"


def _headers(host: str, scheme: str, port: int) -> dict[str, str]:
    return {
        "Host": host_header(host, scheme, port),
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }


async def _default_send(
    method: str,
    connect_url: str,
    headers: dict[str, str],
    *,
    timeout: float,
    sni: str,
) -> tuple[int, dict[str, str], bytes]:
    extensions = {"sni_hostname": sni} if connect_url.startswith("https://") else {}
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, verify=True
    ) as client:
        response = await client.request(
            method,
            connect_url,
            headers=headers,
            extensions=extensions,
        )
        return (
            response.status_code,
            {k.lower(): v for k, v in response.headers.items()},
            response.content,
        )


async def safe_get(
    url: str,
    *,
    max_bytes: int = PAGE_MAX_BYTES,
    timeout: float = HTTP_TIMEOUT_S,
    allow_local: bool | None = None,
    resolve: ResolveFn | None = None,
    send: SendFn | None = None,
) -> FetchResult:
    allow_local = allow_local_scan() if allow_local is None else allow_local
    resolve = resolve or resolve_host
    send = send or _default_send
    current = url
    chain: list[str] = []
    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, port, path = parse_public_url(current, allow_local=allow_local)
        resolved = resolve(host)
        addresses = await resolved if inspect.isawaitable(resolved) else resolved
        refuse_blocked_ips(list(addresses), allow_local=allow_local)
        ip = addresses[0]
        connect_url = ip_url(scheme, ip, port, path)
        try:
            sent = send(
                "GET",
                connect_url,
                _headers(host, scheme, port),
                timeout=timeout,
                sni=host,
            )
            status, headers, body = await sent if inspect.isawaitable(sent) else sent
        except ScanBlockedError:
            raise
        except Exception as exc:
            raise ScanBlockedError() from exc
        if status in REDIRECT_STATUSES:
            location = headers.get("location")
            if not location:
                raise ScanBlockedError()
            chain.append(current)
            current = urljoin(current, location)
            continue
        text = body[:max_bytes].decode("utf-8", errors="replace")
        return FetchResult(
            url=current,
            status_code=status,
            body=text,
            content_type=headers.get("content-type", ""),
            redirect_chain=chain,
        )
    raise ScanBlockedError()


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _same_origin(page_url: str, candidate: str) -> bool:
    try:
        return _origin(page_url) == _origin(candidate)
    except ValueError:
        return False


def parse_csp(content: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in content.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def csp_blocks_external_scripts(content: str) -> bool:
    directives = parse_csp(content)
    src = directives.get("script-src") or directives.get("default-src") or []
    if not src:
        return False
    for token in src:
        low = token.lower()
        if low in {"'self'", "self", "'none'", "none"}:
            continue
        if low.startswith("'nonce-") or low.startswith("'sha256-") or low.startswith(
            "'sha384-"
        ) or low.startswith("'sha512-"):
            continue
        return False
    return True


@dataclass
class WebsiteScan:
    references: list[Reference]
    html: str
    url: str
    csp_blocks_external_scripts: bool = False
    ignored_non_hosts: int = 0


class _PageParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.hits: list[_TagHit] = []
        self._script_open: tuple[int, dict[str, str]] | None = None
        self.same_site_scripts: list[str] = []
        self.csp = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        line, _col = self.getpos()
        adict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta" and adict.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = adict.get("content", "")
            return
        if tag == "script":
            self._script_open = (line, adict)
            src = adict.get("src")
            if src:
                self._add(line, "script", "src", src, bool(adict.get("integrity")))
            return
        if tag == "link":
            rels = {part.lower() for part in adict.get("rel", "").split()}
            if rels & LINK_RELS and adict.get("href"):
                self._add(
                    line,
                    "link",
                    "href",
                    adict["href"],
                    bool(adict.get("integrity")),
                )
            return
        attr = {
            "iframe": "src",
            "form": "action",
            "img": "src",
            "source": "src",
        }.get(tag)
        if attr and adict.get(attr):
            self._add(line, tag, attr, adict[attr], None)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._script_open = None

    def handle_data(self, data: str) -> None:
        if not self._script_open:
            return
        start_line, adict = self._script_open
        if adict.get("src"):
            return
        for offset, line in enumerate(data.splitlines()):
            for match in URL_RE.finditer(line):
                raw = match.group(0).rstrip(TRAILING_JUNK)
                self._add(start_line + offset, "script", "data", raw, None)

    def _add(
        self, line: int, tag: str, attribute: str, value: str, sri: bool | None
    ) -> None:
        absolute = urljoin(self.page_url, value.strip())
        if not absolute.startswith(("http://", "https://")):
            return
        self.hits.append(
            _TagHit(
                line=max(line, 1),
                tag=tag,
                attribute=attribute,
                raw=absolute,
                sri=sri,
            )
        )
        if tag == "script" and attribute == "src" and _same_origin(
            self.page_url, absolute
        ):
            if absolute not in self.same_site_scripts:
                self.same_site_scripts.append(absolute)


def _reference_from_hit(
    hit: _TagHit, *, page_url: str, file: str, loaded_by: str
) -> Reference | None:
    parsed = _classify_http_url(hit.raw, "", "")
    if parsed is None:
        return None
    host_or_bucket, raw, domain, reason = parsed
    return Reference(
        file=file,
        line=hit.line,
        raw=raw,
        host_or_bucket=host_or_bucket,
        domain=domain,
        context=f"<{hit.tag} {hit.attribute}>",
        filter_reason=reason,
        page_url=page_url,
        tag=hit.tag,
        attribute=hit.attribute,
        sri=hit.sri,
        loaded_by=loaded_by,
    )


async def extract_website(
    url: str,
    *,
    allow_local: bool | None = None,
    resolve: ResolveFn | None = None,
    send: SendFn | None = None,
) -> list[Reference]:
    return (await extract_website_scan(url, allow_local=allow_local, resolve=resolve, send=send)).references


async def extract_website_scan(
    url: str,
    *,
    allow_local: bool | None = None,
    resolve: ResolveFn | None = None,
    send: SendFn | None = None,
) -> WebsiteScan:
    page = await safe_get(
        url,
        max_bytes=PAGE_MAX_BYTES,
        allow_local=allow_local,
        resolve=resolve,
        send=send,
    )
    parser = _PageParser(page.url)
    parser.feed(page.body)
    parser.close()
    blocks = csp_blocks_external_scripts(parser.csp)
    found: dict[tuple[str, str, int], Reference] = {}
    for hit in parser.hits:
        ref = _reference_from_hit(
            hit, page_url=page.url, file=page.url, loaded_by="html"
        )
        if ref is None:
            continue
        if blocks:
            ref = ref.model_copy(update={"csp_blocks_external_scripts": True})
        key = (ref.host_or_bucket, ref.file, ref.line)
        found.setdefault(key, ref)

    for script_url in parser.same_site_scripts[:MAX_SAME_SITE_JS]:
        try:
            js = await safe_get(
                script_url,
                max_bytes=JS_MAX_BYTES,
                allow_local=allow_local,
                resolve=resolve,
                send=send,
            )
        except ScanBlockedError:
            continue
        for index, line in enumerate(js.body.splitlines(), start=1):
            for match in URL_RE.finditer(line):
                raw = match.group(0).rstrip(TRAILING_JUNK)
                hit = _TagHit(
                    line=index,
                    tag="script",
                    attribute="src",
                    raw=raw,
                    sri=None,
                    loaded_by="first_party_js",
                )
                ref = _reference_from_hit(
                    hit,
                    page_url=page.url,
                    file=js.url,
                    loaded_by="first_party_js",
                )
                if ref is None:
                    continue
                if blocks:
                    ref = ref.model_copy(update={"csp_blocks_external_scripts": True})
                key = (ref.host_or_bucket, ref.file, ref.line)
                found.setdefault(key, ref)

    refs = sorted(found.values(), key=lambda item: (item.file, item.line, item.raw))
    refs, ignored = drop_junk_refs(refs)
    return WebsiteScan(
        references=refs,
        html=page.body,
        url=page.url,
        csp_blocks_external_scripts=blocks,
        ignored_non_hosts=ignored,
    )
