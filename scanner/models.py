from datetime import date

from pydantic import BaseModel, Field


class Reference(BaseModel):
    file: str
    line: int = Field(ge=1)
    raw: str
    host_or_bucket: str
    domain: str = ""
    context: str = ""
    filter_reason: str | None = None


class RdapResult(BaseModel):
    domain: str
    status: str
    registrar: str | None = None
    expiry: date | None = None
    days_to_expiry: int | None = None
    statuses: list[str] = Field(default_factory=list)


class DnsResult(BaseModel):
    host: str
    status: str
    addresses: list[str] = Field(default_factory=list)
    cnames: list[str] = Field(default_factory=list)


class BucketProbeResult(BaseModel):
    name: str
    provider: str
    status: str
    http_status: int | None = None


class CertHistoryResult(BaseModel):
    domain: str
    status: str
    issuers: list[str] = Field(default_factory=list)
    first_seen: date | None = None
    last_seen: date | None = None


class WaybackResult(BaseModel):
    url: str
    status: str
    first_snapshot: str | None = None
    last_snapshot: str | None = None
    first_digest: str | None = None
    last_digest: str | None = None
