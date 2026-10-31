from datetime import date
from typing import Any, Literal

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


RefType = Literal["script", "api", "asset", "config", "bucket", "ci", "docs", "test"]
RunsIn = Literal["browser", "server", "build", "ci", "docs_only"]


class ClassificationItem(BaseModel):
    id: str
    type: RefType
    runs_in: RunsIn
    blast_radius: int = Field(ge=0, le=3)
    confidence: float = Field(ge=0, le=1)
    reason: str


class ClassificationBatch(BaseModel):
    items: list[ClassificationItem]


class Classification(BaseModel):
    id: str
    file: str
    line: int
    host_or_bucket: str
    type: RefType
    runs_in: RunsIn
    blast_radius: int
    confidence: float
    reason: str


class CallLog(BaseModel):
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0
    cost_usd: float = 0
    cached: bool = False
    api_usage: dict[str, Any] | None = None
