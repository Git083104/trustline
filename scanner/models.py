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
    page_url: str = ""
    tag: str = ""
    attribute: str = ""
    sri: bool | None = None
    loaded_by: str = ""
    action_owner: str = ""
    action_repo: str = ""
    action_ref: str = ""
    action_sha_pinned: bool | None = None


class RdapResult(BaseModel):
    domain: str
    status: str
    registrar: str | None = None
    registered: date | None = None
    expiry: date | None = None
    days_to_expiry: int | None = None
    last_changed: date | None = None
    transfer: date | None = None
    nameservers: list[str] = Field(default_factory=list)
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


class PlatformTakeoverResult(BaseModel):
    host: str
    status: str
    platform: str = ""
    takeover: str = ""
    signal: str | None = None
    http_status: int | None = None


class LiveFetchResult(BaseModel):
    url: str
    final_url: str
    status: str
    http_status: int | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    title: str = ""
    parked: bool = False
    for_sale: bool = False
    signal: str | None = None
    nameservers: list[str] = Field(default_factory=list)


class GithubOwnerResult(BaseModel):
    owner: str
    status: str
    exists: bool | None = None
    kind: str | None = None
    created_at: date | None = None
    http_status: int | None = None


class GithubRepoResult(BaseModel):
    owner: str
    repo: str
    status: str
    exists: bool | None = None
    http_status: int | None = None


class CertHistoryResult(BaseModel):
    domain: str
    status: str
    issuers: list[str] = Field(default_factory=list)
    first_seen: date | None = None
    last_seen: date | None = None
    first_issuer_org: str = ""
    last_issuer_org: str = ""
    max_gap_days: int | None = None


class WaybackResult(BaseModel):
    url: str
    status: str
    first_snapshot: str | None = None
    last_snapshot: str | None = None
    first_digest: str | None = None
    last_digest: str | None = None


RefType = Literal["script", "api", "asset", "bucket", "docs_link", "other"]
RunsIn = Literal["browser", "server", "build", "deploy", "ci", "test", "docs_only"]


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


class TraceEvent(BaseModel):
    kind: Literal["plan", "act", "observe"]
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None
    tokens: int = 0
    cost_usd: float = 0
    note: str = ""


class Investigation(BaseModel):
    file: str
    line: int
    host_or_bucket: str
    status: Literal["done", "budget", "deadline"]
    summary: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    trace: list[TraceEvent] = Field(default_factory=list)
    cost_usd: float = 0


Severity = Literal["critical", "high", "medium", "low", "info"]
FixKind = Literal[
    "remove dead reference",
    "self-host the asset",
    "pin with subresource integrity",
    "re-register what you abandoned",
    "replace with maintained source",
]


class RankModelOut(BaseModel):
    severity: Severity
    risk: str
    fix: FixKind
    uncertain_about: str = ""
    blast_radius: int = Field(ge=0, le=3)
    blast_override_reason: str = ""


class Finding(BaseModel):
    target: str
    kind: Literal["bucket", "domain"]
    references: list[str]
    severity: Severity
    model_severity: Severity
    final_severity: Severity
    classified_blast_radius: int
    ranked_blast_radius: int
    blast_override_reason: str = ""
    risk: str
    fix: FixKind | str
    uncertain_about: str = ""
    needs_review: bool = False
    floor_applied: str = ""
    floor_reason: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    evidence_line: str = ""
    cost_usd: float = 0
    locations: list[dict[str, Any]] = Field(default_factory=list)
    action_ref: str = ""
    action_sha_pinned: bool | None = None
    evidence_level: Literal["proven", "likely", ""] = ""
