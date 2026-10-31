from pydantic import BaseModel, Field


class Reference(BaseModel):
    file: str
    line: int = Field(ge=1)
    raw: str
    host_or_bucket: str
    domain: str = ""
    context: str = ""
    filter_reason: str | None = None
