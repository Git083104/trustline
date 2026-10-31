from __future__ import annotations

from typing import Any

NAME = "bucket_probe"


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": "HTTP GET probe of an S3 or GCS bucket. Never creates or writes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "provider": {"type": "string", "enum": ["s3", "gcs"]},
                },
                "required": ["name", "provider"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.bucket_probe(
        args["name"], args["provider"], cache=ctx.cache
    )
    return result.model_dump(mode="json")
