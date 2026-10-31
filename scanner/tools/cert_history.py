from __future__ import annotations

from typing import Any

NAME = "cert_history"


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": "Certificate transparency history for a domain via crt.sh.",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.cert_history(args["domain"], cache=ctx.cache)
    return result.model_dump(mode="json")
