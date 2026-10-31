from __future__ import annotations

from typing import Any

NAME = "done"


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": "Finish investigating this reference. Call when you have enough evidence.",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    return {"done": True, "summary": args.get("summary", "")}
