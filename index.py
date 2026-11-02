"""Vercel entrypoint (pyproject.toml [tool.vercel]): Vercel serves the `app` below.

Everywhere else run the factory: uvicorn api.main:app --factory
"""
from api.main import create_app

app = create_app()
