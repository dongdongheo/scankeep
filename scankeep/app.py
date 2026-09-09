"""Gunicorn entry point for the standalone service."""

from . import create_app

app = create_app()
