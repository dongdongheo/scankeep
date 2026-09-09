"""Standalone Scankeep backed by SonarQube."""

from __future__ import annotations

import atexit
import os
import secrets
from pathlib import Path

from flask import Blueprint, Flask, g, jsonify, redirect, request

from .runner import ScanRunner
from .scheduler import ScanScheduler
from .store import ScankeepStore

scankeep_bp = Blueprint(
    "scankeep",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/scankeep/static",
)


def _secret(name: str) -> str:
    file_path = os.getenv(f"{name}_FILE", "").strip()
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"cannot read {name}_FILE: {exc}") from exc
    return os.getenv(name, "").strip()


def create_app() -> Flask:
    """Create the standalone web application and runtime."""
    os.umask(0o077)
    access_token = _secret("SCANKEEP_ACCESS_TOKEN")
    encryption_key = _secret("SCANKEEP_ENCRYPTION_KEY")
    if not access_token:
        raise RuntimeError(
            "SCANKEEP_ACCESS_TOKEN or SCANKEEP_ACCESS_TOKEN_FILE is required"
        )
    if not encryption_key:
        raise RuntimeError(
            "SCANKEEP_ENCRYPTION_KEY or SCANKEEP_ENCRYPTION_KEY_FILE is required"
        )

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 1_048_576
    app.config["SCANKEEP_ACCESS_TOKEN"] = access_token
    app.register_blueprint(scankeep_bp)
    data_dir = Path(
        os.getenv(
            "SCANKEEP_DATA_DIR",
            Path(__file__).resolve().parent / "data",
        )
    ).expanduser()
    store = ScankeepStore(data_dir / "scankeep.db", encryption_key)
    store.fail_active_jobs()
    runner = ScanRunner(store, data_dir)
    scheduler = ScanScheduler(store, runner)
    scheduler.start()
    app.extensions["scankeep_store"] = store
    app.extensions["scankeep_runner"] = runner
    atexit.register(runner.stop)
    atexit.register(scheduler.stop)

    @app.before_request
    def create_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def security_context():
        return {"csp_nonce": g.csp_nonce}

    @app.get("/")
    def root():
        return redirect("/scankeep")

    @app.get("/healthz")
    def health():
        return jsonify({"status": "ok"})

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "object-src 'none'; form-action 'self'; "
            f"script-src 'self' 'nonce-{g.csp_nonce}'; "
            "style-src 'self' 'unsafe-inline'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    return app


from . import routes  # noqa: E402,F401
