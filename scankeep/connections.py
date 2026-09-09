"""SonarQube and Git provider interactions."""

from __future__ import annotations

import base64
import os
import subprocess
import time
import urllib.parse
from pathlib import PurePosixPath
from typing import Any

import httpx


class ConnectionError(RuntimeError):
    """A configured external service could not be reached or authenticated."""


def process_environment() -> dict[str, str]:
    env = dict(os.environ)
    for name in (
        "SCANKEEP_ACCESS_TOKEN",
        "SCANKEEP_ACCESS_TOKEN_FILE",
        "SCANKEEP_ENCRYPTION_KEY",
        "SCANKEEP_ENCRYPTION_KEY_FILE",
    ):
        env.pop(name, None)
    return env


def normalize_sonar_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("SonarQube URL must be HTTPS and must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("SonarQube URL must not contain a query or fragment")
    return f"https://{parsed.netloc}{parsed.path}".rstrip("/")


def normalize_repository_url(url: str, provider: str) -> str:
    if provider not in {"github", "gitlab"}:
        raise ValueError("provider must be github or gitlab")
    parsed = urllib.parse.urlparse(url.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            "repository URL must be HTTPS and must not contain credentials"
        )
    host = parsed.hostname.lower()
    if provider == "github" and not (
        host == "github.com" or host.endswith(".github.com")
    ):
        raise ValueError("repository URL does not match the GitHub provider")
    if provider == "gitlab" and "gitlab" not in host:
        raise ValueError("repository URL does not match the GitLab provider")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or parsed.query or parsed.fragment:
        raise ValueError("repository URL must identify one repository")
    authority = f"{host}:{parsed.port}" if parsed.port not in (None, 443) else host
    return f"https://{authority}/{path}.git"


def normalize_scan_path(scan_path: str) -> str:
    value = scan_path.strip().strip("/")
    if not value:
        return ""
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("scan path must stay within the repository")
    return path.as_posix()


def git_environment(provider: str, token: str) -> dict[str, str]:
    env = {**process_environment(), "GIT_TERMINAL_PROMPT": "0"}
    if not token:
        return env
    username = "x-access-token" if provider == "github" else "oauth2"
    credentials = base64.b64encode(f"{username}:{token}".encode()).decode()
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {credentials}",
        }
    )
    return env


def list_remote_branches(
    repository_url: str,
    provider: str,
    token: str,
    *,
    timeout: int = 60,
) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", repository_url],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=git_environment(provider, token),
        )
    except FileNotFoundError as exc:
        raise ConnectionError("git is not installed on the Scankeep host") from exc
    except subprocess.TimeoutExpired as exc:
        raise ConnectionError("repository branch lookup timed out") from exc
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ""
        raise ConnectionError(
            f"repository branch lookup failed{f': {detail}' if detail else ''}"
        )
    prefix = "refs/heads/"
    branches = set()
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].startswith(prefix):
            branches.add(parts[1][len(prefix) :])
    return sorted(branches, key=str.lower)


def validate_sonar_server(url: str, token: str, *, timeout: int = 15) -> None:
    try:
        response = httpx.get(
            f"{url}/api/authentication/validate",
            auth=(token, ""),
            timeout=timeout,
        )
        response.raise_for_status()
        if not response.json().get("valid"):
            raise ConnectionError("SonarQube rejected the supplied token")
    except (httpx.HTTPError, ValueError) as exc:
        raise ConnectionError(f"SonarQube validation failed: {exc}") from exc


def check_sonar_server_health(
    url: str, token: str, *, timeout: int = 10
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        status_response = httpx.get(
            f"{url}/api/system/status",
            auth=(token, ""),
            timeout=timeout,
        )
        status_response.raise_for_status()
        payload = status_response.json()
        status = str(payload.get("status") or "UNKNOWN").upper()
        auth_response = httpx.get(
            f"{url}/api/authentication/validate",
            auth=(token, ""),
            timeout=timeout,
        )
        auth_response.raise_for_status()
        if not auth_response.json().get("valid"):
            return {
                "healthy": False,
                "status": "AUTHENTICATION_FAILED",
                "version": str(payload.get("version") or ""),
                "latency_ms": round((time.monotonic() - started) * 1000),
                "error": "SonarQube rejected the stored token",
            }
        return {
            "healthy": status == "UP",
            "status": status,
            "version": str(payload.get("version") or ""),
            "latency_ms": round((time.monotonic() - started) * 1000),
            "error": "",
        }
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        return {
            "healthy": False,
            "status": "UNREACHABLE",
            "version": "",
            "latency_ms": round((time.monotonic() - started) * 1000),
            "error": str(exc),
        }


def fetch_sonar_report(
    url: str,
    token: str,
    project_key: str,
    branch: str,
    *,
    expected_revision: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    auth = (token, "")
    common = {"branch": branch}
    try:
        quality_gate = httpx.get(
            f"{url}/api/qualitygates/project_status",
            params={"projectKey": project_key, **common},
            auth=auth,
            timeout=timeout,
        )
        quality_gate.raise_for_status()
        measures = httpx.get(
            f"{url}/api/measures/component",
            params={
                "component": project_key,
                "metricKeys": (
                    "bugs,vulnerabilities,security_hotspots,code_smells,"
                    "coverage,duplicated_lines_density,ncloc"
                ),
                **common,
            },
            auth=auth,
            timeout=timeout,
        )
        measures.raise_for_status()
        analyses = httpx.get(
            f"{url}/api/project_analyses/search",
            params={"project": project_key, "p": 1, "ps": 1, **common},
            auth=auth,
            timeout=timeout,
        )
        analyses.raise_for_status()
    except httpx.HTTPError as exc:
        raise ConnectionError(f"SonarQube report lookup failed: {exc}") from exc

    try:
        measure_values = {
            item["metric"]: item.get("value", "")
            for item in (measures.json().get("component") or {}).get("measures", [])
        }
        latest = (analyses.json().get("analyses") or [{}])[0]
        status = (quality_gate.json().get("projectStatus") or {}).get("status", "NONE")
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectionError("SonarQube report response is invalid") from exc
    revision = str(latest.get("revision") or "")
    if expected_revision and revision != expected_revision:
        raise ConnectionError(
            "SonarQube has not published a report for the scanned commit"
        )
    query = urllib.parse.urlencode({"id": project_key, "branch": branch})
    return {
        "quality_gate": status,
        "measures": measure_values,
        "analysis_date": latest.get("date", ""),
        "analysis_revision": revision,
        "dashboard_url": f"{url}/dashboard?{query}",
    }
