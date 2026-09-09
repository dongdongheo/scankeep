"""Flask pages and JSON API for Scankeep."""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial, wraps
from typing import Any

from flask import current_app, jsonify, render_template, request

from . import scankeep_bp
from .connections import (
    ConnectionError,
    check_sonar_server_health,
    list_remote_branches,
    normalize_repository_url,
    normalize_scan_path,
    normalize_sonar_url,
    validate_sonar_server,
)
from .cron import next_cron_run, normalize_cron
from .store import ScankeepConfigError, utc_now


def _store():
    return current_app.extensions["scankeep_store"]


def _runner():
    return current_app.extensions["scankeep_runner"]


def _error(message: str, status: int):
    return jsonify({"error": message}), status


def _json() -> dict[str, Any]:
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise ValueError("request body must be a JSON object")
    return value


def _required(data: dict[str, Any], field: str, max_length: int | None = None) -> str:
    value = str(data.get(field) or "").strip()
    if not value:
        raise ValueError(f"{field} is required")
    if max_length and len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value


def _optional(data: dict[str, Any], field: str, max_length: int = 120) -> str:
    value = str(data.get(field) or "").strip()
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value


def _query_filter(field: str, max_length: int = 400) -> str | None:
    value = request.args.get(field, "").strip()
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value or None


def api_access(function: Callable):
    @wraps(function)
    def wrapped(*args, **kwargs):
        expected = current_app.config["SCANKEEP_ACCESS_TOKEN"]
        supplied = request.headers.get("Authorization", "")
        if not supplied.startswith("Bearer ") or not hmac.compare_digest(
            supplied[7:], expected
        ):
            return _error("Unauthorized", 401)
        return function(*args, **kwargs)

    return wrapped


@scankeep_bp.route("/scankeep")
def home():
    return render_template(
        "scankeep/home.html",
        active_page="home",
    )


@scankeep_bp.route("/scankeep/manual-scans")
def manual_scans():
    return render_template(
        "scankeep/manual_scans.html",
        active_page="manual_scans",
    )


@scankeep_bp.route("/scankeep/jobs/<job_id>")
def job_detail(job_id: str):
    return render_template(
        "scankeep/job.html",
        active_page="home",
        job_id=job_id,
    )


@scankeep_bp.route("/scankeep/presets")
def preset_list():
    return render_template("scankeep/presets.html", active_page="presets")


@scankeep_bp.route("/scankeep/presets/new")
def preset_create():
    return render_template("scankeep/preset_form.html", active_page="presets")


@scankeep_bp.route("/scankeep/presets/<preset_id>")
def preset_detail(preset_id: str):
    return render_template(
        "scankeep/preset_detail.html",
        active_page="presets",
        preset_id=preset_id,
    )


@scankeep_bp.route("/scankeep/schedules")
def schedule_list():
    return render_template("scankeep/schedules.html", active_page="schedules")


@scankeep_bp.route("/scankeep/schedules/new")
def schedule_create():
    return render_template(
        "scankeep/schedule_form.html",
        active_page="schedules",
    )


@scankeep_bp.route("/scankeep/schedules/<schedule_id>")
def schedule_detail(schedule_id: str):
    return render_template(
        "scankeep/schedule_detail.html",
        active_page="schedules",
        schedule_id=schedule_id,
    )


@scankeep_bp.route("/scankeep/servers")
def server_management():
    return render_template(
        "scankeep/servers.html",
        active_page="servers",
    )


@scankeep_bp.route("/scankeep/project-targets")
def project_target_management():
    return render_template(
        "scankeep/project_targets.html",
        active_page="project_targets",
    )


@scankeep_bp.route("/scankeep/servers/new")
def server_create():
    return render_template("scankeep/server_form.html", active_page="servers")


@scankeep_bp.route("/scankeep/servers/<server_id>")
def server_detail(server_id: str):
    return render_template(
        "scankeep/server_detail.html",
        active_page="servers",
        server_id=server_id,
    )


@scankeep_bp.route("/scankeep/project-targets/new")
def project_target_create():
    return render_template(
        "scankeep/project_target_form.html",
        active_page="project_targets",
    )


@scankeep_bp.route("/scankeep/project-targets/<project_target_id>")
def project_target_detail(project_target_id: str):
    return render_template(
        "scankeep/project_target_detail.html",
        active_page="project_targets",
        project_target_id=project_target_id,
    )


@scankeep_bp.route("/api/scankeep/auth", methods=["POST"])
@api_access
def authenticate():
    return jsonify({"authenticated": True})


@scankeep_bp.route("/api/scankeep/config")
@api_access
def config():
    return jsonify(
        {
            "encryption_ready": _store().encryption_ready,
            "runtime": _runner().runtime_status(),
        }
    )


@scankeep_bp.route("/api/scankeep/dashboard")
@api_access
def dashboard():
    return jsonify(_store().dashboard_summary())


@scankeep_bp.route("/api/scankeep/servers", methods=["GET", "POST"])
@api_access
def servers():
    if request.method == "GET":
        return jsonify({"servers": _store().list_servers()})
    try:
        data = _json()
        name = _required(data, "name", 120)
        url = normalize_sonar_url(_required(data, "url"))
        token = _required(data, "token")
        validate_sonar_server(url, token)
        server = _store().add_server(name, url, token)
        return jsonify(server), 201
    except (ValueError, ConnectionError) as exc:
        return _error(str(exc), 400)
    except ScankeepConfigError as exc:
        return _error(str(exc), 503)
    except sqlite3.IntegrityError:
        return _error("a SonarQube server with this name already exists", 409)


@scankeep_bp.route("/api/scankeep/servers/health")
@api_access
def server_health():
    store = _store()
    servers = store.list_servers()

    if not servers:
        return jsonify({"servers": []})
    with ThreadPoolExecutor(max_workers=min(8, len(servers))) as executor:
        results = list(executor.map(partial(_server_health, store), servers))
    return jsonify({"servers": results})


def _server_health(store, server: dict[str, Any]) -> dict[str, Any]:
    try:
        private = store.get_server(server["id"], include_token=True)
        health = check_sonar_server_health(private["url"], private["token"])
    except ScankeepConfigError as exc:
        health = {
            "healthy": False,
            "status": "CONFIGURATION_ERROR",
            "version": "",
            "latency_ms": 0,
            "error": str(exc),
        }
    return {**server, **health, "checked_at": utc_now()}


@scankeep_bp.route("/api/scankeep/servers/<server_id>/health")
@api_access
def server_item_health(server_id: str):
    try:
        store = _store()
        return jsonify(_server_health(store, store.get_server(server_id)))
    except KeyError:
        return _error("SonarQube server not found", 404)


@scankeep_bp.route(
    "/api/scankeep/servers/<server_id>", methods=["GET", "PATCH", "DELETE"]
)
@api_access
def server_item(server_id: str):
    try:
        if request.method == "GET":
            return jsonify(_store().get_server(server_id))
        if request.method == "PATCH":
            data = _json()
            current = _store().get_server(server_id, include_token=True)
            name = _required(data, "name", 120) if "name" in data else current["name"]
            url = (
                normalize_sonar_url(_required(data, "url"))
                if "url" in data
                else current["url"]
            )
            replacement = str(data.get("token") or "").strip()
            if url != current["url"] and not replacement:
                raise ValueError("token is required when changing the SonarQube URL")
            validate_sonar_server(url, replacement or current["token"])
            return jsonify(
                _store().update_server(
                    server_id,
                    name=name,
                    url=url,
                    token=replacement or None,
                )
            )
        _store().delete_server(server_id)
        return "", 204
    except KeyError:
        return _error("SonarQube server not found", 404)
    except (ValueError, ConnectionError) as exc:
        return _error(str(exc), 400)
    except ScankeepConfigError as exc:
        return _error(str(exc), 503)
    except sqlite3.IntegrityError:
        if request.method == "PATCH":
            return _error("a SonarQube server with this name already exists", 409)
        return _error(
            "delete associated project targets before deleting this server", 409
        )


@scankeep_bp.route("/api/scankeep/project-targets", methods=["GET", "POST"])
@api_access
def project_targets():
    if request.method == "GET":
        return jsonify({"project_targets": _store().list_project_targets()})
    try:
        data = _json()
        name = _required(data, "name", 120)
        provider = _required(data, "provider").lower()
        url = normalize_repository_url(_required(data, "url"), provider)
        token = _required(data, "token")
        server_id = _required(data, "security_server_id")
        project_key = _required(data, "project_key", 400)
        scan_path = normalize_scan_path(str(data.get("scan_path") or ""))
        _store().get_server(server_id)
        branches = list_remote_branches(url, provider, token)
        if not branches:
            raise ConnectionError("project target has no branches")
        project_target = _store().add_project_target(
            name=name,
            provider=provider,
            url=url,
            token=token,
            security_server_id=server_id,
            project_key=project_key,
            scan_path=scan_path,
        )
        return jsonify(project_target), 201
    except KeyError:
        return _error("SonarQube server not found", 404)
    except (ValueError, ConnectionError) as exc:
        return _error(str(exc), 400)
    except ScankeepConfigError as exc:
        return _error(str(exc), 503)
    except sqlite3.IntegrityError:
        return _error("a project target with this name already exists", 409)


@scankeep_bp.route(
    "/api/scankeep/project-targets/<project_target_id>",
    methods=["GET", "PATCH", "DELETE"],
)
@api_access
def project_target_item(project_target_id: str):
    try:
        if request.method == "GET":
            return jsonify(_store().get_project_target(project_target_id))
        if request.method == "PATCH":
            data = _json()
            current = _store().get_project_target(
                project_target_id, include_tokens=True
            )
            name = _required(data, "name", 120) if "name" in data else current["name"]
            provider = (
                _required(data, "provider").lower()
                if "provider" in data
                else current["provider"]
            )
            url = normalize_repository_url(
                _required(data, "url") if "url" in data else current["url"],
                provider,
            )
            replacement = str(data.get("token") or "").strip()
            token = replacement or current["token"]
            server_id = (
                _required(data, "security_server_id")
                if "security_server_id" in data
                else current["security_server_id"]
            )
            project_key = (
                _required(data, "project_key", 400)
                if "project_key" in data
                else current["project_key"]
            )
            scan_path = (
                normalize_scan_path(str(data.get("scan_path") or ""))
                if "scan_path" in data
                else current["scan_path"]
            )
            if (
                url != current["url"] or provider != current["provider"]
            ) and not replacement:
                raise ValueError(
                    "token is required when changing the repository URL or provider"
                )
            _store().get_server(server_id)
            branches = list_remote_branches(url, provider, token)
            if not branches:
                raise ConnectionError("project target has no branches")
            return jsonify(
                _store().update_project_target(
                    project_target_id,
                    name=name,
                    provider=provider,
                    url=url,
                    token=replacement or None,
                    security_server_id=server_id,
                    project_key=project_key,
                    scan_path=scan_path,
                )
            )
        _store().delete_project_target(project_target_id)
        return "", 204
    except KeyError:
        return _error("project target not found", 404)
    except (ValueError, ConnectionError) as exc:
        return _error(str(exc), 400)
    except ScankeepConfigError as exc:
        return _error(str(exc), 503)
    except sqlite3.IntegrityError:
        if request.method == "PATCH":
            return _error("a project target with this name already exists", 409)
        return _error(
            "project targets used by scan history, presets, or schedules "
            "cannot be deleted",
            409,
        )


@scankeep_bp.route("/api/scankeep/project-targets/<project_target_id>/branches")
@api_access
def project_target_branches(project_target_id: str):
    try:
        project_target = _store().get_project_target(
            project_target_id, include_tokens=True
        )
        branches = list_remote_branches(
            project_target["url"],
            project_target["provider"],
            project_target["token"],
        )
        return jsonify({"branches": branches})
    except KeyError:
        return _error("project target not found", 404)
    except (ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)


def _project_target_for_branch(
    project_target_id: str,
    branch: str,
    *,
    expected_server_id: str | None = None,
    expected_project_key: str | None = None,
) -> dict[str, Any]:
    project_target = _store().get_project_target(project_target_id, include_tokens=True)
    if (
        expected_server_id
        and expected_server_id != project_target["security_server_id"]
    ):
        raise ValueError("selected server does not match the project target")
    if expected_project_key and expected_project_key != project_target["project_key"]:
        raise ValueError("selected project key does not match the project target")
    branches = list_remote_branches(
        project_target["url"], project_target["provider"], project_target["token"]
    )
    if branch not in branches:
        raise ValueError("selected branch no longer exists on the remote")
    return project_target


def _start_scan(
    project_target_id: str,
    branch: str,
    *,
    label: str,
    preset_id: str | None = None,
    preset_name: str = "",
    schedule_id: str | None = None,
    schedule_name: str = "",
    trigger_source: str = "manual",
    expected_server_id: str | None = None,
    expected_project_key: str | None = None,
) -> dict[str, Any]:
    _project_target_for_branch(
        project_target_id,
        branch,
        expected_server_id=expected_server_id,
        expected_project_key=expected_project_key,
    )
    _runner().ensure_runtime()
    return _runner().start(
        project_target_id,
        branch,
        label=label,
        preset_id=preset_id,
        preset_name=preset_name,
        schedule_id=schedule_id,
        schedule_name=schedule_name,
        trigger_source=trigger_source,
    )


@scankeep_bp.route("/api/scankeep/scans", methods=["GET", "POST"])
@api_access
def scans():
    if request.method == "GET":
        try:
            source = _query_filter("trigger_source", 20)
            status = _query_filter("status", 20)
            result_status = _query_filter("result_status", 20)
            if source and source not in {"manual", "preset", "schedule"}:
                raise ValueError("invalid trigger_source")
            if status and status not in {"queued", "running", "succeeded", "failed"}:
                raise ValueError("invalid status")
            if result_status and result_status not in {
                "passed",
                "failed",
                "pending",
                "unavailable",
                "other",
            }:
                raise ValueError("invalid result_status")
            return jsonify(
                {
                    "scans": _runner().list_jobs(
                        trigger_source=source,
                        preset_id=_query_filter("preset_id"),
                        schedule_id=_query_filter("schedule_id"),
                        project_key=_query_filter("project_key"),
                        project_target_id=_query_filter("project_target_id"),
                        label=_query_filter("label", 120),
                        status=status,
                        result_status=result_status,
                    )
                }
            )
        except ValueError as exc:
            return _error(str(exc), 400)
    try:
        data = _json()
        project_target_id = _required(data, "project_target_id")
        branch = _required(data, "branch")
        label = _optional(data, "label")
        job = _start_scan(
            project_target_id,
            branch,
            label=label,
            expected_server_id=_required(data, "security_server_id"),
            expected_project_key=_required(data, "project_key", 400),
        )
        return jsonify(job), 202
    except KeyError:
        return _error("project target not found", 404)
    except (ValueError, ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except RuntimeError as exc:
        return _error(str(exc), 503)


@scankeep_bp.route("/api/scankeep/scans/<job_id>")
@api_access
def scan(job_id: str):
    try:
        job = _runner().get_job(job_id)
        job["log"] = _runner().read_log(job_id)
        return jsonify(job)
    except KeyError:
        return _error("scan not found", 404)


@scankeep_bp.route("/api/scankeep/presets", methods=["GET", "POST"])
@api_access
def presets():
    if request.method == "GET":
        return jsonify({"presets": _store().list_presets()})
    try:
        data = _json()
        name = _required(data, "name", 120)
        project_target_id = _required(data, "project_target_id")
        branch = _required(data, "branch")
        label = _optional(data, "label")
        _project_target_for_branch(
            project_target_id,
            branch,
            expected_server_id=str(data.get("security_server_id") or "") or None,
            expected_project_key=str(data.get("project_key") or "") or None,
        )
        preset = _store().add_preset(
            name=name,
            project_target_id=project_target_id,
            branch=branch,
            label=label,
        )
        return jsonify(preset), 201
    except KeyError:
        return _error("project target not found", 404)
    except (ValueError, ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except sqlite3.IntegrityError:
        return _error("a scan preset with this name already exists", 409)


@scankeep_bp.route(
    "/api/scankeep/presets/<preset_id>",
    methods=["GET", "PATCH", "DELETE"],
)
@api_access
def preset_item(preset_id: str):
    try:
        if request.method == "GET":
            return jsonify(_store().get_preset(preset_id))
        if request.method == "PATCH":
            data = _json()
            _store().get_preset(preset_id)
            project_target_id = _required(data, "project_target_id")
            branch = _required(data, "branch")
            try:
                _project_target_for_branch(
                    project_target_id,
                    branch,
                    expected_server_id=(
                        str(data.get("security_server_id") or "") or None
                    ),
                    expected_project_key=str(data.get("project_key") or "") or None,
                )
            except KeyError:
                return _error("project target not found", 404)
            return jsonify(
                _store().update_preset(
                    preset_id,
                    name=_required(data, "name", 120),
                    project_target_id=project_target_id,
                    branch=branch,
                    label=_optional(data, "label"),
                )
            )
        _store().delete_preset(preset_id)
        return "", 204
    except KeyError:
        return _error("scan preset not found", 404)
    except (ValueError, ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except sqlite3.IntegrityError:
        return _error("a scan preset with this name already exists", 409)


@scankeep_bp.route("/api/scankeep/presets/<preset_id>/scans", methods=["POST"])
@api_access
def run_preset(preset_id: str):
    try:
        preset = _store().get_preset(preset_id)
        job = _start_scan(
            preset["project_target_id"],
            preset["branch"],
            label=preset["label"] or preset["name"],
            preset_id=preset_id,
            preset_name=preset["name"],
            trigger_source="preset",
        )
        return jsonify(job), 202
    except KeyError:
        return _error("scan preset not found", 404)
    except (ValueError, ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except RuntimeError as exc:
        return _error(str(exc), 503)


@scankeep_bp.route("/api/scankeep/schedules", methods=["GET", "POST"])
@api_access
def schedules():
    if request.method == "GET":
        return jsonify({"schedules": _store().list_schedules()})
    try:
        data = _json()
        project_target_id = _required(data, "project_target_id")
        branch = _required(data, "branch")
        _project_target_for_branch(
            project_target_id,
            branch,
            expected_server_id=str(data.get("security_server_id") or "") or None,
            expected_project_key=str(data.get("project_key") or "") or None,
        )
        expression = normalize_cron(_required(data, "cron_expression", 200))
        next_run = next_cron_run(expression, utc_now())
        schedule = _store().add_schedule(
            name=_required(data, "name", 120),
            project_target_id=project_target_id,
            branch=branch,
            label=_optional(data, "label"),
            cron_expression=expression,
            next_run_at=next_run,
        )
        return jsonify(schedule), 201
    except KeyError:
        return _error("project target not found", 404)
    except (ValueError, ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except sqlite3.IntegrityError:
        return _error("a scan schedule with this name already exists", 409)


@scankeep_bp.route(
    "/api/scankeep/schedules/<schedule_id>",
    methods=["GET", "PATCH", "DELETE"],
)
@api_access
def schedule_item(schedule_id: str):
    try:
        if request.method == "GET":
            return jsonify(_store().get_schedule(schedule_id))
        if request.method == "PATCH":
            data = _json()
            current = _store().get_schedule(schedule_id)
            enabled = data.get("enabled", current["enabled"])
            if not isinstance(enabled, bool):
                raise ValueError("enabled must be true or false")
            project_target_id = (
                _required(data, "project_target_id")
                if "project_target_id" in data
                else current["project_target_id"]
            )
            branch = (
                _required(data, "branch") if "branch" in data else current["branch"]
            )
            changed_target = {
                "project_target_id",
                "branch",
                "security_server_id",
                "project_key",
            } & data.keys()
            if changed_target:
                try:
                    _project_target_for_branch(
                        project_target_id,
                        branch,
                        expected_server_id=(
                            str(data.get("security_server_id") or "") or None
                        ),
                        expected_project_key=(
                            str(data.get("project_key") or "") or None
                        ),
                    )
                except KeyError:
                    return _error("project target not found", 404)
            expression = (
                normalize_cron(_required(data, "cron_expression", 200))
                if "cron_expression" in data
                else None
            )
            return jsonify(
                _store().update_schedule(
                    schedule_id,
                    enabled=enabled,
                    name=(_required(data, "name", 120) if "name" in data else None),
                    project_target_id=(
                        project_target_id if "project_target_id" in data else None
                    ),
                    branch=branch if "branch" in data else None,
                    label=_optional(data, "label") if "label" in data else None,
                    cron_expression=expression,
                )
            )
        _store().delete_schedule(schedule_id)
        return "", 204
    except KeyError:
        return _error("scan schedule not found", 404)
    except ValueError as exc:
        return _error(str(exc), 400)
    except (ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except sqlite3.IntegrityError:
        return _error("a scan schedule with this name already exists", 409)


@scankeep_bp.route("/api/scankeep/schedules/<schedule_id>/scans", methods=["POST"])
@api_access
def run_schedule(schedule_id: str):
    try:
        schedule = _store().get_schedule(schedule_id)
        job = _start_scan(
            schedule["project_target_id"],
            schedule["branch"],
            label=schedule["label"] or schedule["name"],
            schedule_id=schedule_id,
            schedule_name=schedule["name"],
            trigger_source="schedule",
        )
        _store().record_schedule_run(schedule_id)
        return jsonify(job), 202
    except KeyError:
        return _error("scan schedule not found", 404)
    except (ValueError, ConnectionError, ScankeepConfigError) as exc:
        return _error(str(exc), 400)
    except RuntimeError as exc:
        return _error(str(exc), 503)
