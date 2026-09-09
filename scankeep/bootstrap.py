"""Create, inspect, and explicitly rotate deployment secrets."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


def _write_secret(path: Path, value: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(f"{value}\n")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def initialize(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    access_path = directory / "access_token"
    encryption_path = directory / "encryption_key"
    access_exists = access_path.exists() and bool(
        access_path.read_text(encoding="utf-8").strip()
    )
    encryption_exists = encryption_path.exists() and bool(
        encryption_path.read_text(encoding="utf-8").strip()
    )
    if access_exists != encryption_exists:
        raise SystemExit(
            "deployment secrets are incomplete; restore the missing secret or "
            "remove both files for a new deployment"
        )
    if access_exists:
        access_path.chmod(0o600)
        encryption_path.chmod(0o600)
        print("Existing deployment secrets preserved.")
        return

    access_token = secrets.token_urlsafe(32)
    _write_secret(access_path, access_token)
    _write_secret(encryption_path, Fernet.generate_key().decode())
    print(f"Initial access token: {access_token}")
    print("Store this token securely. It will not be printed on later deployments.")


def rotate_access_token(directory: Path) -> None:
    encryption_path = directory / "encryption_key"
    try:
        encryption_key = encryption_path.read_text(encoding="utf-8").strip()
        Fernet(encryption_key.encode())
    except (OSError, TypeError, ValueError) as exc:
        raise SystemExit(
            "a valid encryption key is required before rotating the access token"
        ) from exc
    directory.chmod(0o700)
    access_token = secrets.token_urlsafe(32)
    _write_secret(directory / "access_token", access_token)
    print(f"New access token: {access_token}")
    print("Store this token securely and restart Scankeep to activate it.")


def show_access_token(directory: Path) -> None:
    path = directory / "access_token"
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"cannot read access token: {exc}") from exc
    if not token:
        raise SystemExit("access token is empty; run the deployment bootstrap first")
    print(token)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=("init", "rotate-access-token", "show-access-token"),
    )
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    if arguments.action == "init":
        initialize(arguments.directory)
    elif arguments.action == "rotate-access-token":
        rotate_access_token(arguments.directory)
    else:
        show_access_token(arguments.directory)


if __name__ == "__main__":
    main()
