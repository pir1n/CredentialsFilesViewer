"""Decrypt Windows Credential files using offline DPAPI Protect artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from credential_api import Credential

SID_PATTERN = re.compile(r"S-1-\d+(?:-\d+)+", re.IGNORECASE)
GUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
MAX_ARTIFACT_SIZE = 4 * 1024 * 1024


@dataclass
class OfflineResult:
    credentials: list[Credential]
    masterkey_count: int
    file_count: int
    failures: list[str]


def find_sid_directories(protect_dir: str | Path) -> dict[str, Path]:
    path = Path(protect_dir)
    if not path.is_dir():
        raise ValueError("Thư mục Protect không tồn tại.")
    if SID_PATTERN.fullmatch(path.name):
        return {path.name: path}
    return {child.name: child for child in path.iterdir() if child.is_dir() and SID_PATTERN.fullmatch(child.name)}


def _filetime(value: int) -> str:
    if not value:
        return ""
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)).isoformat(timespec="seconds")
    except (ValueError, OverflowError):
        return ""


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            return value.hex(" ")
    return value.rstrip("\x00")


def read_offline_credentials(
    credentials_dir: str | Path,
    protect_dir: str | Path,
    sid: str,
    *,
    password: str | None = None,
    masterkeys_json: str | Path | None = None,
) -> OfflineResult:
    """Read artifact copies; never changes files in the evidence directories."""
    from pypykatz.dpapi.dpapi import DPAPI

    credentials_path = Path(credentials_dir)
    if not credentials_path.is_dir():
        raise ValueError("Thư mục Credentials không tồn tại.")
    sid_dirs = find_sid_directories(protect_dir)
    if sid not in sid_dirs:
        raise ValueError("Không tìm thấy thư mục SID đã chọn trong Protect.")
    if password is None and masterkeys_json is None:
        raise ValueError("Cần mật khẩu Windows của tài khoản hoặc file masterkeys JSON đã giải mã.")

    dpapi = DPAPI()
    if masterkeys_json is not None:
        dpapi.load_masterkeys(str(masterkeys_json))
    if password is not None:
        dpapi.get_prekeys_from_password(sid, password=password)

    failures = []
    for path in sorted(sid_dirs[sid].iterdir()):
        if not path.is_file() or not GUID_PATTERN.fullmatch(path.name):
            continue
        try:
            if path.stat().st_size > MAX_ARTIFACT_SIZE:
                raise ValueError("file quá lớn")
            dpapi.decrypt_masterkey_file(str(path))
        except Exception as exc:
            failures.append(f"Master key {path.name}: {type(exc).__name__}: {exc}")
    masterkey_count = len(dpapi.masterkeys) + len(dpapi.backupkeys)
    if masterkey_count == 0:
        raise ValueError("Không giải mã được DPAPI master key. Kiểm tra SID, mật khẩu hoặc masterkeys JSON.")

    credentials = []
    files = sorted(path for path in credentials_path.iterdir() if path.is_file())
    for path in files:
        try:
            if path.stat().st_size > MAX_ARTIFACT_SIZE:
                raise ValueError("file quá lớn")
            record = dpapi.decrypt_credential_file(str(path))
            blob = record.unknown4_raw or b""
            extra_blob = record.unknown3_raw or b""
            credentials.append(Credential(
                target=_text(record.target) or path.name,
                username=_text(record.username),
                kind=record.type,
                persistence=record.persist,
                modified=_filetime(record.last_written),
                blob=blob,
                comment=_text(record.description),
                alias=_text(record.target_alias),
                source=str(path),
                extra_blob=extra_blob,
            ))
        except Exception as exc:
            failures.append(f"Credential {path.name}: {type(exc).__name__}: {exc}")
    return OfflineResult(credentials, masterkey_count, len(files), failures)
