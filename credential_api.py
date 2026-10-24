"""Read credentials belonging to the current Windows logon session."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class Credential:
    target: str
    username: str
    kind: int
    persistence: int
    modified: str
    blob: bytes
    comment: str = ""
    alias: str = ""
    source: str = "Windows Credential Manager"
    extra_blob: bytes = b""


TYPE_NAMES = {
    1: "Generic",
    2: "Domain Password",
    3: "Domain Certificate",
    4: "Domain Visible Password",
    5: "Generic Certificate",
    6: "Domain Extended",
}
PERSIST_NAMES = {1: "Session", 2: "Local Machine", 3: "Enterprise"}


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def _filetime_iso(value: FILETIME) -> str:
    ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
    if not ticks:
        return ""
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)).isoformat(timespec="seconds")
    except OverflowError:
        return ""


def read_current_credentials() -> list[Credential]:
    """Enumerate credentials exposed to this user's current logon token."""
    if os.name != "nt":
        raise OSError("Chế độ online chỉ hỗ trợ Windows.")

    dll = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    dll.CredEnumerateW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(CREDENTIALW))),
    ]
    dll.CredEnumerateW.restype = wintypes.BOOL
    dll.CredFree.argtypes = [ctypes.c_void_p]
    dll.CredFree.restype = None

    count = wintypes.DWORD()
    items = ctypes.POINTER(ctypes.POINTER(CREDENTIALW))()
    if not dll.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(items)):
        code = ctypes.get_last_error()
        if code == 1168:  # ERROR_NOT_FOUND
            return []
        raise ctypes.WinError(code)

    result = []
    try:
        for index in range(count.value):
            item = items[index].contents
            blob = (
                ctypes.string_at(item.CredentialBlob, item.CredentialBlobSize)
                if item.CredentialBlob and item.CredentialBlobSize
                else b""
            )
            result.append(
                Credential(
                    target=item.TargetName or "",
                    username=item.UserName or "",
                    kind=item.Type,
                    persistence=item.Persist,
                    modified=_filetime_iso(item.LastWritten),
                    blob=blob,
                    comment=item.Comment or "",
                    alias=item.TargetAlias or "",
                )
            )
    finally:
        dll.CredFree(items)
    return result


def display_secret(blob: bytes) -> str:
    """Present text blobs as text; retain binary blobs as hexadecimal."""
    if not blob:
        return ""
    looks_utf16 = len(blob) % 2 == 0 and (
        blob.startswith(b"\xff\xfe") or blob[1::2].count(0) >= max(1, len(blob) // 6)
    )
    encodings = ("utf-16-le", "utf-8") if looks_utf16 else ("utf-8",)
    for encoding in encodings:
        try:
            value = blob.decode(encoding).rstrip("\x00")
        except UnicodeDecodeError:
            continue
        if value and all(char.isprintable() or char in "\r\n\t" for char in value):
            return value
    return blob.hex(" ")
