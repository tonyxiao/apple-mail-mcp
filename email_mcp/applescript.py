"""Shared macOS AppleScript error vocabulary.

Refresh, doctor, and triage intentionally keep separate subprocess seams:
they invoke different scripts, accept different inputs, and have different
recovery policies.  Numeric AppleScript interpretation is common, though,
and must not drift between those callers.
"""
from __future__ import annotations

import ctypes
import sys


# Stable osascript/Apple Event error numbers observed across the Mail and
# System Events integrations.
NOT_AUTHORIZED = -1743
NO_APP = -1728
ASSISTIVE_ACCESS_DENIED = frozenset({-1719, -25211})
ACCESSIBILITY_DENIED = ASSISTIVE_ACCESS_DENIED | {NOT_AUTHORIZED}
EVENT_HANDLER_FAILED = -10000


def automation_permission(bundle_id: str) -> int | None:
    """Inspect this process's Apple Events grant without requesting consent.

    The native CLI, rather than a generic Python subprocess, must perform
    this check so macOS evaluates the same identity that sends the event.
    None is only used off macOS. Failure to inspect a grant fails closed.
    """
    if sys.platform != "darwin":
        return None

    class AEDesc(ctypes.Structure):
        _fields_ = [("descriptorType", ctypes.c_uint32),
                    ("dataHandle", ctypes.c_void_p)]

    try:
        library = ctypes.CDLL(
            "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
        )
        library.AECreateDesc.argtypes = [ctypes.c_uint32, ctypes.c_void_p,
                                       ctypes.c_ssize_t, ctypes.POINTER(AEDesc)]
        library.AECreateDesc.restype = ctypes.c_int32
        library.AEDisposeDesc.argtypes = [ctypes.POINTER(AEDesc)]
        library.AEDisposeDesc.restype = ctypes.c_int32
        determine = library.AEDeterminePermissionToAutomateTarget
        determine.argtypes = [ctypes.POINTER(AEDesc), ctypes.c_uint32,
                              ctypes.c_uint32, ctypes.c_uint8]
        determine.restype = ctypes.c_int32
        target = AEDesc()
        identifier = bundle_id.encode("utf-8")
        status = library.AECreateDesc(int.from_bytes(b"bund", "big"),
                                     identifier, len(identifier), ctypes.byref(target))
        if status != 0:
            return status
        try:
            wildcard = int.from_bytes(b"****", "big")
            return determine(ctypes.byref(target), wildcard, wildcard, 0)
        finally:
            library.AEDisposeDesc(ctypes.byref(target))
    except (OSError, AttributeError):
        return NOT_AUTHORIZED


def permission_denial(script: str) -> str | None:
    """Refuse unattended AppleScript before it could show a TCC dialog."""
    for application, bundle_id in (("Mail", "com.apple.mail"),
                                   ("System Events", "com.apple.systemevents")):
        if f'application "{application}"' not in script:
            continue
        status = automation_permission(bundle_id)
        if status in (None, 0):
            continue
        if status == -600:  # procNotFound: do not launch an app from a probe
            return f"{application} is not running ({NO_APP})"
        return (
            f"{application} automation permission is unavailable (native status {status}). "
            "Grant the dedicated Apple Mail MCP CLI permission in System Settings > "
            "Privacy & Security > Automation during setup. "
            f"Background calls never request consent. ({NOT_AUTHORIZED})"
        )
    return None


def error_code(stderr: str | None) -> int | None:
    """Extract the trailing ``(-1234)`` code from osascript stderr.

    The parser is deliberately total: malformed, absent, or non-numeric
    suffixes return ``None`` rather than creating a second failure while an
    original AppleScript failure is being reported.
    """
    text = (stderr or "").strip()
    if "(-" not in text or not text.endswith(")"):
        return None
    try:
        return int(text.rsplit("(", 1)[1][:-1])
    except ValueError:
        return None
