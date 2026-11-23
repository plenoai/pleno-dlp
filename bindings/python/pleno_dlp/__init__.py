"""Python bindings for pleno-dlp's stable embeddable API (docs/library.md).

The package loads the bundled ``libpleno_dlp`` shared library through
:mod:`ctypes`; no compiler is needed at install time. Set
``PLENO_DLP_LIBRARY`` to load a library from another path.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from ._version import __version__

__all__ = [
    "Detector",
    "Finding",
    "PlenoDLPError",
    "RevokeResult",
    "VerifyResult",
    "__version__",
    "api_version",
    "detectors",
    "revoke",
    "scan_bytes",
    "scan_paths",
    "verify",
]


class PlenoDLPError(Exception):
    """Raised when the native API returns an error envelope.

    ``code`` is one of ``unknown_detector``, ``not_supported``,
    ``not_confirmed``, ``invalid_argument`` or ``internal``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Finding:
    detector: str
    verified: bool
    verdict: str
    severity: str
    redacted: str
    assurance: str = ""
    raw: str = ""
    raw_v2: str = ""
    path: str = ""
    line: int = 0
    verify_error: str = ""
    extra_data: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class VerifyResult:
    detector: str
    verified: bool
    error: str = ""


@dataclass(frozen=True)
class RevokeResult:
    detector: str
    revoked: bool
    dry_run: bool = False
    revoked_at: str = ""
    provider_id: str = ""
    note: str = ""


@dataclass(frozen=True)
class Detector:
    name: str
    keywords: List[str]
    can_verify: bool
    can_revoke: bool


def _lib_name() -> str:
    if sys.platform == "darwin":
        return "libpleno_dlp.dylib"
    if sys.platform == "win32":
        return "pleno_dlp.dll"
    return "libpleno_dlp.so"


def _load() -> ctypes.CDLL:
    override = os.environ.get("PLENO_DLP_LIBRARY")
    path = Path(override) if override else Path(__file__).parent / "lib" / _lib_name()
    if not path.exists():
        raise ImportError(
            f"pleno-dlp native library not found at {path} "
            f"({sys.platform}/{platform.machine()} may be unsupported; see docs/library.md)"
        )
    lib = ctypes.CDLL(str(path))
    c = ctypes.c_char_p
    vp = ctypes.c_void_p
    for name, args in {
        "pleno_dlp_version": [],
        "pleno_dlp_detectors": [],
        "pleno_dlp_scan_bytes": [c, ctypes.c_longlong, c],
        "pleno_dlp_scan_paths": [c, c],
        "pleno_dlp_verify": [c, c],
        "pleno_dlp_revoke": [c, c, c],
    }.items():
        fn = getattr(lib, name)
        fn.argtypes = args
        fn.restype = vp  # keep the pointer so it can be freed
    lib.pleno_dlp_free.argtypes = [vp]
    lib.pleno_dlp_free.restype = None
    return lib


_LIB: Optional[ctypes.CDLL] = None


def _lib() -> ctypes.CDLL:
    global _LIB
    if _LIB is None:
        _LIB = _load()
    return _LIB


def _call(name: str, *args: Any) -> Any:
    lib = _lib()
    ptr = getattr(lib, name)(*args)
    try:
        raw = ctypes.string_at(ptr)
    finally:
        lib.pleno_dlp_free(ptr)
    env = json.loads(raw)
    err = env.get("error")
    if err:
        raise PlenoDLPError(err.get("code", "internal"), err.get("message", ""))
    return env.get("ok")


def _enc(s: str) -> bytes:
    return s.encode("utf-8")


def _opts(
    verify: bool,
    include_raw: bool,
    detectors: Optional[Iterable[str]],
    concurrency: int,
    max_file_size: int,
) -> bytes:
    o: Dict[str, Any] = {"verify": verify, "include_raw": include_raw}
    if detectors:
        o["detectors"] = list(detectors)
    if concurrency:
        o["concurrency"] = concurrency
    if max_file_size:
        o["max_file_size"] = max_file_size
    return _enc(json.dumps(o))


def api_version() -> str:
    """Return the native contract version (``dlp.APIVersion``)."""
    return _call("pleno_dlp_version")


def detectors() -> List[Detector]:
    """Return every registered detector sorted by name."""
    return [Detector(**d) for d in _call("pleno_dlp_detectors")]


def scan_bytes(
    data: Union[bytes, str],
    *,
    verify: bool = False,
    include_raw: bool = False,
    detectors: Optional[Iterable[str]] = None,
    concurrency: int = 0,
) -> List[Finding]:
    """Scan an in-memory buffer. Offline and redacted unless opted in."""
    buf = _enc(data) if isinstance(data, str) else bytes(data)
    out = _call(
        "pleno_dlp_scan_bytes",
        buf,
        len(buf),
        _opts(verify, include_raw, detectors, concurrency, 0),
    )
    return [Finding(**f) for f in out]


def scan_paths(
    paths: Union[str, os.PathLike, Sequence[Union[str, os.PathLike]]],
    *,
    verify: bool = False,
    include_raw: bool = False,
    detectors: Optional[Iterable[str]] = None,
    concurrency: int = 0,
    max_file_size: int = 0,
) -> List[Finding]:
    """Recursively scan files and directories."""
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    plist = [os.fspath(p) for p in paths]
    out = _call(
        "pleno_dlp_scan_paths",
        _enc(json.dumps(plist)),
        _opts(verify, include_raw, detectors, concurrency, max_file_size),
    )
    return [Finding(**f) for f in out]


def verify(detector: str, secret: str) -> VerifyResult:
    """Ask the detector's provider whether ``secret`` is live (network call)."""
    return VerifyResult(**_call("pleno_dlp_verify", _enc(detector), _enc(secret)))


def revoke(detector: str, secret: str, *, confirm: bool = False, dry_run: bool = False) -> RevokeResult:
    """Irreversibly revoke ``secret``. Exactly one of ``confirm``/``dry_run`` is required."""
    opts = _enc(json.dumps({"confirm": confirm, "dry_run": dry_run}))
    return RevokeResult(**_call("pleno_dlp_revoke", _enc(detector), _enc(secret), opts))
