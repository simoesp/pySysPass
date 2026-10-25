"""Content-based MIME detection, as PHP ``mime_content_type()`` does.

PHP's fileinfo extension is built on libmagic; this calls the system libmagic
(``libmagic1`` in the container image) through ctypes, so no Python binding
is needed. When libmagic is missing, detection returns None and callers fall
back to the declared type only.
"""
import ctypes
import ctypes.util
import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_MAGIC_MIME_TYPE = 0x10
_lock = threading.Lock()  # a libmagic cookie is not thread-safe
_cookie = None
_lib = None
_loaded = False


def _load():
    global _cookie, _lib, _loaded
    _loaded = True
    path = ctypes.util.find_library("magic")
    if not path:
        logger.warning("libmagic not found; uploads are checked by declared MIME type only")
        return
    try:
        lib = ctypes.CDLL(path)
        lib.magic_open.restype = ctypes.c_void_p
        lib.magic_open.argtypes = [ctypes.c_int]
        lib.magic_load.restype = ctypes.c_int
        lib.magic_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.magic_buffer.restype = ctypes.c_char_p
        lib.magic_buffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        cookie = lib.magic_open(_MAGIC_MIME_TYPE)
        if not cookie or lib.magic_load(cookie, None) != 0:
            raise OSError("magic_load failed")
    except (OSError, AttributeError):
        logger.warning("libmagic could not be loaded; uploads are checked by declared MIME type only")
        return
    _lib, _cookie = lib, cookie


def detect_mime(content: bytes) -> Optional[str]:
    """The MIME type libmagic reports for ``content``, or None if unavailable."""
    with _lock:
        if not _loaded:
            _load()
        if _cookie is None:
            return None
        result = _lib.magic_buffer(_cookie, content, len(content))
    return result.decode("ascii", "replace").lower() if result else None


def available() -> bool:
    with _lock:
        if not _loaded:
            _load()
        return _cookie is not None
