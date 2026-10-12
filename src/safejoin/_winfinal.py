"""Ask Windows for the final path of an open file descriptor (Windows only)."""

from __future__ import annotations

import sys

if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _GET_FINAL = _KERNEL32.GetFinalPathNameByHandleW
    _GET_FINAL.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    _GET_FINAL.restype = wintypes.DWORD
    # FILE_NAME_NORMALIZED | VOLUME_NAME_DOS: a "\\?\C:\..." or "\\?\UNC\..." path.
    _FLAGS = 0

    def final_path(fd: int) -> str:
        """Return the normalised path of the file the descriptor really refers to."""
        handle = msvcrt.get_osfhandle(fd)
        size = 512
        while True:
            buffer = ctypes.create_unicode_buffer(size)
            length = _GET_FINAL(handle, buffer, size, _FLAGS)
            if length == 0:
                raise ctypes.WinError(ctypes.get_last_error())
            if length < size:
                return buffer.value
            size = length + 1
