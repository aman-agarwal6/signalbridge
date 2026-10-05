"""Read available physical memory directly; no WMI process or machine changes."""

import ctypes
import sys

from .verification import LabControlError


class MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("load", ctypes.c_uint32),
        *[
            (name, ctypes.c_uint64)
            for name in (
                "total_physical",
                "available_physical",
                "total_commit",
                "available_commit",
                "total_virtual",
                "available_virtual",
                "reserved",
            )
        ],
    ]


def available_memory():
    if sys.platform != "win32":
        raise LabControlError("The reviewed Windows memory probe is required.")
    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    library = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    query = library.GlobalMemoryStatusEx
    query.argtypes = [ctypes.POINTER(MemoryStatus)]
    query.restype = ctypes.c_int
    if (
        status.length != 64
        or not query(ctypes.byref(status))
        or status.reserved != 0
        or status.load > 100
        or not 0 < status.total_physical <= 1024 * 1024**3
        or status.available_physical > status.total_physical
    ):
        raise LabControlError("Available physical memory could not be verified.")
    return int(status.available_physical)
