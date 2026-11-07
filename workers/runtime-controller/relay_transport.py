#!/usr/bin/python3 -I
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Host Unix-only bridge. The peer check and all traffic use the same socket."""
import ctypes
import os
import selectors
import socket
import struct
import sys


def peer_uid(connection: socket.socket) -> int:
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        function = library.getpeereid
        function.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint))
        function.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if function(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), "peer_identity")
        return uid.value
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack("3i", credentials)[1]


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("/") or len(sys.argv[1].encode()) > 100:
        raise ValueError("relay_path")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect(sys.argv[1])
        if peer_uid(connection) != os.getuid():
            raise PermissionError("relay_peer")
        connection.settimeout(None)
        with selectors.DefaultSelector() as events:
            events.register(0, selectors.EVENT_READ)
            events.register(connection, selectors.EVENT_READ)
            while True:
                for key, _ in events.select():
                    if key.fd == 0:
                        data = os.read(0, 65536)
                        if not data:
                            connection.shutdown(socket.SHUT_WR)
                            return
                        connection.sendall(data)
                    else:
                        data = connection.recv(65536)
                        if not data:
                            return
                        view = memoryview(data)
                        while view:
                            written = os.write(1, view)
                            view = view[written:]


if __name__ == "__main__":
    main()
