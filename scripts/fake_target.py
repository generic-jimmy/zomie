#!/usr/bin/env python3
"""Fake PHP target for testing the php2shell console diagnostics.

Modes:
  plain  - HTTP 200, no Set-Cookie header
  cookie - HTTP 200 with a Set-Cookie: PHPSESSID=<1200 junk bytes>; path=/
  tcp    - accepts TCP and closes immediately (no HTTP response)

Usage: python3 fake_target.py <port> <mode>
"""
import socket
import sys
import threading

JUNK = b"A" * 1200


def http_mode(port: int, mode: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    def handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(30)
            data = b""
            # read request head
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            # read body per Content-Length so uploads complete cleanly
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
            cl = 0
            for line in head.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
            body = data.split(b"\r\n\r\n", 1)[1]
            while len(body) < cl:
                chunk = conn.recv(1 << 20)
                if not chunk:
                    break
                body += chunk
            cookie = (b"Set-Cookie: PHPSESSID=" + JUNK + b"; path=/\r\n"
                      if mode == "cookie" else b"")
            resp = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    + cookie + b"Connection: close\r\n\r\nhi")
            conn.sendall(resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def tcp_mode(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        conn.close()  # accept and drop: TCP open, no HTTP response


if __name__ == "__main__":
    port = int(sys.argv[1])
    mode = sys.argv[2]
    if mode == "tcp":
        tcp_mode(port)
    else:
        http_mode(port, mode)
