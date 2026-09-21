#!/usr/bin/env python3
"""Hedef makinede sahte ama GERCEK dinleyen servisler — nmap -sV banner alsin."""
import socket, threading, os

BANNERS = {
    23:   b"\xff\xfd\x18\xff\xfd\x20Ubuntu 22.04 LTS\r\nlogin: ",
    21:   b"220 (vsFTPd 3.0.5)\r\n",
    80:   b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 13\r\n\r\nHello, world\n",
    3306: b"J\x00\x00\x00\n8.0.35-0ubuntu0.22.04.1\x00",
    8080: b"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.z)\r\nContent-Length: 3\r\n\r\nok\n",
}
PORTS = [int(p) for p in os.environ.get("OPEN_PORTS", "23,21,80,3306,8080").split(",")]


def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port)); s.listen(16)
    except Exception:
        return
    while True:
        try:
            c, _ = s.accept()
            try:
                c.sendall(BANNERS.get(port, b"service ready\r\n"))
                c.settimeout(2.0)
                c.recv(256)
            except Exception:
                pass
            finally:
                c.close()
        except Exception:
            pass


for p in PORTS:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
