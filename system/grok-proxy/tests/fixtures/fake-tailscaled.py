#!/usr/bin/env python3
import argparse
import atexit
import os
import signal
import socket
import sys


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--socket", required=True)
parser.add_argument("--socks5-server", required=True)
args, _ = parser.parse_known_args()

host, port_text = args.socks5_server.rsplit(":", 1)
unix_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    os.unlink(args.socket)
except FileNotFoundError:
    pass
unix_listener.bind(args.socket)
unix_listener.listen(4)

tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def cleanup():
    tcp_listener.close()
    unix_listener.close()
    try:
        os.unlink(args.socket)
    except FileNotFoundError:
        pass


atexit.register(cleanup)
tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_listener.bind((host, int(port_text)))
tcp_listener.listen(4)


def stop(*_):
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    while True:
        signal.pause()
finally:
    cleanup()
