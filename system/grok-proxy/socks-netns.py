#!/usr/bin/env python3
"""SOCKS5 proxy whose listener and egress live in different network namespaces.

Every egress rung sits behind one stable endpoint (127.0.0.1:1080) so that a rung can
be swapped underneath a running grok. The home-PC rung binds that port itself
(`ssh -D`); this program is the VPN rung's equivalent. It binds the port in the host
namespace and then serves from inside the VPN namespace.

The listening socket is created *before* entering the namespace, so it stays reachable
from the host, while every outbound connection -- and every DNS lookup -- is made
inside the namespace and therefore leaves through the VPN tun. When the tun dies the
namespace has no route left, outbound connects fail, and nothing falls back to the
host route: the kill switch the netns gives us is preserved.

Entering the namespace is done with `ip netns exec` rather than a bare setns(), because
`ip netns exec` also bind-mounts /etc/netns/<ns>/resolv.conf over /etc/resolv.conf.
Without that, DNS inside the namespace would query the host's resolver, which is not
routable from the namespace. Hence two stages:

  stage 1 (root, host netns): bind the port, re-exec via `ip netns exec`, passing the fd
  stage 2 (root, VPN netns):  drop privileges, write pidfile, listen, accept, serve

With --netns omitted the program serves from the current namespace, which is what the
test harness and the "direct" rung use.
"""

import argparse
import errno
import os
import pwd
import selectors
import signal
import socket
import struct
import sys
import threading

SOCKS5 = 5
NO_AUTH = 0
NO_ACCEPTABLE_METHODS = 0xFF
CMD_CONNECT = 1
ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6 = 1, 3, 4

REP_OK = 0
REP_GENERAL_FAILURE = 1
REP_NETWORK_UNREACHABLE = 3
REP_HOST_UNREACHABLE = 4
REP_CONNECTION_REFUSED = 5
REP_CMD_NOT_SUPPORTED = 7
REP_ATYP_NOT_SUPPORTED = 8

# A dead tun shows up as one of these; map them so the client sees a proper SOCKS
# failure instead of a truncated stream.
ERRNO_TO_REP = {
    errno.ECONNREFUSED: REP_CONNECTION_REFUSED,
    errno.ENETUNREACH: REP_NETWORK_UNREACHABLE,
    errno.ENETDOWN: REP_NETWORK_UNREACHABLE,
    errno.EHOSTUNREACH: REP_HOST_UNREACHABLE,
    errno.ETIMEDOUT: REP_HOST_UNREACHABLE,
}

CONNECT_TIMEOUT = 15.0
HANDSHAKE_TIMEOUT = 10.0
LISTEN_BACKLOG = 128
BUF = 65536
MAX_CONNECTIONS = 256

# Kernel TCP keepalive reaps a peer that has gone silently unreachable (e.g. a collapsed
# tun) without a data-idle timeout, which would wrongly cut a long but byte-silent
# reasoning stream: a live peer's kernel ACKs the probes regardless of application silence.
# Kept deliberately long: grok-4.5 high-effort streams can be byte-silent for minutes during
# reasoning, and over a lossy VPN a short keepalive can drop such a live connection (its probes
# get lost) -- surfacing as "error sending request" on the pooled reuse. Only a genuinely dead
# peer (no probe answered for ~7 min) is reaped; grok's own ~5.5-min retry covers a real tun death.
KEEPALIVE_IDLE = 300
KEEPALIVE_INTVL = 15
KEEPALIVE_CNT = 8

# Cap concurrent relays so a flood of half-open handshakes cannot spawn unbounded threads.
CONN_SEMAPHORE = threading.BoundedSemaphore(MAX_CONNECTIONS)


def log(msg):
    print(f"[socks-netns] {msg}", file=sys.stderr, flush=True)


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed during handshake")
        buf += chunk
    return buf


def reply(sock, code, addr=("0.0.0.0", 0)):
    host, port = addr[0], addr[1]
    # Build the bound-address field BEFORE the sendall try: a parse failure must fall back
    # to a valid all-zeros v4 reply, never be swallowed into emitting no reply at all (which
    # would hang the client waiting on a SOCKS response).
    if ":" in host:
        try:
            atyp, packed = ATYP_IPV6, socket.inet_pton(socket.AF_INET6, host.split("%", 1)[0])
        except OSError:
            atyp, packed = ATYP_IPV4, b"\x00\x00\x00\x00"
    else:
        try:
            atyp, packed = ATYP_IPV4, socket.inet_aton(host)
        except OSError:
            atyp, packed = ATYP_IPV4, b"\x00\x00\x00\x00"
    try:
        sock.sendall(struct.pack("!BBBB", SOCKS5, code, 0, atyp) + packed + struct.pack("!H", port))
    except OSError:
        pass


def read_request(sock):
    """Negotiate no-auth and read one CONNECT request. Returns (host, port)."""
    ver, nmethods = struct.unpack("!BB", recv_exactly(sock, 2))
    if ver != SOCKS5:
        raise ConnectionError(f"unsupported SOCKS version {ver}")
    methods = recv_exactly(sock, nmethods)
    if NO_AUTH not in methods:
        sock.sendall(struct.pack("!BB", SOCKS5, NO_ACCEPTABLE_METHODS))
        raise ConnectionError("client offered no NO_AUTH method")
    sock.sendall(struct.pack("!BB", SOCKS5, NO_AUTH))

    ver, cmd, _rsv, atyp = struct.unpack("!BBBB", recv_exactly(sock, 4))
    if ver != SOCKS5:
        raise ConnectionError(f"unsupported SOCKS version {ver}")
    if cmd != CMD_CONNECT:
        reply(sock, REP_CMD_NOT_SUPPORTED)
        raise ConnectionError(f"unsupported command {cmd}")

    if atyp == ATYP_IPV4:
        host = socket.inet_ntoa(recv_exactly(sock, 4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, recv_exactly(sock, 16))
    elif atyp == ATYP_DOMAIN:
        length = recv_exactly(sock, 1)[0]
        raw = recv_exactly(sock, length)
        # Plain ASCII: idna both rejects valid punycode A-labels and raises UnicodeError,
        # which is neither ConnectionError nor OSError, so it would escape handle() as a
        # thread-crash traceback. Decode strictly and turn a bad label into a clean reply.
        try:
            host = raw.decode("ascii")
        except (UnicodeError, ValueError):
            reply(sock, REP_HOST_UNREACHABLE)
            raise ConnectionError("undecodable domain in CONNECT request")
    else:
        reply(sock, REP_ATYP_NOT_SUPPORTED)
        raise ConnectionError(f"unsupported address type {atyp}")

    port = struct.unpack("!H", recv_exactly(sock, 2))[0]
    return host, port


def enable_keepalive(sock):
    """Let the kernel reap a peer that has gone silently unreachable (e.g. a collapsed
    tun). This is deliberately NOT a data-idle timeout: a live peer's kernel ACKs the
    probes even while the application is byte-silent, so a long reasoning stream survives."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTVL)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_CNT)
    except OSError:
        pass


def pump(client, upstream):
    """Relay both directions until either side closes. A silently-dead peer is reaped by
    kernel TCP keepalive (enable_keepalive), never by a wall-clock idle timeout that would
    wrongly cut a long but byte-silent reasoning stream."""
    sel = selectors.DefaultSelector()
    enable_keepalive(client)
    enable_keepalive(upstream)
    client.setblocking(False)
    upstream.setblocking(False)
    sel.register(client, selectors.EVENT_READ, upstream)
    sel.register(upstream, selectors.EVENT_READ, client)
    try:
        while True:
            for key, _ in sel.select(timeout=None):
                src, dst = key.fileobj, key.data
                try:
                    data = src.recv(BUF)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        sel.close()


def handle(client):
    upstream = None
    try:
        client.settimeout(HANDSHAKE_TIMEOUT)
        host, port = read_request(client)
        client.settimeout(None)
        try:
            # Created inside the VPN namespace: this is what forces egress out the tun,
            # and getaddrinfo() for `host` resolves against the namespace's resolv.conf.
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except socket.gaierror:
            reply(client, REP_HOST_UNREACHABLE)
            return
        except OSError as exc:
            reply(client, ERRNO_TO_REP.get(exc.errno, REP_GENERAL_FAILURE))
            return
        upstream.settimeout(None)
        reply(client, REP_OK, upstream.getsockname())
        pump(client, upstream)
    except (ConnectionError, OSError):
        pass
    except Exception as exc:
        # A stray struct.error etc. would otherwise dump a raw per-thread traceback; log
        # one line instead. The finally still runs, so the semaphore permit is returned.
        log(f"handler error: {exc!r}")
    finally:
        for sock in (client, upstream):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        CONN_SEMAPHORE.release()


def drop_privileges(username):
    if os.geteuid() != 0 or not username:
        return
    entry = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)


def serve(listener, username, pidfile):
    drop_privileges(username)
    if pidfile:
        with open(pidfile, "w") as handle_:
            handle_.write(str(os.getpid()))
    # listen() only AFTER the pidfile exists, so the port never accepts -- and egress.sh's
    # port_listening readiness probe never passes -- before socks_alive can see the pidfile.
    listener.listen(LISTEN_BACKLOG)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log(f"serving on {listener.getsockname()} (egress netns: {os.readlink('/proc/self/ns/net')})")
    while True:
        try:
            client, _ = listener.accept()
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            raise
        # Bound concurrency: block accepting past MAX_CONNECTIONS in-flight relays. The
        # permit is released in handle()'s finally (one acquire here per one release there).
        CONN_SEMAPHORE.acquire()
        try:
            threading.Thread(target=handle, args=(client,), daemon=True).start()
        except Exception:
            CONN_SEMAPHORE.release()
            try:
                client.close()
            except OSError:
                pass


def bind_listener(host, port):
    # bind only -- listen() is deferred to serve(), after the pidfile is written (see L19),
    # so the port is never LISTEN-able before socks_alive's pidfile check can succeed.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    return listener


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", default="127.0.0.1:1080", help="host:port to bind in the HOST namespace")
    parser.add_argument("--netns", default="", help="network namespace to egress from (empty = current)")
    parser.add_argument("--user", default="", help="drop privileges to this user once inside the namespace")
    parser.add_argument("--pidfile", default="")
    parser.add_argument("--serve-fd", type=int, default=-1, help=argparse.SUPPRESS)  # stage 2 only
    args = parser.parse_args()

    if args.serve_fd >= 0:
        listener = socket.socket(fileno=args.serve_fd)
        serve(listener, args.user, args.pidfile)
        return

    host, _, port = args.listen.rpartition(":")
    listener = bind_listener(host, int(port))

    if not args.netns:
        serve(listener, args.user, args.pidfile)
        return

    # Stage 1 -> stage 2. The fd must survive execve, so clear CLOEXEC. `ip netns exec`
    # execs in place, so the listener -- created here, in the host namespace -- is
    # inherited by a process whose *new* sockets will belong to the VPN namespace.
    fd = listener.fileno()
    os.set_inheritable(fd, True)
    argv = [
        "ip", "netns", "exec", args.netns,
        sys.executable, os.path.abspath(__file__),
        "--serve-fd", str(fd),
        "--user", args.user,
        "--pidfile", args.pidfile,
    ]
    os.execvp("ip", argv)


if __name__ == "__main__":
    main()
