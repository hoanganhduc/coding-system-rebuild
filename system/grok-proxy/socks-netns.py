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
import ctypes
import errno
import os
import pwd
import resource
import selectors
import signal
import socket
import stat
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
MAX_BUFFER_PER_DIRECTION = 4 * BUF

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

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


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
    """Relay ordered bytes with bounded backpressure and duplex half-closes.

    Output is attempted only when the destination reports write readiness. EOF
    closes just that direction: buffered bytes drain before SHUT_WR reaches the
    peer, while the reverse direction remains available for a delayed response.
    There is deliberately no application-idle timeout.
    """
    sel = selectors.DefaultSelector()
    enable_keepalive(client)
    enable_keepalive(upstream)
    client.setblocking(False)
    upstream.setblocking(False)
    peers = {client: upstream, upstream: client}
    pending = {client: bytearray(), upstream: bytearray()}
    read_open = {client: True, upstream: True}
    write_closed = {client: False, upstream: False}
    registered = set()

    def close_write(sock):
        if write_closed[sock]:
            return
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        write_closed[sock] = True

    def refresh(sock):
        peer = peers[sock]
        events = 0
        # Stop reading at the high-water mark. Sending below it re-enables reads
        # on the next loop, bounding each direction without dropping bytes.
        if read_open[sock] and len(pending[peer]) < MAX_BUFFER_PER_DIRECTION:
            events |= selectors.EVENT_READ
        if pending[sock] and not write_closed[sock]:
            events |= selectors.EVENT_WRITE
        if events:
            if sock in registered:
                sel.modify(sock, events)
            else:
                sel.register(sock, events)
                registered.add(sock)
        elif sock in registered:
            sel.unregister(sock)
            registered.remove(sock)

    refresh(client)
    refresh(upstream)
    try:
        while registered:
            for key, mask in sel.select(timeout=None):
                sock = key.fileobj
                peer = peers[sock]
                if mask & selectors.EVENT_READ:
                    try:
                        room = MAX_BUFFER_PER_DIRECTION - len(pending[peer])
                        data = sock.recv(min(BUF, room))
                    except BlockingIOError:
                        data = None
                    except OSError:
                        return
                    if data == b"":
                        read_open[sock] = False
                        if not pending[peer]:
                            close_write(peer)
                    elif data:
                        pending[peer].extend(data)

                if mask & selectors.EVENT_WRITE and pending[sock]:
                    try:
                        sent = sock.send(pending[sock])
                    except BlockingIOError:
                        sent = 0
                    except OSError:
                        return
                    if sent:
                        del pending[sock][:sent]
                    # The opposite read side reached EOF. Propagate its FIN only
                    # after every byte it produced has been delivered.
                    if not pending[sock] and not read_open[peer]:
                        close_write(sock)

                refresh(sock)
                refresh(peer)
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


def write_pidfile(pidfile, pid_fd=-1):
    """Publish this process ID without following a caller-controlled file link.

    The fixed root broker passes an already-open, ownership-checked descriptor.
    Direct/unprivileged use keeps the path form, but opens it with O_NOFOLLOW and
    verifies the resulting regular file before writing.
    """
    data = f"{os.getpid()}\n".encode("ascii")
    owned_fd = pid_fd < 0
    if owned_fd:
        if not pidfile:
            return
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
        )
        pid_fd = os.open(pidfile, flags, 0o600)
    try:
        info = os.fstat(pid_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError("unsafe pidfile descriptor")
        os.fchmod(pid_fd, 0o600)
        os.ftruncate(pid_fd, 0)
        os.lseek(pid_fd, 0, os.SEEK_SET)
        view = memoryview(data)
        while view:
            count = os.write(pid_fd, view)
            if count <= 0:
                raise RuntimeError("short pidfile write")
            view = view[count:]
        os.fsync(pid_fd)
    finally:
        os.close(pid_fd)


def enable_same_uid_fd_inspection(username):
    """Expose only the demoted relay's descriptors to its owning UID.

    Linux clears dumpability when the root broker drops to the requesting
    account.  The supervisor must still bind the host listener inode to this
    exact process through ``/proc/<pid>/fd``.  Restore that same-UID read
    boundary only after the broker-owned pid descriptor has been closed.
    """
    entry = pwd.getpwnam(username)
    if (
        entry.pw_uid == 0
        or os.getresuid() != (entry.pw_uid, entry.pw_uid, entry.pw_uid)
        or os.getresgid() != (entry.pw_gid, entry.pw_gid, entry.pw_gid)
    ):
        raise RuntimeError("relay credentials were not fully demoted")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 1:
        raise RuntimeError("relay dumpability did not read back as enabled")


def serve(listener, username, pidfile, pid_fd=-1):
    drop_privileges(username)
    write_pidfile(pidfile, pid_fd)
    if username:
        enable_same_uid_fd_inspection(username)
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
        # Reject overload immediately rather than blocking the accept loop after
        # it has already consumed a socket and allowing the kernel backlog to grow.
        if not CONN_SEMAPHORE.acquire(blocking=False):
            try:
                client.close()
            except OSError:
                pass
            continue
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
    parser.add_argument("--pid-fd", type=int, default=-1, help=argparse.SUPPRESS)  # broker-owned fd
    args = parser.parse_args()

    if args.serve_fd >= 0:
        listener = socket.socket(fileno=args.serve_fd)
        serve(listener, args.user, args.pidfile, args.pid_fd)
        return

    host, _, port = args.listen.rpartition(":")
    listener = bind_listener(host, int(port))

    if not args.netns:
        serve(listener, args.user, args.pidfile, args.pid_fd)
        return

    # Stage 1 -> stage 2. The fd must survive execve, so clear CLOEXEC. `ip netns exec`
    # execs in place, so the listener -- created here, in the host namespace -- is
    # inherited by a process whose *new* sockets will belong to the VPN namespace.
    fd = listener.fileno()
    os.set_inheritable(fd, True)
    if args.pid_fd >= 0:
        os.set_inheritable(args.pid_fd, True)
    argv = [
        "ip", "netns", "exec", args.netns,
        sys.executable, os.path.abspath(__file__),
        "--serve-fd", str(fd),
        "--user", args.user,
        "--pidfile", args.pidfile,
    ]
    if args.pid_fd >= 0:
        argv.extend(["--pid-fd", str(args.pid_fd)])
    os.execvp("ip", argv)


if __name__ == "__main__":
    main()
