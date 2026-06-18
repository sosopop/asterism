#!/usr/bin/env python3
"""End-to-end smoke test for asterism.

Launches several real asterism processes in distinct node roles and drives a
client through every node, over both TCP and UDP:

    Client --SOCKS5/HTTP--> Relay --tunnel--> Agent --> Target        (TCP)
    Client --SOCKS5 UDP-->  Relay --tunnel--> Agent --> Target        (UDP)
    Client --TCP--> Portal --HTTP CONNECT--> Relay --> Agent --> Target (TCP)

Roles:
  * Relay  : asterism -i socks5://.. -i http://.. -o tcp://.. -d
  * Agent  : asterism -r tcp://<relay-outer> -u <user> -p <pass>
  * Portal : asterism -L <local>#http://user:pass@<relay-http>#<target>
  * Client : this script (raw sockets)
  * Target : in-process TCP echo + UDP echo servers

Usage:
    python smoke_test.py <build-dir-or-binary> [--verbose]

Exits 0 on success, non-zero on any failure.
"""

import base64
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

USER = "smoke"
PASS = "smokepass"
HOST = "127.0.0.1"


def log(msg):
    print("[smoke] " + msg, flush=True)


def find_binary(arg):
    """Accept either the binary itself or a build directory to search."""
    if os.path.isfile(arg):
        return arg
    names = ("asterism.exe", "asterism")
    candidates = []
    for root, _dirs, files in os.walk(arg):
        for f in files:
            if f in names:
                candidates.append(os.path.join(root, f))
    # Prefer the shortest path (top-most), skip the test binary if any.
    candidates = [c for c in candidates if "asterism_test" not in os.path.basename(c)]
    if not candidates:
        raise SystemExit("could not find asterism binary under: " + arg)
    candidates.sort(key=len)
    return candidates[0]


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------
# Target servers (the destination the client ultimately talks to)
# --------------------------------------------------------------------------
class EchoServers:
    def __init__(self):
        self.tcp_port = free_port()
        self.udp_port = free_port()
        self._stop = False
        self._threads = []

    def start(self):
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((HOST, self.tcp_port))
        self._tcp.listen(16)
        self._tcp.settimeout(0.5)

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind((HOST, self.udp_port))
        self._udp.settimeout(0.5)

        self._threads = [
            threading.Thread(target=self._tcp_loop, daemon=True),
            threading.Thread(target=self._udp_loop, daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _tcp_loop(self):
        while not self._stop:
            try:
                conn, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._tcp_conn, args=(conn,), daemon=True).start()

    def _tcp_conn(self, conn):
        conn.settimeout(5)
        try:
            while not self._stop:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def _udp_loop(self):
        while not self._stop:
            try:
                data, peer = self._udp.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._udp.sendto(data, peer)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self._tcp.close()
        except OSError:
            pass
        try:
            self._udp.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# asterism process management
# --------------------------------------------------------------------------
class Node:
    def __init__(self, binary, name, args, verbose):
        self.name = name
        self.logfile = tempfile.NamedTemporaryFile(
            prefix="asterism_%s_" % name, suffix=".log", delete=False)
        cmd = [binary] + args
        if verbose:
            cmd.append("-v")
        log("start %s: %s" % (name, " ".join(args)))
        self.proc = subprocess.Popen(cmd, stdout=self.logfile, stderr=subprocess.STDOUT)

    def alive(self):
        return self.proc.poll() is None

    def dump(self):
        self.logfile.flush()
        try:
            with open(self.logfile.name, "rb") as f:
                data = f.read().decode("utf-8", "replace").strip()
        except OSError:
            data = ""
        rc = self.proc.poll()
        log("---- %s (exit=%s) ----" % (self.name, rc))
        if data:
            print(data, flush=True)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self.logfile.close()
            os.unlink(self.logfile.name)
        except OSError:
            pass


def wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((HOST, port))
            s.close()
            return True
        except OSError:
            s.close()
            time.sleep(0.1)
    return False


# --------------------------------------------------------------------------
# Client helpers
# --------------------------------------------------------------------------
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("connection closed (got %d/%d bytes)" % (len(buf), n))
        buf += chunk
    return buf


def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def socks5_auth(sock):
    sock.sendall(b"\x05\x01\x02")
    if recv_exact(sock, 2) != b"\x05\x02":
        raise IOError("socks5 method select failed")
    auth = bytes([1, len(USER)]) + USER.encode() + bytes([len(PASS)]) + PASS.encode()
    sock.sendall(auth)
    if recv_exact(sock, 2) != b"\x01\x00":
        raise IOError("socks5 auth failed")


def test_socks5_tcp(socks_port, target_port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, socks_port))
        socks5_auth(s)
        req = b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + struct.pack("!H", target_port)
        s.sendall(req)
        resp = recv_exact(s, 10)
        if resp[0] != 5 or resp[1] != 0:
            raise IOError("socks5 connect reply %r" % resp[:2])
        s.sendall(payload)
        return recv_exact(s, len(payload))
    finally:
        s.close()


def test_http_tcp(http_port, target_port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, http_port))
        cred = base64.b64encode(("%s:%s" % (USER, PASS)).encode()).decode()
        req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
               "Proxy-Authorization: Basic %s\r\n\r\n"
               % (HOST, target_port, HOST, target_port, cred))
        s.sendall(req.encode())
        head = recv_until(s, b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0]
        if b"200" not in first:
            raise IOError("http connect reply: %r" % first)
        s.sendall(payload)
        return recv_exact(s, len(payload))
    finally:
        s.close()


def test_socks5_udp(socks_port, target_port, payload):
    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.settimeout(5)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    try:
        ctrl.connect((HOST, socks_port))
        socks5_auth(ctrl)
        # UDP ASSOCIATE
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = recv_exact(ctrl, 10)
        if resp[0] != 5 or resp[1] != 0:
            raise IOError("udp associate reply %r" % resp[:2])
        relay_udp_port = struct.unpack("!H", resp[8:10])[0]
        # SOCKS5 UDP request header: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2)
        header = b"\x00\x00\x00\x01" + socket.inet_aton(HOST) + struct.pack("!H", target_port)
        udp.sendto(header + payload, (HOST, relay_udp_port))
        data, _ = udp.recvfrom(65536)
        # response is prefixed with the same 10-byte IPv4 SOCKS5 UDP header
        return data[10:]
    finally:
        udp.close()
        ctrl.close()


def test_portal_tcp(portal_port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST, portal_port))
        s.sendall(payload)
        return recv_exact(s, len(payload))
    finally:
        s.close()


def retry(fn, what, timeout=20.0):
    """Run fn() until it succeeds or timeout; absorbs node startup latency."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - smoke test, report anything
            last = e
            time.sleep(0.3)
    raise IOError("%s failed after %ss: %s" % (what, timeout, last))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    verbose = "--verbose" in sys.argv[1:]
    target_arg = args[0] if args else "build"
    binary = find_binary(target_arg)
    log("binary: " + binary)

    relay_socks = free_port()
    relay_http = free_port()
    relay_outer = free_port()
    portal_local = free_port()

    echo = EchoServers()
    echo.start()
    log("targets: tcp=%d udp=%d" % (echo.tcp_port, echo.udp_port))

    nodes = []
    failures = []
    try:
        relay = Node(binary, "relay", [
            "-i", "socks5://%s:%d" % (HOST, relay_socks),
            "-i", "http://%s:%d" % (HOST, relay_http),
            "-o", "tcp://%s:%d" % (HOST, relay_outer),
            "-d",
        ], verbose)
        nodes.append(relay)

        if not (wait_port(relay_socks) and wait_port(relay_http) and wait_port(relay_outer)):
            raise SystemExit("relay did not open its listen ports")

        agent = Node(binary, "agent", [
            "-r", "tcp://%s:%d" % (HOST, relay_outer),
            "-u", USER, "-p", PASS,
        ], verbose)
        nodes.append(agent)

        portal = Node(binary, "portal", [
            "-L", "%s:%d#http://%s:%s@%s:%d#%s:%d" % (
                HOST, portal_local, USER, PASS, HOST, relay_http, HOST, echo.tcp_port),
        ], verbose)
        nodes.append(portal)

        if not wait_port(portal_local):
            raise SystemExit("portal did not open its local port")

        for n in nodes:
            if not n.alive():
                raise SystemExit("%s exited prematurely" % n.name)

        # --- the four end-to-end checks (retried to absorb agent-join latency) ---
        # Each entry: (name, expected-payload, request-fn returning echoed bytes).
        checks = [
            ("SOCKS5 TCP", b"socks5-tcp-hello",
             lambda p: test_socks5_tcp(relay_socks, echo.tcp_port, p)),
            ("HTTP CONNECT TCP", b"http-tcp-hello",
             lambda p: test_http_tcp(relay_http, echo.tcp_port, p)),
            ("SOCKS5 UDP", b"socks5-udp-hello",
             lambda p: test_socks5_udp(relay_socks, echo.udp_port, p)),
            ("Portal TCP", b"portal-tcp-hello",
             lambda p: test_portal_tcp(portal_local, p)),
        ]
        for i, (name, payload, fn) in enumerate(checks):
            # the first check gets a longer budget (the agent must join first)
            budget = 25.0 if i == 0 else 15.0
            try:
                got = retry(lambda: fn(payload), name, timeout=budget)
                if got != payload:
                    raise IOError("echo mismatch: sent %r got %r" % (payload, got))
                log("PASS %s" % name)
            except Exception as e:  # noqa: BLE001
                failures.append("%s: %s" % (name, e))
                log("FAIL %s: %s" % (name, e))

        for n in nodes:
            if not n.alive():
                failures.append("%s exited during test" % n.name)
    finally:
        if failures:
            for n in nodes:
                n.dump()
        for n in nodes:
            n.stop()
        echo.stop()

    if failures:
        log("SMOKE TEST FAILED:")
        for f in failures:
            log("  - " + f)
        return 1
    log("SMOKE TEST PASSED (Relay + Agent + Portal + Client, TCP & UDP)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
