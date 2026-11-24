#!/usr/bin/env python3
"""
HTTP Proxy Server with Caching and Firewall
-------------------------------------------
Features
  * Handles HTTP GET requests sent by a client to the proxy (GET http://host/path HTTP/1.1)
  * In-memory cache driven by HTTP headers (Cache-Control, Expires, ETag, Last-Modified),
    with revalidation of stale copies (If-None-Match / If-Modified-Since -> 304 Not Modified)
  * Firewall: blocks the domains listed in blocked_domains.txt with 403 Forbidden
  * Logs every CACHE HIT / CACHE MISS / BLOCKED / ERROR to the console and to proxy.log
  * Exception handling: an error in one request never stops the proxy

Usage:  python proxy.py [--host 127.0.0.1] [--port 8888] [--blocked blocked_domains.txt]
"""

import argparse
import html
import logging
import socket
import threading
import time
from collections import OrderedDict
from datetime import timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
BUFFER_SIZE = 65536
CLIENT_TIMEOUT = 10                     # seconds to wait for the client's request
ORIGIN_TIMEOUT = 10                     # seconds to wait for the web server
MAX_REQUEST_SIZE = 64 * 1024            # reject request headers larger than this
MAX_CACHEABLE_SIZE = 5 * 1024 * 1024    # responses larger than 5 MB are not cached
MAX_CACHE_ENTRIES = 100                 # the cache keeps at most this many responses
DEFAULT_TTL = 60                        # seconds a response stays fresh if the server gives no hint

log = logging.getLogger("proxy")


# ----------------------------------------------------------------------------
# Exception that carries the HTTP status sent back to the client
# ----------------------------------------------------------------------------
class ProxyError(Exception):
    def __init__(self, status, reason, detail=""):
        super().__init__(detail or reason)
        self.status, self.reason, self.detail = status, reason, detail


# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
class Firewall:
    """Blocks a host that is a listed domain or a sub-domain of one.
    The rules file is read once, when the first request arrives."""

    def __init__(self, path):
        self.path = path
        self.domains = None
        self._lock = threading.Lock()

    def _load(self):
        domains = []
        try:
            # utf-8-sig: ignores the byte-order mark that Windows Notepad adds
            with open(self.path, encoding="utf-8-sig") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip().lower()    # drop comments and spaces
                    if line:
                        domains.append(line)
        except (OSError, UnicodeDecodeError) as e:
            # A missing or broken rules file must not stop the proxy: nothing is blocked
            log.error("Could not read firewall file %s (%s); nothing is blocked", self.path, e)
        log.info("Firewall rules loaded: %s", sorted(domains))
        return domains

    def is_blocked(self, host):
        with self._lock:
            if self.domains is None:
                self.domains = self._load()
        host = host.lower().rstrip(".")    # "facebook.com." is the same site as "facebook.com"
        return any(host == d or host.endswith("." + d) for d in self.domains)


# ----------------------------------------------------------------------------
# Cache
# ----------------------------------------------------------------------------
class CacheEntry:
    """One stored response and the time until which it is fresh."""

    def __init__(self, status, reason, headers, body, expires_at):
        self.status, self.reason, self.headers, self.body = status, reason, headers, body
        self.expires_at = expires_at
        h = {k.lower(): v for k, v in headers}
        self.etag = h.get("etag")                       # used to revalidate a stale copy
        self.last_modified = h.get("last-modified")

    def is_fresh(self):
        return time.time() < self.expires_at


class Cache:
    """Cache keyed by URL. When it is full, the least recently used entry is removed.
    A lock protects it because every client runs in its own thread."""

    def __init__(self, max_entries=MAX_CACHE_ENTRIES):
        self.max_entries = max_entries
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry:
                self._data.move_to_end(key)             # mark as recently used
            return entry

    def put(self, key, entry):
        with self._lock:
            self._data[key] = entry
            self._data.move_to_end(key)
            if len(self._data) > self.max_entries:
                evicted, _ = self._data.popitem(last=False)   # oldest entry
                log.info("CACHE EVICT   %s", evicted)

    def discard(self, key):
        with self._lock:
            self._data.pop(key, None)

    def __len__(self):
        return len(self._data)


def parse_cache_control(value):
    """'max-age=60, no-cache' -> {'max-age': '60', 'no-cache': True}"""
    directives = {}
    for part in (value or "").split(","):
        part = part.strip().lower()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip()] = v.strip().strip('"')
        else:
            directives[part] = True
    return directives


def compute_expiry(headers):
    """Decide from the response headers how long the response may be reused.
    Returns the time (in seconds since 1970) until which it is fresh,
    or None if the response must not be stored."""
    h = {k.lower(): v for k, v in headers}
    cc = parse_cache_control(h.get("cache-control"))

    if "no-store" in cc or "private" in cc:
        return None                                  # the server forbids storing it
    if "no-cache" in cc:
        return time.time()                           # store it, but revalidate before every use
    if "max-age" in cc:
        try:
            return time.time() + max(0, int(cc["max-age"]))
        except ValueError:
            pass                                     # invalid number: ignore it
    if "expires" in h:
        try:
            expires = parsedate_to_datetime(h["expires"])
            if expires.tzinfo is None:               # "-0000" means GMT, not the computer's time zone
                expires = expires.replace(tzinfo=timezone.utc)
            return expires.timestamp()
        except (TypeError, ValueError, OverflowError):
            return time.time()                       # invalid date: treat as already stale
    return time.time() + DEFAULT_TTL


# ----------------------------------------------------------------------------
# Reading and checking HTTP messages
# ----------------------------------------------------------------------------
def recv_until(sock, marker, limit):
    """Read from the socket until `marker` is received (or the other side closes)."""
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise ProxyError(400, "Bad Request", "Request headers too large")
    return bytes(data)


def parse_request(raw):
    """Check the client's request. Returns (url, host, port, path, headers)."""
    try:
        head = raw.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
        lines = head.split("\r\n")
        method, url, version = lines[0].split()
    except ValueError:
        raise ProxyError(400, "Bad Request", "Malformed request line")

    if not version.startswith("HTTP/"):
        raise ProxyError(400, "Bad Request", "Missing HTTP version")
    if method.upper() != "GET":
        raise ProxyError(405, "Method Not Allowed", "Only GET is supported")

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if url.lower().startswith("https://"):
        raise ProxyError(501, "Not Implemented", "HTTPS is not supported by this proxy")
    if not url.lower().startswith("http://"):
        raise ProxyError(400, "Bad Request", "Request target must be an absolute http:// URL")

    try:
        parts = urlsplit(url)
        host = parts.hostname                        # already lower-case
        port = parts.port if parts.port is not None else 80   # .port raises ValueError if invalid
    except ValueError:
        raise ProxyError(400, "Bad Request", "Invalid host or port in URL")
    if not host:
        raise ProxyError(400, "Bad Request", "Missing host name in URL")
    if not 1 <= port <= 65535:
        raise ProxyError(400, "Bad Request", "Invalid host or port in URL")

    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    return f"http://{host_port(host, port)}{path}", host, port, path, headers


def host_port(host, port):
    """'example.com', 80 -> 'example.com';  '::1', 8080 -> '[::1]:8080' (IPv6 needs brackets)"""
    name = f"[{host}]" if ":" in host else host
    return name if port == 80 else f"{name}:{port}"


def parse_response(raw):
    """Split the web server's answer into (status, reason, headers, body) and check it."""
    end = raw.find(b"\r\n\r\n")
    if end == -1:
        raise ProxyError(502, "Bad Gateway", "Origin sent an invalid response")
    lines = raw[:end].decode("iso-8859-1").split("\r\n")
    body = raw[end + 4:]
    try:
        _, status, *reason = lines[0].split(" ", 2)
        status = int(status)
    except ValueError:
        raise ProxyError(502, "Bad Gateway", "Origin sent an invalid status line")
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    h = {k.lower(): v for k, v in headers}

    if status == 304:
        body = b""                                     # 304 Not Modified has no body
    elif "chunked" in h.get("transfer-encoding", "").lower():
        # We ask for HTTP/1.0, so a correct server never sends a chunked body
        raise ProxyError(502, "Bad Gateway", "Origin sent a chunked body, which is not supported")
    elif "content-length" in h:
        try:
            expected = int(h["content-length"])
        except ValueError:
            raise ProxyError(502, "Bad Gateway", "Origin sent an invalid Content-Length")
        if len(body) < expected:                       # connection closed too early: do not cache it
            raise ProxyError(502, "Bad Gateway",
                             f"Origin response truncated ({len(body)} of {expected} bytes)")
        body = body[:expected]
    return status, (reason[0] if reason else ""), headers, body


# ----------------------------------------------------------------------------
# Talking to the web server
# ----------------------------------------------------------------------------
def fetch_from_origin(host, port, path, validators=None):
    """Send a GET to the web server and return (status, reason, headers, body).
    `validators` holds If-None-Match / If-Modified-Since when a stale copy is revalidated.
    Every network problem is turned into a ProxyError with the right HTTP status."""
    lines = [
        f"GET {path} HTTP/1.0",              # HTTP/1.0: the server closes the connection when done
        f"Host: {host_port(host, port)}",
        "User-Agent: CachingProxy/1.0",
        "Accept: */*",
        "Accept-Encoding: identity",         # no compression, so the body stays readable
        "Connection: close",
    ]
    for k, v in (validators or {}).items():
        lines.append(f"{k}: {v}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")

    try:
        with socket.create_connection((host, port), timeout=ORIGIN_TIMEOUT) as s:
            s.sendall(request)
            raw = bytearray()
            while True:                      # read until the server closes the connection
                chunk = s.recv(BUFFER_SIZE)
                if not chunk:
                    break
                raw += chunk
    except socket.gaierror:
        raise ProxyError(502, "Bad Gateway", f"DNS lookup failed for {host}")
    except socket.timeout:
        raise ProxyError(504, "Gateway Timeout", f"{host} did not respond in time")
    except ConnectionRefusedError:
        raise ProxyError(502, "Bad Gateway", f"Connection refused by {host}:{port}")
    except OSError as e:
        raise ProxyError(502, "Bad Gateway", f"Network error: {e}")
    return parse_response(bytes(raw))


# ----------------------------------------------------------------------------
# Building the reply for the client
# ----------------------------------------------------------------------------
# Headers that describe the connection, not the content; the proxy sets its own
SKIP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "content-length",
                "proxy-connection", "x-cache"}


def build_response(status, reason, headers, body, x_cache):
    """Build the reply. X-Cache tells the client where it came from (HIT, MISS, BLOCKED, ERROR)."""
    out = [f"HTTP/1.1 {status} {reason}".rstrip()]
    for k, v in headers:
        if k.lower() not in SKIP_HEADERS:
            out.append(f"{k}: {v}")
    out += [f"X-Cache: {x_cache}", f"Content-Length: {len(body)}", "Connection: close"]
    return ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1", errors="replace") + body


def error_response(status, reason, detail=""):
    body = (f"<html><body><h1>{status} {html.escape(reason)}</h1><p>{html.escape(detail)}</p>"
            f"<hr>Caching Proxy</body></html>").encode("utf-8")
    headers = [("Content-Type", "text/html; charset=utf-8")]
    tag = "BLOCKED" if status == 403 else "ERROR"
    return build_response(status, reason, headers, body, tag)


# ----------------------------------------------------------------------------
# Handling one request
# ----------------------------------------------------------------------------
def handle_request(raw, cache, firewall):
    """Return the bytes to send back to the client. Raises ProxyError on failure."""
    url, host, port, path, req_headers = parse_request(raw)

    # 1) Firewall: blocked sites are never contacted and never served from the cache
    if firewall.is_blocked(host):
        log.warning("BLOCKED      %s", url)
        raise ProxyError(403, "Forbidden", f"Access to {host} is blocked by the proxy firewall.")

    # 2) The client may ask for a fresh copy (client.py --no-cache)
    bypass = ("no-cache" in req_headers.get("cache-control", "").lower()
              or "no-cache" in req_headers.get("pragma", "").lower())

    entry = None if bypass else cache.get(url)
    if entry and entry.is_fresh():
        log.info("CACHE HIT     %s", url)
        return build_response(entry.status, entry.reason, entry.headers, entry.body, "HIT")

    # 3) A stale copy with an ETag or Last-Modified value: ask the server if it changed
    validators = {}
    if entry:
        if entry.etag:
            validators["If-None-Match"] = entry.etag
        if entry.last_modified:
            validators["If-Modified-Since"] = entry.last_modified

    status, reason, headers, body = fetch_from_origin(host, port, path, validators)

    if status == 304 and validators:
        # Not modified: keep our copy and give it the new lifetime from the 304 headers
        expiry = compute_expiry(headers)
        if expiry is None:
            cache.discard(url)
        else:
            entry.expires_at = expiry
        log.info("CACHE HIT     %s (revalidated with 304 Not Modified)", url)
        return build_response(entry.status, entry.reason, entry.headers, entry.body,
                              "HIT (revalidated)")

    # 4) Cache miss: store the response if its headers allow it
    log.info("%s %s (origin status %d, %d bytes)",
             "CACHE BYPASS  " if bypass else "CACHE MISS   ", url, status, len(body))
    if status == 200 and len(body) <= MAX_CACHEABLE_SIZE:
        expiry = compute_expiry(headers)
        if expiry is not None:
            cache.put(url, CacheEntry(status, reason, headers, body, expiry))
            log.info("CACHE STORE   %s (fresh for %ds)", url, max(0, int(expiry - time.time())))
        else:
            cache.discard(url)
            log.info("CACHE SKIP    %s (Cache-Control forbids storing)", url)
    return build_response(status, reason, headers, body, "MISS (bypass)" if bypass else "MISS")


def client_thread(conn, addr, cache, firewall):
    """One thread per client connection. Every exception is caught here,
    so a bad request or a network error never stops the proxy."""
    try:
        conn.settimeout(CLIENT_TIMEOUT)
        try:
            raw = recv_until(conn, b"\r\n\r\n", MAX_REQUEST_SIZE)
        except socket.timeout:
            log.error("ERROR 408      client %s sent no complete request", addr[0])
            conn.sendall(error_response(408, "Request Timeout", "No complete request received."))
            return
        if not raw.strip():
            return                                    # the client connected and left
        try:
            response = handle_request(raw, cache, firewall)
        except ProxyError as e:                       # expected errors: send an error page
            if e.status != 403:
                log.error("ERROR %d      %s from %s", e.status, e.detail or e.reason, addr[0])
            response = error_response(e.status, e.reason, e.detail)
        except Exception as e:                        # unexpected bug: answer 500, keep running
            log.exception("UNEXPECTED ERROR handling request from %s: %s", addr[0], e)
            response = error_response(500, "Internal Server Error", "The proxy hit an unexpected error.")
        conn.sendall(response)
    except ProxyError as e:                           # request headers too large
        log.error("ERROR %d      %s from %s", e.status, e.detail, addr[0])
        try:
            conn.sendall(error_response(e.status, e.reason, e.detail))
        except OSError:
            pass
    except OSError:                                   # timeout or client disconnected early
        log.error("ERROR         client %s disconnected or timed out", addr[0])
    except Exception as e:
        log.exception("UNEXPECTED ERROR in client thread: %s", e)
    finally:
        conn.close()                                  # always close the client socket


def serve(host, port, blocked_file):
    cache, firewall = Cache(), Firewall(blocked_file)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
    except OSError as e:                              # e.g. the port is already in use
        log.critical("Cannot bind to %s:%d - %s", host, port, e)
        raise SystemExit(1)
    server.listen(50)
    server.settimeout(1.0)      # wake up every second so that Ctrl+C works on Windows too
    log.info("Proxy listening on %s:%d  (firewall file: %s)", host, port, blocked_file)
    try:
        while True:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=client_thread, args=(conn, addr, cache, firewall),
                             daemon=True).start()
    except KeyboardInterrupt:
        log.info("Shutting down (cache held %d entries)", len(cache))
    finally:
        server.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HTTP proxy with cache and firewall")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--blocked", default="blocked_domains.txt")
    ap.add_argument("--log", default="proxy.log")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s", datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(), logging.FileHandler(args.log, encoding="utf-8")],
    )
    serve(args.host, args.port, args.blocked)
