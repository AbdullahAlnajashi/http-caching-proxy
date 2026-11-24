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
ORIGIN_TIMEOUT = 10                     # seconds to wait for each piece of the web server's answer
ORIGIN_TOTAL_TIMEOUT = 30               # seconds for the whole answer (stops slow-drip servers)
MAX_REQUEST_SIZE = 64 * 1024            # reject request headers larger than this
MAX_RESPONSE_SIZE = 20 * 1024 * 1024    # never read more than 20 MB from a web server
MAX_CACHEABLE_SIZE = 5 * 1024 * 1024    # responses larger than 5 MB are not cached
MAX_CACHE_ENTRIES = 100                 # the cache keeps at most this many responses ...
MAX_CACHE_BYTES = 100 * 1024 * 1024     # ... and at most this many bytes in total
DEFAULT_TTL = 60                        # seconds a response stays fresh if the server gives no hint
MAX_CLIENTS = 100                       # connections served at the same time (others get 503)
VIA_TOKEN = "CachingProxy"              # added to forwarded requests; seeing it again means a loop

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
        self.status, self.reason, self.body = status, reason, body
        self.expires_at = expires_at
        self.set_headers(headers)

    def set_headers(self, headers):
        # A shared cache must never replay one user's Set-Cookie (e.g. a session id) to others
        self.headers = [(k, v) for k, v in headers if k.lower() != "set-cookie"]
        h = {k.lower(): v for k, v in self.headers}
        self.etag = h.get("etag")                       # used to revalidate a stale copy
        self.last_modified = h.get("last-modified")
        self.size = len(self.body) + sum(len(k) + len(v) for k, v in self.headers)

    def is_fresh(self):
        return time.time() < self.expires_at


class Cache:
    """LRU cache keyed by URL, limited by number of entries and by total bytes.
    A lock protects it because every client runs in its own thread."""

    def __init__(self, max_entries=MAX_CACHE_ENTRIES, max_bytes=MAX_CACHE_BYTES):
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self._data = OrderedDict()
        self._sizes = {}            # size each entry had when it was stored (entries can change later)
        self.size_bytes = 0
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry:
                self._data.move_to_end(key)             # mark as recently used
            return entry

    def put(self, key, entry):
        with self._lock:
            self._remove(key)
            self._data[key] = entry
            self._sizes[key] = entry.size
            self.size_bytes += entry.size
            while len(self._data) > 1 and (len(self._data) > self.max_entries
                                           or self.size_bytes > self.max_bytes):
                evicted = next(iter(self._data))        # least recently used
                self._remove(evicted)
                log.info("CACHE EVICT   %s", evicted)

    def discard(self, key):
        with self._lock:
            self._remove(key)

    def _remove(self, key):
        if self._data.pop(key, None) is not None:
            self.size_bytes -= self._sizes.pop(key)

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
    try:
        age = max(0, int(h.get("age", "0")))         # seconds the copy already spent in other caches
    except ValueError:
        age = 0
    for key in ("s-maxage", "max-age"):              # this is a shared cache, so s-maxage wins
        if key in cc:
            try:
                return time.time() + max(0, int(cc[key]) - age)
            except ValueError:
                pass                                 # invalid number: ignore it
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


def decode_chunked(body):
    """Decode a Transfer-Encoding: chunked body: each chunk is '<hex size>\\r\\n<data>\\r\\n',
    and a chunk of size 0 ends the body. Raises ValueError if it is malformed or cut short."""
    out, pos = bytearray(), 0
    while True:
        eol = body.find(b"\r\n", pos)
        if eol == -1:
            raise ValueError("truncated chunked body")
        size = int(body[pos:eol].split(b";")[0].strip(), 16)      # ';' starts chunk extensions
        if size < 0:
            raise ValueError("negative chunk size")
        if size == 0:
            return bytes(out)
        end = eol + 2 + size
        if end + 2 > len(body) or body[end:end + 2] != b"\r\n":
            raise ValueError("truncated or malformed chunk")
        out += body[eol + 2:end]
        pos = end + 2


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
        # We ask for HTTP/1.0, but some servers answer with HTTP/1.1 chunked encoding anyway
        try:
            body = decode_chunked(body)
        except ValueError:
            raise ProxyError(502, "Bad Gateway", "Origin sent a malformed chunked body")
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
        f"Via: 1.1 {VIA_TOKEN}",             # lets a proxy loop be detected
        "Connection: close",
    ]
    for k, v in (validators or {}).items():
        lines.append(f"{k}: {v}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")

    deadline = time.monotonic() + ORIGIN_TOTAL_TIMEOUT
    try:
        with socket.create_connection((host, port), timeout=ORIGIN_TIMEOUT) as s:
            s.sendall(request)
            raw = bytearray()
            while True:                      # read until the server closes the connection
                remaining = deadline - time.monotonic()
                if remaining <= 0:           # a server sending one byte at a time must not
                    raise socket.timeout()   # hold this thread forever
                s.settimeout(min(ORIGIN_TIMEOUT, remaining))
                chunk = s.recv(BUFFER_SIZE)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > MAX_RESPONSE_SIZE:
                    raise ProxyError(502, "Bad Gateway", "Origin response too large")
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
def is_self(host, port, listen):
    """True if host:port is this proxy's own listening address."""
    return port == listen[1] and host in {"localhost", "127.0.0.1", "::1", listen[0].lower()}


def handle_request(raw, cache, firewall, listen=("127.0.0.1", 8888)):
    """Return the bytes to send back to the client. Raises ProxyError on failure.
    `listen` is the proxy's own (host, port), used to refuse requests that would loop."""
    url, host, port, path, req_headers = parse_request(raw)

    # 0) Loop protection: a request for the proxy itself, or one this proxy already forwarded
    if is_self(host, port, listen) or VIA_TOKEN.lower() in req_headers.get("via", "").lower():
        raise ProxyError(508, "Loop Detected", "The proxy cannot forward a request to itself.")

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
        # Not modified: keep our body, but newer header values from the 304 replace the stored ones
        merged = {k.lower(): (k, v) for k, v in entry.headers}
        for k, v in headers:
            if k.lower() not in SKIP_HEADERS:
                merged[k.lower()] = (k, v)
        entry.set_headers(list(merged.values()))
        expiry = compute_expiry(entry.headers)
        if expiry is None:
            cache.discard(url)                       # the new headers forbid storing it
        else:
            entry.expires_at = expiry
            cache.put(url, entry)                    # store again: its size may have changed
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


def graceful_close(conn):
    """Close without destroying the reply we just sent.
    Closing a socket that still holds unread client data makes TCP send a reset (RST), which can
    wipe the reply from the client's buffer. So: send FIN, drain what is left (bounded), then close."""
    try:
        conn.shutdown(socket.SHUT_WR)
        deadline, drained = time.monotonic() + 0.5, 0
        while drained < 1024 * 1024 and time.monotonic() < deadline:
            conn.settimeout(max(0.05, deadline - time.monotonic()))
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break
            drained += len(chunk)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def refuse(conn):
    """Answer 503 to a client we have no capacity for (runs in its own short-lived thread)."""
    try:
        conn.settimeout(1)
        try:
            conn.recv(BUFFER_SIZE)                    # read the request first so closing does not RST
        except OSError:
            pass
        conn.sendall(error_response(503, "Service Unavailable", "Proxy is busy, try again."))
    except OSError:
        pass
    finally:
        graceful_close(conn)


def client_thread(conn, addr, cache, firewall, limit, listen):
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
            response = handle_request(raw, cache, firewall, listen)
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
        graceful_close(conn)                          # always close the client socket
        limit.release()                               # free this client's slot


def serve(host, port, blocked_file, max_clients=None):
    cache, firewall = Cache(), Firewall(blocked_file)
    limit = threading.BoundedSemaphore(max_clients or MAX_CLIENTS)
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
            if not limit.acquire(blocking=False):     # too many clients: answer 503 instead
                threading.Thread(target=refuse, args=(conn,), daemon=True).start()
                continue
            threading.Thread(target=client_thread,
                             args=(conn, addr, cache, firewall, limit, (host, port)),
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
