#!/usr/bin/env python3
"""
HTTP Client for the caching proxy
---------------------------------
Sends HTTP GET requests THROUGH the proxy, prints the response, measures the
retrieval time and reports whether the proxy served it from its cache (HIT)
or fetched it from the web server (MISS).

Examples
  python client.py http://example.com
  python client.py http://example.com -n 3          # repeat: shows MISS then HITs
  python client.py http://example.com -n 3 --no-cache   # force the proxy to skip its cache
  python client.py http://example.com http://httpbin.org/get -n 2 --no-body
  python client.py http://example.com --proxy 127.0.0.1:8888 --full
  python client.py http://example.com --headers     # also print the response headers
  python client.py https://example.com              # HTTPS through a CONNECT tunnel (never cached)
"""

import argparse
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

BUFFER_SIZE = 65536


def fetch(url, proxy_host, proxy_port, timeout=15, no_cache=False):
    """Send one GET request via the proxy (http:// directly, https:// through a CONNECT tunnel).
    Returns dict(status_line, status, headers, header_lines, body, elapsed_ms, cache)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("URL must look like http://host/path or https://host/path")

    start = time.perf_counter()                       # start timer
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as s:
        s.settimeout(timeout)
        if parts.scheme == "https":
            raw, cache = fetch_https(s, parts, timeout)
        else:
            s.sendall(build_request(f"GET {url} HTTP/1.1", parts.netloc, no_cache))
            raw, cache = read_all(s), None
    elapsed_ms = (time.perf_counter() - start) * 1000  # stop timer

    reply = parse_reply(raw)
    reply["elapsed_ms"] = elapsed_ms
    if cache:
        reply["cache"] = cache
    return reply


def build_request(request_line, host, no_cache=False):
    lines = [request_line, f"Host: {host}", "User-Agent: CachingProxyClient/1.0", "Accept: */*"]
    if no_cache:                                   # ask the proxy for a fresh copy
        lines += ["Cache-Control: no-cache", "Pragma: no-cache"]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


def read_all(sock):
    """Read until the other side closes the connection."""
    raw = bytearray()
    while True:
        try:
            chunk = sock.recv(BUFFER_SIZE)
        except ssl.SSLEOFError:                    # some HTTPS servers close without a TLS goodbye
            break
        if not chunk:
            break
        raw += chunk
    return bytes(raw)


def fetch_https(sock, parts, timeout):
    """Ask the proxy for a tunnel, then speak TLS with the web server through it.
    The proxy only sees encrypted bytes, so the answer can never come from its cache.
    Returns (raw response, cache tag)."""
    port = parts.port or 443
    target = f"[{parts.hostname}]:{port}" if ":" in parts.hostname else f"{parts.hostname}:{port}"
    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("iso-8859-1"))
    head = bytearray()
    while b"\r\n\r\n" not in head:                 # the proxy's own answer to CONNECT
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        head += chunk
    if parse_reply(bytes(head))["status"] != 200:  # blocked or failed: the error page is the answer
        return bytes(head) + read_all(sock), None

    context = ssl.create_default_context()         # checks the server's certificate and name
    with context.wrap_socket(sock, server_hostname=parts.hostname) as tls:
        tls.settimeout(timeout)
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        tls.sendall(build_request(f"GET {path} HTTP/1.0", parts.netloc))   # 1.0: no chunked body
        return read_all(tls), "TUNNEL"


def parse_reply(raw):
    """Split a raw HTTP response into its parts."""
    if b"\r\n\r\n" not in raw:
        raise ConnectionError("proxy closed the connection without a complete response")
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError):
        status = 0

    return {
        "status_line": status_line, "status": status, "headers": headers,
        "header_lines": lines[1:],                    # the headers exactly as received, for --headers
        "body": body,
        "cache": headers.get("x-cache", "UNKNOWN"),   # the proxy says HIT, MISS, BLOCKED or ERROR
    }


def body_text(r):
    """Body as text for display (characters that are not valid UTF-8 are replaced)."""
    return r["body"].decode("utf-8", errors="replace")


def describe_source(cache_tag):
    if cache_tag == "HIT (revalidated)":
        return "CACHE (stale copy revalidated with web server via 304 Not Modified)"
    if cache_tag.startswith("HIT"):
        return "CACHE (served from proxy cache)"
    if cache_tag == "MISS (bypass)":
        return "WEB SERVER (cache bypassed on request)"
    if cache_tag == "MISS":
        return "WEB SERVER (fetched by proxy, now cached if allowed)"
    if cache_tag == "BLOCKED":
        return "FIREWALL (request blocked by proxy)"
    if cache_tag == "ERROR":
        return "PROXY ERROR"
    if cache_tag == "TUNNEL":
        return "HTTPS TUNNEL (encrypted end to end, never cached)"
    return "UNKNOWN"


def main():
    ap = argparse.ArgumentParser(description="HTTP client that talks to the caching proxy")
    ap.add_argument("urls", nargs="+", help="http:// or https:// URLs to request")
    ap.add_argument("--proxy", default="127.0.0.1:8888", help="proxy host:port")
    ap.add_argument("-n", "--repeat", type=int, default=1, help="requests per URL")
    ap.add_argument("--no-cache", action="store_true", help="ask the proxy to bypass its cache")
    ap.add_argument("--no-body", action="store_true", help="do not print the body")
    ap.add_argument("--full", action="store_true", help="print the whole body")
    ap.add_argument("--headers", action="store_true", help="also print the response headers")
    args = ap.parse_args()

    for stream in (sys.stdout, sys.stderr):           # never crash on characters the console can't show
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    if args.repeat < 1:
        raise SystemExit("-n must be at least 1")
    try:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        proxy_port = int(proxy_port)
    except ValueError:
        raise SystemExit("--proxy must look like HOST:PORT")

    results = []
    for url in args.urls:
        for i in range(1, args.repeat + 1):
            print("=" * 70)
            print(f"Request {i}/{args.repeat}: GET {url}")
            try:
                r = fetch(url, proxy_host, proxy_port, no_cache=args.no_cache)
            except ValueError as e:
                print(f"ERROR: {e}")
                break                                  # same URL would fail again
            except socket.timeout:
                print("ERROR: timed out waiting for the proxy")
                continue
            except ConnectionRefusedError:
                raise SystemExit(f"ERROR: cannot connect to proxy at {args.proxy} - is it running?")
            except (OSError, ConnectionError) as e:
                print(f"ERROR: {e}")
                continue

            print(f"Status      : {r['status_line']}")
            print(f"Source      : {describe_source(r['cache'])}   [X-Cache: {r['cache']}]")
            print(f"Time taken  : {r['elapsed_ms']:.2f} ms")
            print(f"Body size   : {len(r['body'])} bytes")
            if args.headers:
                print("Headers     :")
                for line in r["header_lines"]:
                    print(f"  {line}")
            if not args.no_body:
                text = body_text(r)
                limit = None if args.full else 500
                print("-" * 70)
                print(text if limit is None else text[:limit] +
                      ("\n... [truncated, use --full]" if len(text) > limit else ""))
            results.append((url, i, r["status"], r["cache"], r["elapsed_ms"]))

    if results:
        print("\n" + "=" * 70)
        print(f"{'#':>2}  {'Status':<6} {'X-Cache':<18} {'Time (ms)':>10}  URL")
        for url, i, status, cache, ms in results:
            print(f"{i:>2}  {status:<6} {cache:<18} {ms:>10.2f}  {url}")
        hits = [ms for _, _, _, c, ms in results if c == "HIT"]
        miss = [ms for _, _, _, c, ms in results if c.startswith("MISS")]
        if hits and miss:
            avg_h, avg_m = sum(hits) / len(hits), sum(miss) / len(miss)
            line = f"\nAverage MISS: {avg_m:.2f} ms | Average HIT: {avg_h:.2f} ms"
            if avg_h > 0:
                line += f" | Speed-up: {avg_m / avg_h:.1f}x"
            print(line)


if __name__ == "__main__":
    main()
