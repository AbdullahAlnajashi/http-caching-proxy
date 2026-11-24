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
"""

import argparse
import socket
import sys
import time
from urllib.parse import urlsplit

BUFFER_SIZE = 65536


def fetch(url, proxy_host, proxy_port, timeout=15, no_cache=False):
    """Send one GET request via the proxy.
    Returns dict(status_line, status, headers, body, elapsed_ms, cache)."""
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("URL must look like http://host/path (HTTPS is not supported)")

    lines = [
        f"GET {url} HTTP/1.1",
        f"Host: {parts.netloc}",
        "User-Agent: CachingProxyClient/1.0",
        "Accept: */*",
    ]
    if no_cache:                                   # ask the proxy for a fresh copy
        lines += ["Cache-Control: no-cache", "Pragma: no-cache"]
    lines.append("Connection: close")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")

    start = time.perf_counter()                       # start timer
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(request)
        raw = bytearray()
        while True:
            chunk = s.recv(BUFFER_SIZE)
            if not chunk:
                break
            raw += chunk
    elapsed_ms = (time.perf_counter() - start) * 1000  # stop timer

    if b"\r\n\r\n" not in raw:
        raise ConnectionError("proxy closed the connection without a complete response")
    head, _, body = bytes(raw).partition(b"\r\n\r\n")
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
        "body": body, "elapsed_ms": elapsed_ms,
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
    return "UNKNOWN"


def main():
    ap = argparse.ArgumentParser(description="HTTP client that talks to the caching proxy")
    ap.add_argument("urls", nargs="+", help="http:// URLs to request")
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
