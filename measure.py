#!/usr/bin/env python3
"""
Performance measurement for the caching proxy
---------------------------------------------
Requests each URL N times through the proxy WITH caching (1 miss, then hits) and N times
WITHOUT caching (--no-cache), then prints the tables used in the report's performance section.

  python measure.py http://example.com http://httpbin.org/get
  python measure.py http://example.com -n 5 --proxy 127.0.0.1:8888 --csv results.csv

Start the proxy first (python proxy.py). Restart it between runs so the cache starts empty.
"""
import argparse
import csv
import sys

import client


def run(url, n, host, port, no_cache):
    out = []
    for _ in range(n):
        r = client.fetch(url, host, port, no_cache=no_cache)
        out.append((r["cache"], r["status"], r["elapsed_ms"]))
    return out


def main():
    ap = argparse.ArgumentParser(description="Measure response times with and without the proxy cache")
    ap.add_argument("urls", nargs="+")
    ap.add_argument("-n", type=int, default=5, help="requests per mode (default 5)")
    ap.add_argument("--proxy", default="127.0.0.1:8888")
    ap.add_argument("--csv", help="also write every measurement to this CSV file")
    args = ap.parse_args()
    if args.n < 2:                  # one miss plus at least one hit is needed for a comparison
        raise SystemExit("-n must be at least 2 (the first request is a miss, the others are hits)")
    try:
        host, port = args.proxy.rsplit(":", 1)
        port = int(port)
    except ValueError:
        raise SystemExit("--proxy must look like HOST:PORT")

    rows, summary = [], []
    for url in args.urls:
        try:
            cached = run(url, args.n, host, port, no_cache=False)
            uncached = run(url, args.n, host, port, no_cache=True)
        except (OSError, ValueError, ConnectionError) as e:
            print(f"{url}: ERROR {e}", file=sys.stderr)
            continue
        for mode, data in (("with cache", cached), ("without cache", uncached)):
            for i, (xc, status, ms) in enumerate(data, 1):
                rows.append((url, mode, i, xc, status, round(ms, 2)))
        misses = [ms for xc, _, ms in cached if xc.startswith("MISS")]
        hits = [ms for xc, _, ms in cached if xc == "HIT"]
        base = sum(ms for _, _, ms in uncached) / len(uncached)
        if not hits or not misses:
            print(f"{url}: no cache hits observed (status {cached[0][1]}, X-Cache {cached[-1][0]}). "
                  "Is the page cacheable? Is the proxy freshly started?", file=sys.stderr)
            continue
        avg_hit = sum(hits) / len(hits)
        summary.append((url, base, misses[0], avg_hit, base / avg_hit))

        print(f"\n{url}")
        print("| Request | " + " | ".join(str(i) for i in range(1, args.n + 1)) + " |")
        print("| --- |" + " --- |" * args.n)
        print("| With cache (ms) | " + " | ".join(f"{ms:.1f} ({xc.split()[0]})" for xc, _, ms in cached) + " |")
        print("| Without cache (ms) | " + " | ".join(f"{ms:.1f}" for _, _, ms in uncached) + " |")

    if summary:
        print("\n| URL | Without cache, average (ms) | With cache, first request (ms) | With cache, average of hits (ms) | Speed-up of a hit |")
        print("| --- | --- | --- | --- | --- |")
        for url, base, first, hit, speed in summary:
            print(f"| {url} | {base:.1f} | {first:.1f} | {hit:.2f} | {speed:.0f}x |")

    if args.csv and rows:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "mode", "request", "x_cache", "status", "time_ms"])
            w.writerows(rows)
        print(f"\nWrote {len(rows)} measurements to {args.csv}")


if __name__ == "__main__":
    main()
