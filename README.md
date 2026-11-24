# HTTP Caching Proxy with Firewall

[![tests](https://github.com/AbdullahAlnajashi/http-caching-proxy/actions/workflows/tests.yml/badge.svg)](https://github.com/AbdullahAlnajashi/http-caching-proxy/actions/workflows/tests.yml)

A multi-threaded HTTP/1.x forward proxy written from scratch in Python with raw TCP sockets
(standard library only). It caches responses according to the HTTP caching rules, revalidates
stale copies with `ETag` / `Last-Modified`, tunnels HTTPS with `CONNECT`, blocks listed domains,
and keeps running when clients or web servers misbehave. A companion client measures how much
faster cached responses are.

> **University project.** This started as a team project for a university computer networks
> course (an HTTP proxy with caching, a firewall and error handling). It was later extended
> beyond the course requirements with HTTPS tunnelling, shared-cache rules, chunked decoding,
> loop detection, a client limit and a larger test suite.

## Features

- **HTTP forwarding** – accepts `GET http://host/path` and forwards it to the web server
  (HTTP/1.0 upstream, `chunked` responses decoded when a server sends them anyway).
- **HTTPS tunnelling** – `CONNECT host:443` opens a TCP tunnel and relays encrypted bytes in both
  directions. Allowed to port 443 only, so the proxy is not an open relay.
- **Shared cache** – follows `Cache-Control` (`no-store`, `private`, `no-cache`, `max-age`,
  `s-maxage`), `Age` and `Expires`. LRU eviction bounded by entry count *and* total bytes;
  responses over 5 MB pass through without being stored.
- **Revalidation** – a stale copy with an `ETag` or `Last-Modified` is checked with
  `If-None-Match` / `If-Modified-Since`; on `304 Not Modified` the new headers are merged in and
  the body is served without a new download.
- **Safe sharing** – `Set-Cookie` is never stored, so one user's session cookie is never replayed
  to another client.
- **Firewall** – domains in `blocked_domains.txt` and their sub-domains get `403 Forbidden`, for
  both HTTP and HTTPS (a trailing dot such as `facebook.com.` does not get around it).
- **Resilience** – 400/405/408/501 for bad requests, 502/504 for DNS failures, refused
  connections and silent servers, a 30 s limit on a whole transfer (stops slow-drip servers), a
  20 MB response cap, `Via`-based loop detection (508), a limit of 100 simultaneous clients (503),
  and a FIN-then-drain close so early error replies are not lost to a TCP reset.
- **Observability** – every reply carries `X-Cache` (`HIT`, `HIT (revalidated)`, `MISS`,
  `BLOCKED`, `ERROR`); every decision is logged (`CACHE HIT`, `CACHE MISS`, `TUNNEL`, `BLOCKED`,
  `ERROR`) to the console and `proxy.log`.

## How it works

```
                 GET http://host/path                       GET /path (HTTP/1.0) + Via
client.py ──────────────────────────────▶ proxy.py ───────────────────────────────▶ web server
                                           │ 0. loop check            (508)
                                           │ 1. parse and validate    (400 / 405 / 501)
                                           │ 2. firewall              (403)
                                           │ 3. cache lookup          fresh copy → HIT, no network
                                           │ 4. fetch or revalidate   (502 / 504 on failure)
                                           │ 5. store if headers allow
          ◀────────── response + X-Cache ──┘

                 CONNECT host:443                           TCP connection
client.py ──────────────────────────────▶ proxy.py ───────────────────────────────▶ web server
          ◀── 200 Connection Established ──┘
          ═════════ TLS, encrypted end to end; the proxy only copies bytes ═════════▶
```

Each client connection runs in its own thread (a semaphore caps how many); a lock protects the
shared cache. A tunnel uses two threads, one per direction, so a full buffer on one side can never
deadlock the other.

## Quick start

Requires Python 3.10 or newer. Nothing to install.

```bash
# terminal 1: start the proxy (Ctrl+C to stop)
python proxy.py --port 8888

# terminal 2: request the same page three times
python client.py http://example.com/ -n 3 --no-body
```

```
Request 1/3: GET http://example.com/
Source      : WEB SERVER (fetched by proxy, now cached if allowed)   [X-Cache: MISS]
Time taken  : 162.44 ms
Request 2/3: GET http://example.com/
Source      : CACHE (served from proxy cache)   [X-Cache: HIT]
Time taken  : 0.78 ms
...
Average MISS: 162.44 ms | Average HIT: 0.64 ms | Speed-up: 252.8x
```

HTTPS goes through a tunnel. The client checks the server's certificate itself, and the proxy
never sees or caches the content:

```bash
python client.py https://httpbin.org/get --no-body
```

```
Status      : HTTP/1.0 200 OK
Source      : HTTPS TUNNEL (encrypted end to end, never cached)   [X-Cache: TUNNEL]
```

## Benchmark

`measure.py` sends 5 requests per site with the cache (1 miss + 4 hits) and 5 with `--no-cache`.
Measured on Windows 11 over a home connection ([`results.csv`](results.csv)):

| Site | Without cache (avg) | Cache hit (avg) | Speed-up |
| --- | ---: | ---: | ---: |
| example.com | 142.9 ms | 0.55 ms | 261× |
| httpbin.org/get | 363.6 ms | 0.68 ms | 531× |
| info.cern.ch | 171.1 ms | 0.68 ms | 251× |

```bash
python measure.py http://example.com/ http://httpbin.org/get http://info.cern.ch/ -n 5 --csv results.csv
```

## More examples

```bash
python client.py http://httpbin.org/etag/abc123       # wait > 60 s, run again → HIT (revalidated)
python client.py http://www.facebook.com/             # 403 Forbidden (listed in blocked_domains.txt)
python client.py https://www.facebook.com/            # 403 as well: the CONNECT is refused
python client.py http://no-such-host.invalid/         # 502 Bad Gateway, proxy keeps running
python client.py http://127.0.0.1:8888/               # 508 Loop Detected
python rawsend.py "HELLO\r\n\r\n"                     # 400 Bad Request
python client.py http://example.com/ --headers        # also print the response headers
```

| Program | Options |
| --- | --- |
| `proxy.py` | `--host 127.0.0.1` `--port 8888` `--blocked blocked_domains.txt` `--log proxy.log` |
| `client.py` | `--proxy HOST:PORT` `-n N` `--no-cache` `--no-body` `--full` `--headers` |
| `measure.py` | `-n N` (≥ 2) `--proxy HOST:PORT` `--csv FILE` |

`blocked_domains.txt` holds one domain per line (`#` starts a comment). It is read when the first
request arrives, so restart the proxy after editing it.

## Tests

```bash
python test_proxy.py -v
```

64 tests run against local servers, so no internet is needed: a web server that can also answer
badly on purpose (truncated, malformed chunked, garbage, silent, one byte every 1.5 s) and an echo
server that stands in for an HTTPS site. They cover the cache rules, revalidation, the firewall,
error mapping, loop detection, the client limit, tunnelling (including 2 MB in both directions at
once), 150 fuzzed requests, the client and the benchmark script. GitHub Actions runs them on Linux
and Windows with Python 3.10 and 3.13 on every push.

## Project layout

| File | Purpose |
| --- | --- |
| `proxy.py` | The proxy: parsing, firewall, cache, forwarding, tunnelling, logging |
| `client.py` | Client that sends HTTP and HTTPS requests through the proxy and times them |
| `measure.py` | Benchmark with and without the cache, prints Markdown tables |
| `rawsend.py` | Sends a raw (possibly invalid) request, for error-handling checks |
| `test_proxy.py` | Automated test suite |
| `blocked_domains.txt` | Firewall rules |
| `results.csv` | Benchmark data used above |

## Limitations

- HTTPS is tunnelled, not inspected, so HTTPS responses are never cached (by design).
- Only `GET` and `CONNECT`; one request per connection (`Connection: close`).
- The cache lives in memory and is empty after a restart.
- The firewall matches host names, so a blocked site requested by IP address is not blocked.
- No authentication; by default the proxy listens on `127.0.0.1` only.
