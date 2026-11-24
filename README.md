# HTTP Caching Proxy with Firewall

[![tests](https://github.com/AbdullahAlnajashi/http-caching-proxy/actions/workflows/tests.yml/badge.svg)](https://github.com/AbdullahAlnajashi/http-caching-proxy/actions/workflows/tests.yml)

A multi-threaded HTTP/1.x forward proxy written from scratch in Python with raw TCP sockets
(standard library only). It caches responses according to their HTTP headers, revalidates stale
copies with `ETag` / `Last-Modified`, blocks listed domains, and keeps running when clients or
web servers misbehave. A companion client measures how much faster cached responses are.

## Features

- **Forwarding** – accepts `GET http://host/path` requests and forwards them to the web server.
- **Header-driven cache** – honours `Cache-Control` (`no-store`, `private`, `no-cache`, `max-age`)
  and `Expires`; least-recently-used eviction; responses over 5 MB are passed through but not stored.
- **Revalidation** – a stale copy with an `ETag` or `Last-Modified` is checked with
  `If-None-Match` / `If-Modified-Since`; a `304 Not Modified` refreshes it without a new download.
- **Firewall** – domains in `blocked_domains.txt` (and their sub-domains) get `403 Forbidden`.
- **Error handling** – malformed requests, DNS failures, refused connections, silent servers and
  truncated answers become `400/405/408/501/502/504` responses; one bad request never stops the proxy.
- **Logging** – every `CACHE HIT`, `CACHE MISS`, `BLOCKED` and `ERROR` goes to the console and `proxy.log`.
- **Observability** – every reply carries an `X-Cache` header (`HIT`, `HIT (revalidated)`, `MISS`,
  `BLOCKED`, `ERROR`), which the client uses to show where the answer came from.

## How it works

```
client.py ──GET http://host/path──▶ proxy.py ──GET /path (HTTP/1.0)──▶ web server
                                     │  1. parse and validate     (400 / 405 / 501)
                                     │  2. firewall check         (403)
                                     │  3. cache lookup           fresh copy → HIT, no network
                                     │  4. fetch or revalidate    (502 / 504 on failure)
                                     │  5. store if headers allow
          ◀──── response + X-Cache ──┘
```

Each client connection runs in its own thread; a lock protects the shared cache.

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

Only plain `http://` is supported (`https://` returns `501`). Sites that work well for testing:
`http://example.com/`, `http://httpbin.org/get`, `http://info.cern.ch/`.

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
python client.py http://no-such-host.invalid/        # 502 Bad Gateway, proxy keeps running
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

46 tests run against a local web server that can also answer badly on purpose (truncated bodies,
garbage, silence), so no internet is needed. They cover cache hits and misses, expiry, ETag and
Last-Modified revalidation, `no-store`, the firewall, malformed requests, gateway errors, parallel
clients, the client and the benchmark script. GitHub Actions runs them on Linux and Windows on every push.

## Project layout

| File | Purpose |
| --- | --- |
| `proxy.py` | The proxy: parsing, firewall, cache, forwarding, logging |
| `client.py` | Client that sends requests through the proxy and times them |
| `measure.py` | Benchmark with and without the cache, prints Markdown tables |
| `rawsend.py` | Sends a raw (possibly invalid) request, for error-handling checks |
| `test_proxy.py` | Automated test suite |
| `blocked_domains.txt` | Firewall rules |
| `results.csv` | Benchmark data used above |

## Limitations

- HTTP only; no `CONNECT` tunnelling for HTTPS.
- Only `GET`; one request per connection (`Connection: close`).
- The cache lives in memory and is empty after a restart.
- The firewall matches host names, so a blocked site requested by IP address is not blocked.
- No authentication; by default the proxy listens on `127.0.0.1` only.
