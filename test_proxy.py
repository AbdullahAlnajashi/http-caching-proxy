#!/usr/bin/env python3
"""
Automated tests for proxy.py, client.py and measure.py
------------------------------------------------------
Starts the proxy and a small local "web server" that can also answer badly on purpose,
so caching, the firewall and error handling can be tested without the internet.

Run:  python test_proxy.py          (add -v for one line per test)
"""

import gzip
import io
import logging
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest

import client
import measure
import proxy

# Short timeouts so the tests run fast (the real values are in proxy.py)
proxy.CLIENT_TIMEOUT = 2
proxy.ORIGIN_TIMEOUT = 2.5


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# Local web server used as the "origin". Each path gives a different answer.
# ---------------------------------------------------------------------------
class Origin:
    def __init__(self):
        self.port = free_port()
        self.hits = {}                       # URL -> number of requests that reached the server
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(100)
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, conn):
        try:
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                c = conn.recv(4096)
                if not c:
                    return
                data += c
            full = data.split(b"\r\n")[0].split()[1].decode("latin1")
            path = full.split("?")[0]
            hdr = data.decode("latin1").lower()
            with self.lock:
                self.hits[full] = self.hits.get(full, 0) + 1
            send = conn.sendall

            def ok(extra, body):
                send(b"HTTP/1.0 200 OK\r\n" + extra + b"Content-Length: %d\r\n\r\n" % len(body) + body)

            if path == "/maxage":
                ok(b"Cache-Control: max-age=30\r\n", b"cached page")
            elif path == "/shortlived":
                ok(b"Cache-Control: max-age=1\r\n", b"short")
            elif path == "/nostore":
                ok(b"Cache-Control: no-store\r\n", b"secret")
            elif path == "/private":
                ok(b"Cache-Control: private, max-age=60\r\n", b"mine")
            elif path == "/nocache":
                ok(b"Cache-Control: no-cache\r\nETag: \"n1\"\r\n", b"must revalidate")
            elif path == "/noheaders":
                ok(b"", b"default ttl")
            elif path == "/etag":                # the 304 gives a new lifetime (max-age=100)
                if 'if-none-match: "v1"' in hdr:
                    send(b"HTTP/1.0 304 Not Modified\r\nETag: \"v1\"\r\nCache-Control: max-age=100\r\n\r\n")
                else:
                    ok(b"ETag: \"v1\"\r\nCache-Control: max-age=0\r\n", b"v1")
            elif path == "/etag2":               # the 304 also brings an updated header
                if 'if-none-match: "w1"' in hdr:
                    send(b"HTTP/1.0 304 Not Modified\r\nETag: \"w1\"\r\nX-Version: 2\r\n"
                         b"Cache-Control: max-age=100\r\n\r\n")
                else:
                    ok(b"ETag: \"w1\"\r\nX-Version: 1\r\nCache-Control: max-age=0\r\n", b"w1")
            elif path == "/cookie":
                ok(b"Cache-Control: max-age=60\r\nSet-Cookie: session=SECRET123\r\n", b"cookie page")
            elif path == "/age":                 # already 60 s old in another cache: stale at once
                ok(b"Cache-Control: max-age=60\r\nAge: 60\r\n", b"already old")
            elif path == "/lastmod":
                if "if-modified-since" in hdr:
                    send(b"HTTP/1.0 304 Not Modified\r\n\r\n")
                else:
                    ok(b"Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nCache-Control: max-age=0\r\n", b"lm")
            elif path == "/spoof":
                ok(b"X-Cache: HIT\r\nConnection: keep-alive\r\nCache-Control: max-age=30\r\n", b"spoof")
            elif path == "/truncated":
                send(b"HTTP/1.0 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 1000\r\n\r\n0123456789")
            elif path == "/chunked":
                send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            elif path == "/garbage":
                send(b"this is not http at all")
            elif path == "/nostatus":
                send(b"HTTP/1.1 abc OK\r\n\r\nx")
            elif path == "/silent":
                time.sleep(4)
            elif path == "/slow":
                time.sleep(0.3)
                ok(b"Cache-Control: max-age=30\r\n", b"slow")
            elif path == "/big":                 # 15 MB: too large to cache
                ok(b"Cache-Control: max-age=60\r\n", b"x" * (15 * 1024 * 1024))
            elif path == "/medium":              # 4 MB: can be cached
                ok(b"Cache-Control: max-age=60\r\n", os.urandom(4 * 1024 * 1024))
            elif path == "/gzip":
                ok(b"Content-Encoding: gzip\r\n", gzip.compress(b"hello gzip " * 20))
            elif path == "/arabic":
                ok(b"Content-Type: text/html; charset=utf-8\r\nCache-Control: max-age=30\r\n",
                   "مرحبا بالعالم".encode())
            elif path == "/notfound":
                send(b"HTTP/1.0 404 Not Found\r\nCache-Control: max-age=60\r\nContent-Length: 2\r\n\r\nno")
            elif path == "/redirect":
                send(b"HTTP/1.0 301 Moved Permanently\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n")
            else:
                ok(b"", b"hello")
        except OSError:
            pass
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def raw_request(port, raw, timeout=15):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(raw)
        data = bytearray()
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                data += c
        except socket.timeout:
            data += b"[TIMEOUT]"
        except ConnectionResetError:
            pass
        return bytes(data)
    finally:
        s.close()


def parse(data):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP/") else 0
    hdrs = [tuple(l.split(": ", 1)) for l in lines[1:] if ": " in l]
    return status, hdrs, body


def xcache(hdrs):
    vals = [v for k, v in hdrs if k.lower() == "x-cache"]
    assert len(vals) == 1, f"expected exactly one X-Cache header, got {vals}"
    return vals[0]


class ProxyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = Origin()
        cls.tmp = tempfile.mkdtemp()
        cls.rules = os.path.join(cls.tmp, "blocked.txt")
        with open(cls.rules, "w", encoding="utf-8") as f:
            f.write("# test rules\nblocked.test\n")
        cls.port = free_port()
        cls.logs = ListHandler()
        proxy.log.addHandler(cls.logs)
        proxy.log.setLevel(logging.INFO)
        proxy.log.propagate = False
        threading.Thread(target=proxy.serve, args=("127.0.0.1", cls.port, cls.rules),
                         daemon=True).start()
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    # one request through the proxy; a unique query string per test avoids cross-test cache hits
    def get(self, path, extra="", raw_url=None):
        url = raw_url or f"http://127.0.0.1:{self.origin.port}{path}"
        data = raw_request(self.port, f"GET {url} HTTP/1.1\r\nHost: x\r\n{extra}\r\n".encode())
        return parse(data)

    def alive(self):
        status, _, body = self.get("/alive-check?" + str(random.random()))
        self.assertEqual((status, body), (200, b"hello"), "proxy stopped working")


class CachingTests(ProxyTestCase):
    def test_miss_then_hit(self):
        s1, h1, b1 = self.get("/maxage?a=1")
        s2, h2, b2 = self.get("/maxage?a=1")
        self.assertEqual((s1, xcache(h1), b1), (200, "MISS", b"cached page"))
        self.assertEqual((s2, xcache(h2), b2), (200, "HIT", b"cached page"))
        self.assertEqual(self.origin.hits["/maxage?a=1"], 1)

    def test_hit_is_faster_than_miss(self):
        t = time.perf_counter(); self.get("/slow?a=1"); miss = time.perf_counter() - t
        t = time.perf_counter(); self.get("/slow?a=1"); hit = time.perf_counter() - t
        self.assertLess(hit, miss / 5)

    def test_different_urls_not_confused(self):
        self.get("/maxage?x=1")
        s, h, _ = self.get("/maxage?x=2")
        self.assertEqual(xcache(h), "MISS")

    def test_max_age_expires(self):
        self.get("/shortlived?a=1")
        self.assertEqual(xcache(self.get("/shortlived?a=1")[1]), "HIT")
        time.sleep(1.3)
        self.assertEqual(xcache(self.get("/shortlived?a=1")[1]), "MISS")

    def test_default_ttl_when_no_headers(self):
        self.get("/noheaders?a=1")
        self.assertEqual(xcache(self.get("/noheaders?a=1")[1]), "HIT")

    def test_no_store_and_private_never_cached(self):
        for p in ("/nostore?a=1", "/private?a=1"):
            self.get(p)
            self.assertEqual(xcache(self.get(p)[1]), "MISS", p)
            self.assertEqual(self.origin.hits[p], 2)

    def test_no_cache_always_asks_the_server(self):
        self.get("/nocache?a=1")
        self.assertEqual(xcache(self.get("/nocache?a=1")[1]), "MISS")
        self.assertEqual(self.origin.hits["/nocache?a=1"], 2)

    def test_non_200_not_cached(self):
        self.get("/notfound?a=1")
        s, h, _ = self.get("/notfound?a=1")
        self.assertEqual((s, xcache(h)), (404, "MISS"))

    def test_redirect_passed_through(self):
        s, h, _ = self.get("/redirect?a=1")
        self.assertEqual(s, 301)
        self.assertIn(("Location", "http://example.com/"), h)

    def test_etag_revalidation_and_new_lifetime_from_304(self):
        self.get("/etag?a=1")                                  # MISS, max-age=0 -> stale at once
        s, h, b = self.get("/etag?a=1")                         # conditional request -> 304
        self.assertEqual((s, xcache(h), b), (200, "HIT (revalidated)", b"v1"))
        s, h, _ = self.get("/etag?a=1")                         # the 304 said max-age=100 -> plain HIT
        self.assertEqual(xcache(h), "HIT")
        self.assertEqual(self.origin.hits["/etag?a=1"], 2)

    def test_last_modified_revalidation(self):
        self.get("/lastmod?a=1")
        self.assertEqual(xcache(self.get("/lastmod?a=1")[1]), "HIT (revalidated)")

    def test_client_no_cache_bypasses_cache(self):
        self.get("/maxage?b=1")
        s, h, _ = self.get("/maxage?b=1", "Cache-Control: no-cache\r\n")
        self.assertEqual(xcache(h), "MISS (bypass)")
        self.assertEqual(self.origin.hits["/maxage?b=1"], 2)
        self.assertEqual(xcache(self.get("/maxage?b=1")[1]), "HIT")           # fresh copy is stored
        s, h, _ = self.get("/maxage?b=1", "Pragma: no-cache\r\n")
        self.assertEqual(xcache(h), "MISS (bypass)")

    def test_origin_cannot_fake_x_cache(self):
        s, h, _ = self.get("/spoof?a=1")
        self.assertEqual(xcache(h), "MISS")                                   # exactly one X-Cache header
        self.assertFalse(any(k.lower() == "connection" and v == "keep-alive" for k, v in h))

    def test_host_name_is_case_insensitive(self):
        p = self.origin.port
        self.get("/maxage?n=1", raw_url=f"http://LOCALHOST:{p}/maxage?n=1")
        s, h, _ = self.get("/maxage?n=1", raw_url=f"http://localhost:{p}/maxage?n=1")
        self.assertEqual(xcache(h), "HIT")

    def test_large_body_not_cached_but_complete(self):
        s, h, b = self.get("/big?a=1")
        self.assertEqual((s, xcache(h), len(b)), (200, "MISS", 15 * 1024 * 1024))
        self.assertEqual(xcache(self.get("/big?a=1")[1]), "MISS")

    def test_medium_body_cached_intact(self):
        _, _, b1 = self.get("/medium?a=1")
        s, h, b2 = self.get("/medium?a=1")
        self.assertEqual((xcache(h), len(b2)), ("HIT", 4 * 1024 * 1024))
        self.assertEqual(b1, b2)

    def test_binary_and_utf8_pass_through(self):
        _, _, b = self.get("/arabic?a=1")
        self.assertEqual(b.decode("utf-8"), "مرحبا بالعالم")
        s, h, b = self.get("/gzip?a=1")
        self.assertIn(("Content-Encoding", "gzip"), h)
        self.assertEqual(gzip.decompress(b), b"hello gzip " * 20)

    def test_cache_log_lines(self):
        self.get("/maxage?log=1"); self.get("/maxage?log=1")
        log = "\n".join(self.logs.lines)
        self.assertIn("CACHE MISS", log)
        self.assertIn("CACHE HIT", log)

    def test_set_cookie_not_replayed_to_other_clients(self):
        _, h1, _ = self.get("/cookie?a=1")
        _, h2, _ = self.get("/cookie?a=1")
        self.assertEqual(xcache(h2), "HIT")
        self.assertTrue(any(k.lower() == "set-cookie" for k, _ in h1))        # the first client gets it
        self.assertFalse(any(k.lower() == "set-cookie" for k, _ in h2))       # nobody else does

    def test_age_header_is_respected(self):
        self.get("/age?a=1")
        self.assertEqual(xcache(self.get("/age?a=1")[1]), "MISS")

    def test_304_updates_stored_headers(self):
        self.get("/etag2?a=1")
        s, h, b = self.get("/etag2?a=1")
        self.assertEqual((xcache(h), b), ("HIT (revalidated)", b"w1"))
        self.assertIn(("X-Version", "2"), h)


class CacheUnitTests(unittest.TestCase):
    def entry(self, n=1):
        return proxy.CacheEntry(200, "OK", [("ETag", '"x"')], b"x" * n, time.time() + 100)

    def test_byte_limit_evicts_oldest(self):
        c = proxy.Cache(max_entries=100, max_bytes=1000)
        c.put("a", self.entry(400)); c.put("b", self.entry(400))
        c.put("a", self.entry(400))                 # replacing must not count the bytes twice
        self.assertEqual(len(c), 2)
        c.put("c", self.entry(400))                 # over 1000 bytes -> the oldest (b) goes
        self.assertIsNone(c.get("b")); self.assertIsNotNone(c.get("a"))

    def test_byte_count_follows_entry_that_grew(self):
        c = proxy.Cache(max_entries=100, max_bytes=10**9)
        e = self.entry(10)
        c.put("a", e)
        e.set_headers([("ETag", '"x"'), ("X-Long", "y" * 500)])   # e.g. headers merged from a 304
        c.put("a", e)
        self.assertEqual(c.size_bytes, e.size)

    def test_shared_cache_rules(self):
        now = time.time()
        f = proxy.compute_expiry
        self.assertAlmostEqual(f([("Cache-Control", "max-age=10, s-maxage=50")]), now + 50, delta=1)
        self.assertAlmostEqual(f([("Cache-Control", "max-age=60"), ("Age", "20")]), now + 40, delta=1)
        self.assertAlmostEqual(f([("Cache-Control", "max-age=-5")]), now, delta=1)

    def test_oldest_entry_removed_when_full(self):
        c = proxy.Cache(max_entries=2)
        for k in "abc":
            c.put(k, self.entry())
        self.assertIsNone(c.get("a"))
        self.assertIsNotNone(c.get("b")); self.assertIsNotNone(c.get("c"))

    def test_recently_used_entry_survives(self):
        c = proxy.Cache(max_entries=2)
        c.put("a", self.entry()); c.put("b", self.entry())
        c.get("a"); c.put("c", self.entry())
        self.assertIsNotNone(c.get("a")); self.assertIsNone(c.get("b"))

    def test_compute_expiry(self):
        now = time.time()
        f = proxy.compute_expiry
        self.assertIsNone(f([("Cache-Control", "no-store")]))
        self.assertIsNone(f([("Cache-Control", "private")]))
        self.assertAlmostEqual(f([("Cache-Control", "max-age=10")]), now + 10, delta=1)
        self.assertAlmostEqual(f([("Cache-Control", "max-age=abc")]), now + proxy.DEFAULT_TTL, delta=1)
        self.assertLessEqual(f([("Expires", "Wed, 21 Oct 2015 07:28:00 GMT")]), now)
        self.assertLessEqual(f([("Expires", "garbage")]), now + 1)
        self.assertLessEqual(f([("Cache-Control", "no-cache")]), now + 1)
        self.assertAlmostEqual(f([]), now + proxy.DEFAULT_TTL, delta=1)

    def test_expires_without_time_zone_means_gmt(self):
        # "-0000" is the old way of writing GMT; it must not depend on the computer's time zone
        gmt = proxy.compute_expiry([("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")])
        zero = proxy.compute_expiry([("Expires", "Thu, 01 Jan 2099 00:00:00 -0000")])
        self.assertEqual(gmt, zero)

    def test_ipv6_url_keeps_brackets(self):
        url, host, port, path, _ = proxy.parse_request(b"GET http://[::1]:8080/x HTTP/1.1\r\n\r\n")
        self.assertEqual((url, host, port, path), ("http://[::1]:8080/x", "::1", 8080, "/x"))


class FirewallTests(ProxyTestCase):
    def test_blocked_domain_and_subdomain(self):
        for url in ("http://blocked.test/", "http://www.blocked.test/x?y=1",
                    "http://A.B.BLOCKED.TEST/", "http://blocked.test:8080/"):
            s, h, b = self.get("", raw_url=url)
            self.assertEqual((s, xcache(h)), (403, "BLOCKED"), url)
            self.assertIn(b"blocked", b.lower())
        self.assertTrue(any("BLOCKED" in l for l in self.logs.lines))

    def test_similar_names_not_blocked(self):
        fw = proxy.Firewall(self.rules)
        for host in ("notblocked.test", "blocked.test.evil.com", "test"):
            self.assertFalse(fw.is_blocked(host), host)

    def test_rules_file_with_comments_and_notepad_bom(self):
        path = os.path.join(self.tmp, "fmt.txt")
        with open(path, "wb") as f:
            f.write("﻿bom.test\r\n# comment\r\n\r\nUPPER.TEST  # inline comment\r\n".encode("utf-8"))
        fw = proxy.Firewall(path)
        self.assertTrue(fw.is_blocked("bom.test"))
        self.assertTrue(fw.is_blocked("upper.test"))
        self.assertFalse(fw.is_blocked("comment"))

    def test_trailing_dot_cannot_bypass_firewall(self):
        # "blocked.test." is the same site as "blocked.test" (a fully qualified name)
        for url in ("http://blocked.test./", "http://www.blocked.test./x"):
            s, h, _ = self.get("", raw_url=url)
            self.assertEqual((s, xcache(h)), (403, "BLOCKED"), url)

    def test_missing_rules_file_blocks_nothing(self):
        fw = proxy.Firewall(os.path.join(self.tmp, "does-not-exist.txt"))
        self.assertFalse(fw.is_blocked("anything.test"))


class ErrorHandlingTests(ProxyTestCase):
    def status(self, raw, **kw):
        return parse(raw_request(self.port, raw, **kw))[0]

    def test_malformed_requests(self):
        cases = {
            b"HELLO WORLD\r\n\r\n": 400,
            b"GET\r\n\r\n": 400,
            b"GET http://a/ HTTP/1.1 extra\r\n\r\n": 400,
            b"GET http://a/ FTP/1.1\r\n\r\n": 400,
            b"\xff\xfe\x00\x01\r\n\r\n": 400,
            b"GET /relative HTTP/1.1\r\nHost: a.test\r\n\r\n": 400,
            b"GET http://127.0.0.1:abc/ HTTP/1.1\r\n\r\n": 400,
            b"GET http://127.0.0.1:99999/ HTTP/1.1\r\n\r\n": 400,
            b"GET http://127.0.0.1:0/ HTTP/1.1\r\n\r\n": 400,
            b"GET http:///nohost HTTP/1.1\r\n\r\n": 400,
            b"POST http://a.test/ HTTP/1.1\r\n\r\n": 405,
            b"GET https://a.test/ HTTP/1.1\r\n\r\n": 501,
        }
        for raw, expected in cases.items():
            self.assertEqual(self.status(raw), expected, raw)
        self.alive()

    def test_oversized_headers_do_not_stop_the_proxy(self):
        raw = b"GET http://a.test/ HTTP/1.1\r\nX: " + b"x" * 70000 + b"\r\n\r\n"
        self.assertIn(self.status(raw), (400, 0))    # 0 = connection closed before the reply was read
        self.alive()

    def test_dns_failure_and_refused(self):
        self.assertEqual(self.get("", raw_url="http://no-such-host.invalid/")[0], 502)
        self.assertEqual(self.get("", raw_url="http://127.0.0.1:9/")[0], 502)
        self.alive()

    def test_bad_origin_responses_are_502_and_not_cached(self):
        for p in ("/truncated", "/chunked", "/garbage", "/nostatus"):
            self.assertEqual(self.get(p + "?a=1")[0], 502, p)
            self.assertEqual(self.get(p + "?a=1")[0], 502, p + " (second time)")
        self.alive()

    def test_silent_origin_gets_504(self):
        self.assertEqual(self.get("/silent?a=1")[0], 504)
        self.alive()

    def test_silent_client_gets_408(self):
        data = raw_request(self.port, b"GET http://a.test/ HTTP/1.1\r\nHost:", timeout=10)
        self.assertEqual(parse(data)[0], 408)
        self.alive()

    def test_client_disconnects_mid_response(self):
        for _ in range(3):
            s = socket.create_connection(("127.0.0.1", self.port))
            s.sendall(f"GET http://127.0.0.1:{self.origin.port}/big?d={random.random()} HTTP/1.1\r\n\r\n".encode())
            s.recv(1000)
            s.close()                                                  # leave while the proxy is still sending
        time.sleep(1.5)
        self.alive()


class ConcurrencyTests(ProxyTestCase):
    def test_parallel_clients(self):
        results, errors = [], []

        def worker(i):
            try:
                s, h, b = self.get(f"/slow?par={i % 5}")
                results.append((s, b))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        t = time.time()
        for th in threads: th.start()
        for th in threads: th.join()
        self.assertEqual(errors, [])
        self.assertEqual(results, [(200, b"slow")] * 20)
        self.assertLess(time.time() - t, 5)                            # served in parallel, not one by one


class ClientTests(ProxyTestCase):
    def fetch(self, path, **kw):
        return client.fetch(f"http://127.0.0.1:{self.origin.port}{path}", "127.0.0.1", self.port, **kw)

    def test_client_shows_source_and_time(self):
        r1, r2 = self.fetch("/slow?c=1"), self.fetch("/slow?c=1")
        self.assertEqual((r1["cache"], r2["cache"]), ("MISS", "HIT"))
        self.assertGreater(r1["elapsed_ms"], r2["elapsed_ms"] * 5)
        self.assertEqual(client.describe_source("HIT"), "CACHE (served from proxy cache)")

    def test_client_no_cache_flag(self):
        self.fetch("/maxage?c=2")
        self.assertEqual(self.fetch("/maxage?c=2", no_cache=True)["cache"], "MISS (bypass)")

    def test_client_blocked_and_error_sources(self):
        self.assertEqual(client.fetch("http://blocked.test/", "127.0.0.1", self.port)["cache"], "BLOCKED")
        self.assertEqual(client.fetch("http://x.invalid/", "127.0.0.1", self.port)["cache"], "ERROR")

    def test_client_rejects_bad_urls(self):
        for url in ("example.com", "https://example.com", "ftp://x/", "http://", ""):
            with self.assertRaises(ValueError, msg=url):
                client.fetch(url, "127.0.0.1", self.port)

    def test_client_handles_unicode_body(self):
        self.assertEqual(client.body_text(self.fetch("/arabic?c=1")), "مرحبا بالعالم")

    def test_client_empty_response(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]

        def serve_once():
            c, _ = srv.accept(); c.recv(1000); c.close(); srv.close()   # closes without replying
        threading.Thread(target=serve_once, daemon=True).start()
        with self.assertRaises(ConnectionError):
            client.fetch("http://x.test/", "127.0.0.1", port)

    def test_client_proxy_not_running(self):
        with self.assertRaises(ConnectionRefusedError):
            client.fetch("http://x.test/", "127.0.0.1", free_port())

    def run_main(self, module, argv):
        """Run a program's main() with these arguments and return what it printed."""
        old_argv, old_out = sys.argv, sys.stdout
        sys.argv, sys.stdout = [module.__name__ + ".py"] + argv, io.StringIO()
        try:
            module.main()
            return sys.stdout.getvalue()
        finally:
            sys.argv, sys.stdout = old_argv, old_out

    def test_client_headers_option_prints_response_headers(self):
        url = f"http://127.0.0.1:{self.origin.port}/maxage?h=1"
        out = self.run_main(client, [url, "--proxy", f"127.0.0.1:{self.port}", "--headers", "--no-body"])
        self.assertIn("Cache-Control: max-age=30", out)
        self.assertIn("X-Cache: MISS", out)


class MeasureTests(ProxyTestCase):
    def test_one_request_per_mode_is_refused_clearly(self):
        # with -n 1 there can be no cache hit to compare, so measure.py must stop with a message
        url = f"http://127.0.0.1:{self.origin.port}/maxage?m=1"
        with self.assertRaises(SystemExit) as cm:
            ClientTests.run_main(self, measure, [url, "-n", "1", "--proxy", f"127.0.0.1:{self.port}"])
        self.assertIn("at least 2", str(cm.exception))

    def test_measure_prints_summary(self):
        url = f"http://127.0.0.1:{self.origin.port}/maxage?m=2"
        out = ClientTests.run_main(self, measure, [url, "-n", "2", "--proxy", f"127.0.0.1:{self.port}"])
        self.assertIn("Speed-up of a hit", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
