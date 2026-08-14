# onion_collector

A forensic, resumable, hash-verifying recursive downloader for collecting
files exposed on a Tor Onion Service directory listing, for **authorized**
incident-response, evidence preservation, and recovery work (e.g.
collecting your own organization's files after a ransomware/data-leak
disclosure).

It is a plain HTTP client (`requests` + `BeautifulSoup`) routed through a
local Tor SOCKS5 proxy. It does not use a browser, does not execute
JavaScript, does not spoof headers or IPs, and never opens/executes any
downloaded file. It only crawls `tr.dir` / `tr.file` directory-listing rows,
downloads the raw bytes, and records everything in SQLite + a CSV manifest
so the collection is reproducible and auditable.

> **Scope of use:** This tool is for collecting data you are authorized to
> collect. It contains no exploitation, credential-theft, authentication
> bypass, or attribution-evasion functionality. It simply performs ordinary
> GET requests over Tor, because Tor is the only way to reach a `.onion`
> address at all.

---

## 1. Project structure

```
onion_collector/
    onion_collector.py
    requirements.txt
    README.md
```

Running the tool creates a **case directory** (`--output`, default
`./evidence_case`) containing:

```
evidence_case/
    evidence/          # downloaded files, mirroring the remote directory tree
    crawler.db         # SQLite state database (resume support)
    manifest.csv        # human-readable evidence ledger
    crawler.log         # full run log
```

---

## 2. Installation

### Linux

```bash
# 1. Install Tor
sudo apt update
sudo apt install -y tor python3 python3-venv python3-pip

# 2. Start Tor (systemd) - listens on 127.0.0.1:9050 by default
sudo systemctl enable --now tor
systemctl status tor

# 3. Set up the tool in a virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows

```powershell
# 1. Install Tor Expert Bundle or Tor Browser
#    https://www.torproject.org/download/tor/
#    (Tor Browser bundles a Tor client that listens on 127.0.0.1:9150 by
#    default - see the port note below. The standalone "Expert Bundle"
#    tor.exe uses 127.0.0.1:9050 by default, matching this tool's default.)

# 2. Install Python 3 from https://www.python.org/downloads/windows/
#    (check "Add Python to PATH" during install)

# 3. Set up the tool
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 4. Start tor.exe (Expert Bundle) in its own terminal, or launch Tor
#    Browser and keep it running in the background.
```

> **Port note:** Tor Browser's bundled Tor client typically listens on
> `127.0.0.1:9150`, not `9050`. If you're using Tor Browser instead of a
> standalone `tor` service, pass `--proxy socks5h://127.0.0.1:9150`.

---

## 3. Tor configuration

The tool needs a local Tor SOCKS5 proxy. Two common setups:

1. **System `tor` service** (Linux, or the Windows Expert Bundle):
   default SOCKS port `9050`.
2. **Tor Browser**: default SOCKS port `9150`. Tor Browser must remain
   open for its proxy to be available.

You can verify Tor is listening with:

```bash
# Linux/macOS
ss -ltnp | grep 9050
# or
netstat -an | grep 9050
```

```powershell
# Windows
netstat -ano | findstr 9050
```

The tool always uses **`socks5h://`** (not `socks5://`) so that `.onion`
hostname resolution happens *through* Tor rather than being leaked to
your normal DNS resolver.

---

## 4. Usage

### Test Tor connectivity first

```bash
python onion_collector.py \
    --url "http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/case/path/" \
    --proxy "socks5h://127.0.0.1:9050" \
    --test-tor
```

### Dry run (see what would be collected, download nothing)

```bash
python onion_collector.py \
    --url "http://xxxxx.onion/case/path/" \
    --output "./evidence_case" \
    --proxy "socks5h://127.0.0.1:9050" \
    --dry-run
```

### Small test batch first

```bash
python onion_collector.py \
    --url "http://xxxxx.onion/case/path/" \
    --output "./evidence_case" \
    --proxy "socks5h://127.0.0.1:9050" \
    --max-files 10
```

### Full collection

```bash
python onion_collector.py \
    --url "http://xxxxx.onion/case/path/" \
    --output "./evidence_case" \
    --proxy "socks5h://127.0.0.1:9050" \
    --workers 2 \
    --delay 1.0 \
    --retries 5 \
    --timeout 60
```

### Download just ONE file (no crawling at all)

If you already know the exact file URL, `--single-file` skips crawling
entirely and downloads only that one URL — still resumable, hash-verified,
and logged/manifested the same as a full run:

```bash
python onion_collector.py \
    --url "http://xxxxx.onion/e4d2e6cbb9dfa25ebc7b4caf0266bb60/MCDCSRVFS01/127.0.0.1/D:/Fejal/Maceio/Almoxarifado/AGENDA%20DOS%20TRANSPORTES/PLANILHA%20CONTROLE%20DE%20DEMANDAS/AGENDA%20TRANSPORTE%20Elias%2018.xlsx" \
    --output "./evidence_case" \
    --proxy "socks5h://127.0.0.1:9050" \
    --single-file
```

### Restrict the crawl to one company/host subfolder

By default (`--restrict-to-start`, on unless you disable it), the crawler
only follows links whose path falls **under** the folder you start it at
— it will never wander into a sibling folder elsewhere on the same onion
host. So to collect only the `MCDCSRVFS01` machine's files and nothing
else exposed on the same leak site, start the crawl there instead of at
the site root:

```bash
python onion_collector.py \
    --url "http://xxxxx.onion/e4d2e6cbb9dfa25ebc7b4caf0266bb60/MCDCSRVFS01/" \
    --output "./evidence_case" \
    --proxy "socks5h://127.0.0.1:9050"
```

Any link the crawler encounters that points outside that subtree (a
different machine name, a sibling company's folder, etc.) is logged as
"Out-of-scope link ignored" and never fetched. If you ever want the old
whole-host behavior back, add `--no-restrict-to-start`.

### Resume after an interruption

Just re-run the exact same command. The tool automatically detects the
existing `crawler.db` in `--output` and resumes; `--resume` is available
to make this explicit in your own scripts/logs, but it is not required —
resume is always the default whenever prior state exists.

```bash
python onion_collector.py \
    --url "http://xxxxx.onion/case/path/" \
    --output "./evidence_case" \
    --proxy "socks5h://127.0.0.1:9050" \
    --resume
```

### All options

| Flag | Default | Description |
|---|---|---|
| `--url` | *(required)* | Starting directory-listing URL |
| `--output` | `./evidence_case` | Case/output directory |
| `--proxy` | `socks5h://127.0.0.1:9050` | SOCKS5(h) proxy |
| `--workers` | `2` | Concurrent worker threads |
| `--delay` | `1.0` | Seconds between requests, per worker |
| `--retries` | `5` | Max retries per file (exponential backoff: 2s,4s,8s,16s,32s) |
| `--timeout` | `60` | Per-request connect timeout (seconds) |
| `--stall-timeout` | `300` | Max seconds a single chunk-read may stall mid-download before retrying (raise this on very slow Tor circuits) |
| `--resume` | off | Explicit resume flag (resume is automatic regardless) |
| `--max-files` | none | Stop after N files downloaded |
| `--max-size` | none | Stop after N bytes downloaded (e.g. `10GB`) |
| `--dry-run` | off | Crawl/report only, no downloads |
| `--test-tor` | off | Test connectivity to `--url` through the proxy, then exit |
| `--single-file` | off | Download only the exact file at `--url`; no crawling |
| `--restrict-to-start` / `--no-restrict-to-start` | on | Only follow links under the `--url` starting subtree |

---

## 5. How resume works

Every discovered directory and file is written to `crawler.db` (SQLite)
the moment it is discovered, with status `DISCOVERED`. As work proceeds,
status transitions to `DOWNLOADING`, then `DOWNLOADED` or `FAILED`.

If the process is killed (Ctrl-C, crash, power loss, network drop) at,
say, item 12,483 of 50,000:

- Anything already `DOWNLOADED` stays on disk with its recorded SHA-256.
- Anything left `DOWNLOADING` is treated as interrupted: on the next run,
  it is automatically reset to `DISCOVERED` and retried.
- Anything `FAILED` (retries exhausted) is retried again on the next run.
- Directories already fully listed (`DOWNLOADED`) are **not** re-fetched,
  so restart is fast even with tens of thousands of items.

Before re-downloading a file that already exists locally, the tool
recomputes its SHA-256 and compares it against the value stored in
`crawler.db`:

- **Hash matches** → file is treated as already collected; skipped.
- **Hash differs or file missing** → re-downloaded from scratch (this
  correctly handles a prior run that was killed mid-write, leaving a
  truncated/corrupt file on disk).

This means you can safely re-run the exact same command as many times as
needed until the collection finishes, without ever losing progress or
silently keeping a corrupted file.

---

## 6. How SHA-256 evidence integrity works

Every file is hashed **while it streams to disk**, in 1 MB chunks, so
large files never need to be fully loaded into memory. The resulting
SHA-256 digest is:

1. Stored in `crawler.db` alongside the URL, local path, size, and
   timestamps.
2. Written to `manifest.csv` as a single, portable evidence ledger you
   can attach to an incident report or hand to counsel/law enforcement.

Because the hash is computed independently on your side at collection
time, it provides:

- **Integrity verification** — you can re-hash the file at any later
  date and prove it hasn't been altered since collection.
- **Deduplication** — identical files (e.g. the same document exposed at
  two different paths) are still stored under both remote paths (never
  silently merged/overwritten), but their matching hashes make it easy
  to identify duplicates during review.
- **Chain-of-custody support** — the manifest ties each hash to an exact
  URL, HTTP status, discovery time, and download time.

Downloaded files are **never opened, executed, extracted, or rendered**
by this tool — only raw bytes are written to disk. This is deliberate:
running macros, opening archives, or rendering Office documents from an
adversary-controlled leak site could execute embedded malicious content.

---

## 7. Troubleshooting

**Progress appears completely frozen (same Discovered/Downloaded/Failed
numbers repeating forever)**
- This is almost always a Tor circuit stall combined with a known
  `PySocks` limitation: the SOCKS5 library `requests` uses to talk to
  Tor doesn't always honor the `timeout=` value once a circuit stalls,
  so the underlying socket can block far longer than `--timeout` — even
  indefinitely. With a small worker count, just 1–2 stuck sockets is
  enough to halt all visible progress (stats only update when an item
  finishes, so a stuck item shows up as nothing changing at all).
- The tool includes a hard wall-clock watchdog (independent of
  `requests`/PySocks) around every request's connect phase (`--timeout`
  + 20s), and a separate, more generous watchdog around each individual
  chunk of a streamed download (`--stall-timeout`, default 300s), since
  Tor circuits can be legitimately very slow — a few KB/s is common —
  and a too-short stall allowance would kill downloads that were
  actually still progressing, just slowly. You'll see periodic
  `... still receiving <url>: N bytes so far` heartbeat lines in
  `crawler.log` for a large file that's genuinely still coming in, and
  a `watchdog timeout exceeded` line only when a socket has truly gone
  silent for the full window.
- If you still see it stall for many minutes with no watchdog message
  and no heartbeat lines at all in `crawler.log`, check whether Tor's
  circuit itself has died: `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`.
  If that also hangs, restart the `tor` service (`sudo systemctl restart tor`)
  and simply re-run the same command — the crawl resumes exactly where
  it left off.
- If a specific onion path consistently times out while others work
  fine, that's more likely real server-side throttling/blocking on that
  path rather than a generic Tor stall — try requesting a fresh Tor
  circuit (`SIGNAL NEWNYM` via the control port, or restart the `tor`
  service) and/or increase `--delay`.

**SOCKS5 connection errors ("Failed to establish a new connection", proxy
refused)**
- Confirm Tor is actually running: `systemctl status tor` (Linux) or
  check that `tor.exe`/Tor Browser is running (Windows).
- Confirm the port matches: `9050` for a standalone `tor` service, `9150`
  for Tor Browser's bundled client.
- Run `--test-tor` first before a full crawl.

**Onion site unavailable / times out**
- Onion services can be slow or intermittently unreachable. Increase
  `--timeout` (e.g. `120`) and let `--retries` handle transient drops.
- Confirm the `.onion` address is correct and still published — leak
  sites sometimes rotate addresses.

**HTTP 403 / 404 / 500 on specific paths**
- These are recorded per-item in `crawler.db` / `manifest.csv` with the
  HTTP status and marked `FAILED`. Re-running will retry them; if they
  persist, the path may genuinely be gone or access-restricted server-side.

**Timeouts on large files**
- Increase `--timeout`. Streaming downloads mean memory isn't the
  bottleneck — only the per-request timeout matters here.

**Interrupted download / corrupted or incomplete file**
- Handled automatically: partial downloads are written to a temporary
  `*.part` file and only renamed into place after a full, successful
  read. On resume, any file whose on-disk SHA-256 doesn't match the
  recorded hash is re-downloaded rather than trusted.

**SQLite "database is locked"**
- All writes go through a single guarded connection with a re-entrant
  lock, so this shouldn't occur under normal use. If it does (e.g. an
  external process/tool has `crawler.db` open, such as a DB browser),
  close that other connection and re-run.

**Filename / path problems on Windows**
- Remote paths are sanitized per path segment: reserved characters
  (`< > : " | ? *` and control characters) are replaced, trailing dots
  and spaces are stripped, and overly long segments are shortened with a
  short content hash suffix. The **original** remote URL/path is always
  preserved in `crawler.db` and `manifest.csv`, even when the local
  on-disk name had to be adjusted.
- If two different remote URLs would map to the same local path, the
  second one is saved with a short deterministic hash suffix instead of
  overwriting the first.

---

## 8. Safety notes

- No IP spoofing, forged headers, or `X-Forwarded-For` manipulation.
- No Selenium/Playwright/browser automation; no JavaScript execution.
- No automatic execution, macro-running, archive extraction, or document
  rendering of collected files — only raw bytes are ever written.
- Conservative defaults (`--workers 2`, `--delay 1.0`) to avoid hammering
  an Onion Service.
- Strict same-host scope enforcement: links to other domains, other
  `.onion` hosts, `javascript:`, and `mailto:` are rejected before ever
  being fetched.
