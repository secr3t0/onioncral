#!/usr/bin/env python3
"""
onion_collector.py
===================

Forensic recursive crawler/downloader for authorized incident-response
evidence collection from a Tor Onion Service directory listing.

This tool is intended ONLY for authorized incident-response, evidence
preservation, and recovery work against infrastructure/data an
organization is authorized to collect (e.g. their own files published
by a threat actor on a leak site). It does not perform any exploitation,
credential theft, authentication bypass, or network-attribution evasion.
It simply routes ordinary HTTP GET requests through a local Tor SOCKS5
proxy and saves the raw bytes it is served, preserving remote path
structure, computing SHA-256 hashes for evidentiary integrity, and
maintaining persistent state so a large collection job can be resumed.

Author: (forensic tooling)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import queue
import re
import sqlite3
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, unquote

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------
# Constants / defaults
# --------------------------------------------------------------------------

DEFAULT_PROXY = "socks5h://127.0.0.1:9050"
DEFAULT_WORKERS = 2
DEFAULT_DELAY = 1.0
DEFAULT_RETRIES = 5
DEFAULT_TIMEOUT = 60
CHUNK_SIZE = 1024 * 1024  # 1 MB streaming chunks
USER_AGENT = "onion_collector/1.0 (+forensic-evidence-collection)"

STATUS_DISCOVERED = "DISCOVERED"
STATUS_DOWNLOADING = "DOWNLOADING"
STATUS_DOWNLOADED = "DOWNLOADED"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"

KIND_DIR = "dir"
KIND_FILE = "file"

# Windows/most filesystems reserved characters. Colon is included because
# exposed Windows paths in these leak sites frequently contain drive
# letters such as "D:" as a path segment.
_INVALID_CHARS_RE = re.compile(r'[<>:"|?*\x00-\x1f]')
_TRAILING_DOTSPACE_RE = re.compile(r"[ .]+$")
_MAX_SEGMENT_LEN = 150


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def setup_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("onion_collector")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(threadName)s %(message)s"
    )

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    return logger


# --------------------------------------------------------------------------
# URL helpers
# --------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Normalize a URL for de-duplication: strip fragment, collapse
    redundant slashes in the path (but not inside the netloc), keep
    percent-encoding as-is so we don't corrupt already-encoded paths."""
    parts = urlsplit(url)
    path = re.sub(r"/{2,}", "/", parts.path)
    normalized = urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))
    return normalized


def is_in_scope(url: str, allowed_host: str, allowed_schemes: Tuple[str, ...],
                 allowed_path_prefix: Optional[str] = None) -> bool:
    """Only allow links that stay on the target onion host, use an
    allowed scheme, and (optionally) fall under a specific starting
    subtree. Rejects javascript:, mailto:, external hosts, sibling
    directories outside the allowed subtree, etc."""
    try:
        parts = urlparse(url)
    except ValueError:
        return False

    if parts.scheme.lower() not in allowed_schemes:
        return False
    if parts.netloc.lower() != allowed_host.lower():
        return False

    if allowed_path_prefix:
        candidate = parts.path
        prefix = allowed_path_prefix
        # Exact match on the starting page itself, or a true subtree
        # match (boundary-checked so "…/MCDCSRVFS01X" can't slip past
        # a prefix of "…/MCDCSRVFS01").
        if candidate != prefix and not candidate.startswith(prefix.rstrip("/") + "/"):
            return False

    return True


def sanitize_segment(segment: str) -> str:
    """Sanitize a single path segment for the local filesystem while
    keeping it human-readable. The *original* remote path is always
    preserved separately in the database/manifest, so this only needs
    to be safe, not reversible."""
    seg = unquote(segment)
    seg = unicodedata.normalize("NFC", seg)
    seg = _INVALID_CHARS_RE.sub("_", seg)
    seg = _TRAILING_DOTSPACE_RE.sub("", seg)
    if seg in ("", ".", ".."):
        seg = "_"
    if len(seg) > _MAX_SEGMENT_LEN:
        digest = hashlib.sha1(seg.encode("utf-8", "surrogatepass")).hexdigest()[:8]
        seg = seg[:_MAX_SEGMENT_LEN - 9] + "_" + digest
    return seg


def remote_path_to_local(base_dir: Path, url: str) -> Path:
    """Map a remote URL's path to a local filesystem path, preserving
    directory structure and sanitizing only what's necessary."""
    parts = urlparse(url)
    segments = [s for s in parts.path.split("/") if s != ""]
    safe_segments = [sanitize_segment(s) for s in segments]
    if not safe_segments:
        safe_segments = ["_root_"]
    return base_dir.joinpath(*safe_segments)


def dedupe_local_path(local_path: Path, url: str) -> Path:
    """If a local path collides with a different remote URL, append a
    short deterministic hash suffix derived from the full URL so we
    never silently overwrite a different file."""
    if not local_path.exists():
        return local_path
    suffix = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    stem = local_path.stem
    ext = local_path.suffix
    return local_path.with_name(f"{stem}__{suffix}{ext}")


# --------------------------------------------------------------------------
# Tor session
# --------------------------------------------------------------------------

class TorSession:
    """Thin wrapper around a requests.Session configured to route all
    traffic through a local Tor SOCKS5(h) proxy. No header spoofing,
    no X-Forwarded-For manipulation, no attribution bypass of any kind
    -- this exists solely to reach a .onion address, which is only
    reachable via Tor in the first place.

    IMPORTANT: PySocks (the library `requests`/urllib3 use to speak
    SOCKS5 to Tor) does not always honor the `timeout=` value passed to
    `requests` once a Tor circuit stalls -- the underlying socket can
    block far longer than the configured timeout, occasionally
    indefinitely. With a small worker count, a couple of stuck sockets
    is enough to freeze an entire crawl (progress counters stop
    changing because nothing ever completes or fails). To make that
    impossible, every request is issued on a small internal thread
    pool and awaited with a *hard* wall-clock timeout independent of
    whatever `requests`/PySocks does internally. If that hard timeout
    fires, we stop waiting and treat it as a timeout error (which
    feeds into the normal retry/backoff logic) -- the now-orphaned
    background thread is abandoned rather than blocking the crawl.
    """

    def __init__(self, proxy: str, timeout: int, logger: logging.Logger,
                 hard_timeout_workers: int = 64):
        self.proxy = proxy
        self.timeout = timeout
        self.logger = logger
        self.session = requests.Session()
        self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers.update({"User-Agent": USER_AGENT})
        # A little slack on top of the requests-level timeout so normal
        # slow-but-working requests aren't punished by the watchdog.
        self._hard_timeout = timeout + 20

    def _run_with_watchdog(self, func, *args, **kwargs):
        """Run func(*args, **kwargs) on a throwaway daemon thread and
        wait at most self._hard_timeout seconds for it. Daemon threads
        (unlike concurrent.futures.ThreadPoolExecutor workers) never
        block interpreter shutdown, so even if the underlying call
        never returns, the process can still exit cleanly -- the
        orphaned thread is simply abandoned."""
        box: Dict[str, object] = {}

        def _target():
            try:
                box["result"] = func(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001
                box["exception"] = exc

        t = threading.Thread(target=_target, daemon=True, name="tor-io")
        t.start()
        t.join(self._hard_timeout)
        if t.is_alive():
            raise requests.exceptions.Timeout(
                "Hard watchdog timeout exceeded (proxy/socket appears stuck)"
            )
        if "exception" in box:
            raise box["exception"]
        return box["result"]

    def get(self, url: str, stream: bool = False) -> requests.Response:
        try:
            return self._run_with_watchdog(
                self.session.get, url, timeout=self.timeout, stream=stream
            )
        except requests.exceptions.Timeout:
            self.logger.warning(
                f"Hard watchdog timeout ({self._hard_timeout}s) exceeded for {url}; "
                f"the underlying socket appears stuck (this can happen when a Tor "
                f"circuit stalls). Abandoning this attempt and retrying."
            )
            raise

    def iter_content_with_watchdog(self, resp: requests.Response, chunk_size: int):
        """Wrap resp.iter_content() so each individual chunk read is
        subject to the same hard wall-clock watchdog as the initial
        request. Without this, a stall mid-download (after headers are
        already received) could still block a worker forever even
        though the connect/first-byte phase is protected."""
        iterator = resp.iter_content(chunk_size=chunk_size)
        sentinel = object()
        while True:
            try:
                chunk = self._run_with_watchdog(next, iterator, sentinel)
            except requests.exceptions.Timeout:
                self.logger.warning(
                    f"Hard watchdog timeout ({self._hard_timeout}s) exceeded mid-download; "
                    f"the underlying socket appears stuck. Abandoning this attempt."
                )
                raise
            if chunk is sentinel:
                return
            yield chunk

    def test_connection(self, url: str) -> bool:
        """Verify the target onion URL is reachable through the
        configured Tor proxy."""
        self.logger.info(f"Testing Tor connectivity to {url} via {self.proxy} ...")
        try:
            resp = self.get(url, stream=False)
            self.logger.info(f"Tor test OK - HTTP {resp.status_code}, "
                              f"{len(resp.content)} bytes received.")
            return True
        except requests.exceptions.ProxyError as exc:
            self.logger.error(f"Tor proxy error: {exc}")
            self.logger.error(
                "Could not reach the SOCKS5 proxy. Is Tor running and "
                "listening on the configured address/port?"
            )
            return False
        except requests.exceptions.ConnectTimeout:
            self.logger.error("Connection to the onion service timed out.")
            return False
        except requests.exceptions.RequestException as exc:
            self.logger.error(f"Tor test failed: {exc}")
            return False


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

class Database:
    """Persistent crawl/download state in SQLite. A single connection
    guarded by a re-entrant lock is used; this keeps write ordering
    simple and correct for the modest (default 2, configurable)
    worker-thread concurrency this tool targets."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS items (
        url TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        parent_url TEXT,
        local_path TEXT,
        status TEXT NOT NULL,
        http_status INTEGER,
        remote_size INTEGER,
        downloaded_size INTEGER,
        sha256 TEXT,
        first_discovered TEXT,
        download_time TEXT,
        error TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_items_status ON items(status);
    CREATE INDEX IF NOT EXISTS idx_items_kind ON items(kind);
    """

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.executescript(self.SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def upsert_discovered(self, url: str, kind: str, parent_url: Optional[str]) -> bool:
        """Insert a new item as DISCOVERED if it doesn't already exist.
        Returns True if it was newly inserted (i.e. should be enqueued)."""
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.execute("SELECT 1 FROM items WHERE url = ?", (url,))
            if cur.fetchone():
                return False
            self.conn.execute(
                "INSERT INTO items (url, kind, parent_url, status, first_discovered, retry_count) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                (url, kind, parent_url, STATUS_DISCOVERED, now),
            )
            self.conn.commit()
            return True

    def get_item(self, url: str) -> Optional[sqlite3.Row]:
        with self.lock:
            cur = self.conn.execute("SELECT * FROM items WHERE url = ?", (url,))
            return cur.fetchone()

    def set_status(self, url: str, status: str, **fields) -> None:
        cols = ["status = ?"]
        vals: List = [status]
        for k, v in fields.items():
            cols.append(f"{k} = ?")
            vals.append(v)
        vals.append(url)
        with self.lock:
            self.conn.execute(
                f"UPDATE items SET {', '.join(cols)} WHERE url = ?", vals
            )
            self.conn.commit()

    def increment_retry(self, url: str) -> int:
        with self.lock:
            self.conn.execute(
                "UPDATE items SET retry_count = retry_count + 1 WHERE url = ?", (url,)
            )
            self.conn.commit()
            cur = self.conn.execute("SELECT retry_count FROM items WHERE url = ?", (url,))
            row = cur.fetchone()
            return row["retry_count"] if row else 0

    def reset_interrupted(self) -> int:
        """On restart, anything left mid-DOWNLOADING was interrupted;
        move it back to DISCOVERED so it gets retried."""
        with self.lock:
            cur = self.conn.execute(
                "UPDATE items SET status = ? WHERE status = ?",
                (STATUS_DISCOVERED, STATUS_DOWNLOADING),
            )
            self.conn.commit()
            return cur.rowcount

    def get_resumable(self) -> List[sqlite3.Row]:
        """Everything still pending: freshly discovered dirs/files, and
        previously failed downloads that haven't exhausted retries."""
        with self.lock:
            cur = self.conn.execute(
                "SELECT * FROM items WHERE status IN (?, ?) ORDER BY first_discovered",
                (STATUS_DISCOVERED, STATUS_FAILED),
            )
            return cur.fetchall()

    def stats(self) -> Dict[str, int]:
        with self.lock:
            cur = self.conn.execute(
                "SELECT kind, status, COUNT(*) AS c, "
                "COALESCE(SUM(downloaded_size), 0) AS bytes_sum "
                "FROM items GROUP BY kind, status"
            )
            rows = cur.fetchall()
        stats = {
            "dirs_total": 0,
            "files_total": 0,
            "files_downloaded": 0,
            "files_failed": 0,
            "files_skipped": 0,
            "files_pending": 0,
            "bytes_downloaded": 0,
        }
        for r in rows:
            if r["kind"] == KIND_DIR:
                stats["dirs_total"] += r["c"]
            elif r["kind"] == KIND_FILE:
                stats["files_total"] += r["c"]
                if r["status"] == STATUS_DOWNLOADED:
                    stats["files_downloaded"] += r["c"]
                    stats["bytes_downloaded"] += r["bytes_sum"]
                elif r["status"] == STATUS_FAILED:
                    stats["files_failed"] += r["c"]
                elif r["status"] == STATUS_SKIPPED:
                    stats["files_skipped"] += r["c"]
                else:
                    stats["files_pending"] += r["c"]
        return stats

    def all_file_rows_for_manifest(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT * FROM items WHERE kind = ? ORDER BY url", (KIND_FILE,)
            )
            return cur.fetchall()


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------

class EvidenceManifest:
    """Writes manifest.csv, the human/legal-review-friendly evidence
    ledger of every file the crawler encountered."""

    COLUMNS = [
        "URL", "LocalPath", "RemoteSize", "DownloadedSize", "SHA256",
        "HTTPStatus", "DiscoveryTime", "DownloadTime", "Status", "Error",
    ]

    def __init__(self, db: Database, path: Path):
        self.db = db
        self.path = path

    def write(self) -> None:
        rows = self.db.all_file_rows_for_manifest()
        with open(self.path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.COLUMNS)
            for r in rows:
                writer.writerow([
                    r["url"],
                    r["local_path"] or "",
                    r["remote_size"] if r["remote_size"] is not None else "",
                    r["downloaded_size"] if r["downloaded_size"] is not None else "",
                    r["sha256"] or "",
                    r["http_status"] if r["http_status"] is not None else "",
                    r["first_discovered"] or "",
                    r["download_time"] or "",
                    r["status"],
                    r["error"] or "",
                ])


# --------------------------------------------------------------------------
# Downloader
# --------------------------------------------------------------------------

class FileDownloader:
    """Streaming, hashing, retrying downloader for individual files."""

    def __init__(self, session: TorSession, db: Database, logger: logging.Logger,
                 retries: int, dry_run: bool):
        self.session = session
        self.db = db
        self.logger = logger
        self.retries = retries
        self.dry_run = dry_run

    def _sha256_of(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()

    def already_collected(self, url: str, local_path: Path) -> bool:
        """If the file already exists on disk and its hash matches the
        recorded SHA-256, treat it as already collected (idempotent
        resume). If it exists but doesn't match (e.g. a partial/corrupt
        previous run), it will be re-downloaded."""
        row = self.db.get_item(url)
        if not row or not local_path.exists():
            return False
        if row["status"] != STATUS_DOWNLOADED or not row["sha256"]:
            return False
        try:
            actual = self._sha256_of(local_path)
        except OSError:
            return False
        if actual == row["sha256"]:
            return True
        self.logger.warning(
            f"Local file hash mismatch for {url} (expected {row['sha256']}, "
            f"got {actual}); will re-download."
        )
        return False

    def download(self, url: str, local_path: Path) -> None:
        if self.dry_run:
            self.logger.info(f"[DRY-RUN] File discovered: {url}")
            self.db.set_status(url, STATUS_DISCOVERED, local_path=str(local_path))
            return

        if self.already_collected(url, local_path):
            self.logger.info(f"Already collected (hash verified): {url}")
            return

        local_path.parent.mkdir(parents=True, exist_ok=True)
        final_path = dedupe_local_path(local_path, url) if local_path.exists() else local_path

        attempt = 0
        backoff = 2
        while attempt <= self.retries:
            attempt += 1
            self.db.set_status(url, STATUS_DOWNLOADING, local_path=str(final_path))
            self.logger.info(f"DOWNLOADING (attempt {attempt}/{self.retries + 1}): {url}")
            tmp_path = final_path.with_suffix(final_path.suffix + ".part")
            try:
                resp = self.session.get(url, stream=True)
                http_status = resp.status_code
                if http_status != 200:
                    raise requests.exceptions.HTTPError(
                        f"HTTP {http_status} for {url}"
                    )
                remote_size_hdr = resp.headers.get("Content-Length")
                remote_size = int(remote_size_hdr) if remote_size_hdr and remote_size_hdr.isdigit() else None

                h = hashlib.sha256()
                downloaded = 0
                with open(tmp_path, "wb") as f:
                    for chunk in self.session.iter_content_with_watchdog(resp, CHUNK_SIZE):
                        if not chunk:
                            continue
                        f.write(chunk)
                        h.update(chunk)
                        downloaded += len(chunk)

                tmp_path.replace(final_path)
                digest = h.hexdigest()
                now = datetime.now(timezone.utc).isoformat()
                self.db.set_status(
                    url, STATUS_DOWNLOADED,
                    local_path=str(final_path),
                    http_status=http_status,
                    remote_size=remote_size,
                    downloaded_size=downloaded,
                    sha256=digest,
                    download_time=now,
                    error=None,
                )
                self.logger.info(
                    f"DOWNLOADED: {url} size={downloaded} sha256={digest}"
                )
                return
            except Exception as exc:  # noqa: BLE001 - want to retry on anything
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
                retry_count = self.db.increment_retry(url)
                self.logger.warning(f"Error downloading {url}: {exc} (retry {retry_count})")
                if attempt > self.retries:
                    self.db.set_status(
                        url, STATUS_FAILED,
                        error=str(exc),
                    )
                    self.logger.error(f"FAILED (giving up): {url}: {exc}")
                    return
                time.sleep(backoff)
                backoff *= 2


# --------------------------------------------------------------------------
# Crawler
# --------------------------------------------------------------------------

@dataclass
class CrawlLimits:
    max_files: Optional[int] = None
    max_size: Optional[int] = None


class OnionCrawler:
    """Recursively walks tr.dir / tr.file directory-listing pages on a
    single onion host, restricted strictly to that host."""

    def __init__(self, session: TorSession, db: Database, logger: logging.Logger,
                 allowed_host: str, evidence_dir: Path, delay: float,
                 downloader: FileDownloader, limits: CrawlLimits, dry_run: bool,
                 allowed_path_prefix: Optional[str] = None):
        self.session = session
        self.db = db
        self.logger = logger
        self.allowed_host = allowed_host
        self.evidence_dir = evidence_dir
        self.delay = delay
        self.downloader = downloader
        self.limits = limits
        self.dry_run = dry_run
        self.allowed_path_prefix = allowed_path_prefix

        self.allowed_schemes = ("http", "https")
        self.q: "queue.Queue[Tuple[str, str]]" = queue.Queue()
        self.stats_lock = threading.Lock()
        self.files_downloaded = 0
        self.bytes_downloaded = 0
        self.stop_new_files = False

    def seed(self, url: str) -> None:
        norm = normalize_url(url)
        if self.db.upsert_discovered(norm, KIND_DIR, None):
            self.logger.info(f"Seeded start URL: {norm}")
        self.q.put((norm, KIND_DIR))

    def enqueue_pending_from_db(self) -> None:
        """Load any items left over from a previous interrupted run."""
        for row in self.db.get_resumable():
            self.q.put((row["url"], row["kind"]))

    def _limits_exceeded(self) -> bool:
        with self.stats_lock:
            if self.limits.max_files is not None and self.files_downloaded >= self.limits.max_files:
                return True
            if self.limits.max_size is not None and self.bytes_downloaded >= self.limits.max_size:
                return True
            return False

    def _record_download(self, size: int) -> None:
        with self.stats_lock:
            self.files_downloaded += 1
            self.bytes_downloaded += size

    def _fetch_directory(self, url: str) -> None:
        self.logger.info(f"Directory discovered / entering: {url}")
        try:
            resp = self.session.get(url, stream=False)
        except requests.exceptions.RequestException as exc:
            self.logger.error(f"Failed to fetch directory {url}: {exc}")
            self.db.set_status(url, STATUS_FAILED, error=str(exc))
            return

        if resp.status_code != 200:
            self.logger.error(f"Directory {url} returned HTTP {resp.status_code}")
            self.db.set_status(url, STATUS_FAILED, http_status=resp.status_code,
                                error=f"HTTP {resp.status_code}")
            return

        soup = BeautifulSoup(resp.text, "html.parser")

        for row in soup.find_all("tr", class_="dir"):
            self._handle_row(row, url, KIND_DIR)
        for row in soup.find_all("tr", class_="file"):
            self._handle_row(row, url, KIND_FILE)

        self.db.set_status(url, STATUS_DOWNLOADED, http_status=200)

    def _handle_row(self, row, current_url: str, kind: str) -> None:
        a = row.find("a", href=True)
        if not a:
            return
        href = a["href"].strip()

        # Reject javascript:, mailto:, and similar pseudo-schemes outright,
        # before even attempting to resolve them as URLs.
        lowered = href.lower()
        if lowered.startswith("javascript:") or lowered.startswith("mailto:") or href in ("#", "../", ".."):
            return

        absolute = urljoin(current_url, href)
        norm = normalize_url(absolute)

        if not is_in_scope(norm, self.allowed_host, self.allowed_schemes,
                           self.allowed_path_prefix):
            self.logger.debug(f"Out-of-scope link ignored: {norm}")
            return

        # Loop / backlink protection: never revisit a URL we've already
        # seen, and never enqueue a directory as its own ancestor.
        is_new = self.db.upsert_discovered(norm, kind, current_url)
        if not is_new:
            return

        if kind == KIND_DIR:
            self.logger.info(f"Directory discovered: {norm}")
        else:
            self.logger.info(f"File discovered: {norm}")

        self.q.put((norm, kind))

    def _process_file(self, url: str) -> None:
        if self._limits_exceeded():
            self.db.set_status(url, STATUS_SKIPPED, error="limit reached")
            return
        local_path = remote_path_to_local(self.evidence_dir, url)
        self.downloader.download(url, local_path)
        row = self.db.get_item(url)
        if row and row["status"] == STATUS_DOWNLOADED and row["downloaded_size"]:
            self._record_download(row["downloaded_size"])

    def worker_loop(self, worker_id: int) -> None:
        while True:
            try:
                url, kind = self.q.get(timeout=2)
            except queue.Empty:
                return
            try:
                if kind == KIND_DIR:
                    if self.dry_run:
                        self._fetch_directory(url)
                    else:
                        self._fetch_directory(url)
                else:
                    self._process_file(url)
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"Unhandled error processing {url}: {exc}")
                self.db.set_status(url, STATUS_FAILED, error=str(exc))
            finally:
                self.q.task_done()
                time.sleep(self.delay)

    def run(self, workers: int) -> None:
        threads = []
        for i in range(workers):
            t = threading.Thread(target=self.worker_loop, args=(i,), daemon=True,
                                  name=f"worker-{i}")
            t.start()
            threads.append(t)
        # Wait until the queue is fully drained (including items
        # produced dynamically as directories are crawled).
        self.q.join()
        for t in threads:
            t.join(timeout=1)


# --------------------------------------------------------------------------
# Progress reporting
# --------------------------------------------------------------------------

def print_progress(db: Database) -> None:
    s = db.stats()
    total_gb = s["bytes_downloaded"] / (1024 ** 3)
    print(
        f"Discovered: {s['files_total']}  "
        f"Downloaded: {s['files_downloaded']}  "
        f"Failed: {s['files_failed']}  "
        f"Skipped: {s['files_skipped']}  "
        f"Pending: {s['files_pending']}  "
        f"Bytes: {total_gb:.2f} GB"
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_size(s: str) -> int:
    """Parse sizes like '10GB', '500MB', '1024' (bytes)."""
    s = s.strip().upper()
    m = re.match(r"^([\d.]+)\s*(B|KB|MB|GB|TB)?$", s)
    if not m:
        raise argparse.ArgumentTypeError(f"Invalid size: {s}")
    value = float(m.group(1))
    unit = m.group(2) or "B"
    mult = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}[unit]
    return int(value * mult)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="onion_collector.py",
        description="Forensic recursive downloader for an authorized "
                    "incident-response collection of files exposed on a "
                    "Tor Onion Service directory listing.",
    )
    p.add_argument("--url", help="Starting directory-listing URL on the onion service.")
    p.add_argument("--output", default="./evidence_case", help="Output/case directory.")
    p.add_argument("--proxy", default=DEFAULT_PROXY,
                    help=f"SOCKS5(h) proxy URL (default: {DEFAULT_PROXY}).")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help=f"Concurrent workers (default: {DEFAULT_WORKERS}). Keep conservative.")
    p.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                    help=f"Delay in seconds between requests per worker (default: {DEFAULT_DELAY}).")
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                    help=f"Max retries per file with exponential backoff (default: {DEFAULT_RETRIES}).")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT}).")
    p.add_argument("--resume", action="store_true",
                    help="Explicitly resume from existing crawler.db (this also happens "
                         "automatically whenever a prior database is found).")
    p.add_argument("--max-files", type=int, default=None,
                    help="Stop after downloading this many files.")
    p.add_argument("--max-size", type=parse_size, default=None,
                    help="Stop after downloading this much total data, e.g. 10GB.")
    p.add_argument("--dry-run", action="store_true",
                    help="Crawl and report what would be downloaded, without downloading.")
    p.add_argument("--test-tor", action="store_true",
                    help="Only test connectivity to --url through the configured Tor proxy, then exit.")
    p.add_argument("--single-file", action="store_true",
                    help="Treat --url as a direct link to ONE file and download only that "
                         "file, with no crawling/recursion at all.")
    p.add_argument("--restrict-to-start", action="store_true", default=True,
                    help="Only follow links that fall under the --url starting subtree "
                         "(default: on). Use --no-restrict-to-start to crawl the whole host.")
    p.add_argument("--no-restrict-to-start", dest="restrict_to_start", action="store_false",
                    help="Disable subtree restriction; follow any in-scope link on the same host.")
    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    db_path = output_dir / "crawler.db"
    manifest_path = output_dir / "manifest.csv"
    log_path = output_dir / "crawler.log"

    logger = setup_logging(log_path)
    logger.info("=" * 60)
    logger.info("onion_collector.py starting")
    logger.info(f"Target: {args.url}")
    logger.info(f"Tor proxy: {args.proxy}")
    logger.info(f"Output directory: {output_dir}")

    session = TorSession(args.proxy, args.timeout, logger)

    if args.test_tor:
        if not args.url:
            logger.error("--test-tor requires --url")
            sys.exit(2)
        ok = session.test_connection(args.url)
        sys.exit(0 if ok else 1)

    if not args.url:
        logger.error("--url is required (unless using --test-tor)")
        sys.exit(2)

    db = Database(db_path)
    reset_count = db.reset_interrupted()
    if reset_count:
        logger.info(f"Resumed {reset_count} interrupted item(s) from a previous run.")

    downloader = FileDownloader(session, db, logger, retries=args.retries, dry_run=args.dry_run)
    limits = CrawlLimits(max_files=args.max_files, max_size=args.max_size)

    start_url = normalize_url(args.url)
    allowed_host = urlparse(start_url).netloc

    start_time = time.time()

    if args.single_file:
        # No crawling at all: register and download exactly one URL.
        logger.info(f"--single-file mode: downloading only {start_url}")
        db.upsert_discovered(start_url, KIND_FILE, None)
        local_path = remote_path_to_local(evidence_dir, start_url)
        downloader.download(start_url, local_path)
    else:
        # Restrict crawling to the subtree the --url starts in, so a
        # listing for one company/host folder (e.g. .../MCDCSRVFS01/)
        # never wanders into sibling folders belonging to someone else.
        allowed_path_prefix = urlparse(start_url).path if args.restrict_to_start else None

        crawler = OnionCrawler(
            session=session, db=db, logger=logger, allowed_host=allowed_host,
            evidence_dir=evidence_dir, delay=args.delay, downloader=downloader,
            limits=limits, dry_run=args.dry_run,
            allowed_path_prefix=allowed_path_prefix,
        )

        crawler.seed(start_url)
        crawler.enqueue_pending_from_db()

        stop_progress = threading.Event()

        def progress_thread():
            while not stop_progress.wait(15):
                print_progress(db)

        pt = threading.Thread(target=progress_thread, daemon=True)
        pt.start()

        try:
            crawler.run(workers=max(1, args.workers))
        except KeyboardInterrupt:
            logger.warning("Interrupted by user. State has been saved; re-run to resume.")
        finally:
            stop_progress.set()

    duration = time.time() - start_time

    manifest = EvidenceManifest(db, manifest_path)
    manifest.write()

    s = db.stats()

    print("\n============================")
    print("COLLECTION COMPLETE" if not args.dry_run else "DRY RUN COMPLETE")
    print("============================")
    print(f"Target:            {args.url}")
    print(f"Directories:       {s['dirs_total']}")
    print(f"Files discovered:  {s['files_total']}")
    print(f"Files downloaded:  {s['files_downloaded']}")
    print(f"Files skipped:     {s['files_skipped']}")
    print(f"Files failed:      {s['files_failed']}")
    print(f"Total bytes:       {s['bytes_downloaded']}")
    print(f"Duration:          {duration:.1f}s")
    print(f"Evidence directory:{evidence_dir}")
    print(f"SQLite database:   {db_path}")
    print(f"Manifest:          {manifest_path}")
    print(f"Log:               {log_path}")

    logger.info("Run complete.")
    db.close()


if __name__ == "__main__":
    main()
