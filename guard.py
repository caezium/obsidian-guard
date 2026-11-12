#!/usr/bin/env python3
"""Local iCloud-vault checks and append-only Git backup snapshots.

Only the external Git object store, backup ref, and this program's state are
written. The worktree, HEAD, normal index, and existing branches are untouched.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from urllib.parse import quote

DEFAULT_CONFIG = Path.home() / "Library/Application Support/ObsidianGuard/config.json"
TEXT = {".md", ".json", ".canvas", ".base"}
SECRET_KEY = re.compile(r"apikey|accesstoken|refreshtoken|personalaccesstoken|password|clientsecret|authorization", re.I)
SECRET_VALUE = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-proj-[A-Za-z0-9_-]{40,})")


class Blocked(Exception):
    pass


def classify_error(stderr):
    text = stderr.lower()
    rules = [
        ("disk_full", (b"no space left", b"disk full", b"not enough space"), "Disk space exhausted; free space before retrying"),
        ("quota", (b"quota", b"budget", b"data packs", b"bandwidth limit"), "Remote storage or bandwidth quota needs attention"),
        ("authentication", (b"authentication", b"bad credentials", b"http 401", b"could not read username", b"gh auth login"), "GitHub credentials need attention; check gh auth status"),
        ("rate_limit", (b"rate limit", b"http 429"), "Remote rate limit reached; will retry later"),
        ("network", (b"could not resolve", b"timed out", b"timeout", b"network", b"connection", b"tls handshake", b"unexpected eof"), "Network request failed; local history is retained and upload will retry"),
        ("access", (b"permission denied", b"access denied", b"operation not permitted", b"http 403"), "Access was denied; check filesystem permissions or repository access"),
        ("index_lock", (b"index.lock", b"another git process"), "Git index could not be locked; check for another Git operation"),
        ("file_changed", (b"changed as we read", b"changed while", b"short read"), "A file changed while Git was reading it; retry after the edit settles"),
        ("file_missing", (b"no such file", b"did not match any files", b"unable to stat"), "A file disappeared during staging; retry after syncing settles"),
        ("remote_rejected", (b"non-fast-forward", b"fetch first", b"rejected"), "The remote rejected the backup; review the remote branch without force-pushing"),
    ]
    for category, patterns, message in rules:
        if any(pattern in text for pattern in patterns):
            return category, message
    return "unknown", "Unclassified command failure; see --details for the operation and error fingerprint"


def load(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
        json.dump(value, f, ensure_ascii=False, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    os.replace(f.name, path)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def secret_fields(value):
    if isinstance(value, dict):
        return any((SECRET_KEY.search(re.sub(r"[^a-z]", "", k.lower())) and isinstance(v, str) and v.strip())
                   or secret_fields(v) for k, v in value.items())
    if isinstance(value, list):
        return any(secret_fields(v) for v in value)
    return False


def terminal_text(value):
    """Keep filenames and messages from injecting terminal control sequences."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(value))


def human_size(value):
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1000 or unit == "TB":
            return f"{size:,.0f} B" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1000


def human_time(timestamp, now):
    if timestamp is None:
        return "Not yet"
    elapsed = now - timestamp
    if elapsed < -60:
        relative = "In the future; check the system clock"
    elif elapsed < 60:
        relative = "Just now"
    else:
        amount, unit = (int(elapsed // 86400), "day") if elapsed >= 86400 else (
            (int(elapsed // 3600), "hour") if elapsed >= 3600 else (int(elapsed // 60), "minute"))
        relative = f"{amount} {unit}{'' if amount == 1 else 's'} ago"
    local = dt.datetime.fromtimestamp(timestamp).astimezone()
    return f"{relative} ({local:%d %b %Y, %H:%M %Z})"


def format_status(status, *, details=False, now=None):
    if status.get("operation") == "open":
        return "Obsidian Guard - checked launcher\n" + terminal_text(status["message"])
    if status.get("state") == "maintenance":
        cleanup = status["cleanup"]
        return ("Obsidian Guard - LFS temporary-file cleanup\n"
                f"Removed {cleanup['removed_files']} verified redundant files ({human_size(cleanup['removed_bytes'])}).\n"
                f"Retained {cleanup['retained_files']} files ({human_size(cleanup['retained_bytes'])}); {cleanup['state']}.\n"
                "Permanent LFS objects and Git history were not pruned.")
    now = time.time() if now is None else now
    state = status.get("state", "not_started")
    labels = {"healthy": "Healthy", "waiting": "Waiting",
              "blocked": "Backup paused", "error": "Check failed", "checked": "Check passed",
              "not_started": "Not started", "busy": "Already running"}
    stale = status.get("stale", False) and state != "not_started"
    title = "Needs attention - check is overdue" if stale else labels.get(state, state)
    lines = ["Obsidian Guard - " + terminal_text(title)]
    if stale:
        lines += ["No completed check in the last 15 minutes. The Mac may have been asleep.",
                  "Run obsidian-guard check to check the vault now."]
    message = status.get("message", "No check has run yet. Run obsidian-guard check to get started.")
    lines += textwrap.wrap(("Last result: " if stale else "") + terminal_text(message), width=88)
    lines.append("")
    rows = [("Last check", human_time(status.get("checked_at"), now)),
            ("Local snapshot", human_time(status.get("last_snapshot_at"), now)),
            ("Remote verified", human_time(status.get("last_push_at"), now))]
    if "files" in status:
        rows.append(("Files checked", f"{status['files']:,}" + (
            f" ({human_size(status['bytes'])})" if "bytes" in status else "")))
    if "changed" in status:
        rows.append(("Last scan", f"{status['changed']:,} changed, {status.get('deleted', 0):,} deleted"))
    if "duration_seconds" in status:
        rows.append(("Last run", f"{status['duration_seconds']:.1f} seconds"))
    if status.get("deferred_files"):
        rows.append(("Deferred", f"{len(status['deferred_files'])} changing generated file(s); previous versions retained"))
    excluded = status.get("credential_exclusions", [])
    if excluded:
        rows.append(("Not backed up", f"{len(excluded):,} credential-containing file{'s' if len(excluded) != 1 else ''}"))
    lines += [f"  {label:<16} {value}" for label, value in rows]
    issues = list(dict.fromkeys(status.get("problems", []) + status.get("anomalies", [])))
    if issues:
        lines += ["", "Needs review:"]
        for issue in issues:
            lines += textwrap.wrap(terminal_text(issue), width=88, initial_indent="  - ", subsequent_indent="    ")
    if status.get("anomalies") and status.get("fingerprint"):
        lines += ["", "If these changes are intentional, review them before approving:",
                  "  obsidian-guard approve --fingerprint " + terminal_text(status["fingerprint"])]
    if details:
        if status.get("commit"):
            lines += ["", "Snapshot commit: " + terminal_text(status["commit"])]
        if excluded:
            lines += ["", "Credential-containing files excluded from new snapshots:"]
            lines += ["  - " + terminal_text(path) for path in excluded]
        for error in status.get("diagnostics", []):
            lines += ["", f"Operation: {terminal_text(error['operation'])}; reason: {error['category']}; "
                      f"error ID: {error.get('error_id', 'none')}"]
        notice = status.get("notification", {})
        if notice:
            lines += ["", "Last macOS notification request: " + terminal_text(notice.get("result", "unknown")),
                      "A successful request does not confirm that a banner was displayed or seen."]
    elif excluded:
        lines += ["", "Use --details to see excluded files, or --json for machine-readable output."]
    if status.get("notification", {}).get("result") == "failed":
        lines += ["", "macOS notification request failed; check --details and macOS notification settings."]
    cleanup = status.get("cleanup", {})
    if cleanup.get("retained_bytes", 0) > 1024**3:
        lines += ["", f"LFS temporary storage: {human_size(cleanup['retained_bytes'])} retained ({cleanup['state']})."]
    return "\n".join(lines)


class Guard:
    def __init__(self, config):
        self.c = config
        self.root = Path(config["vault_root"]).expanduser()
        self.gd = Path(config["git_dir"]).expanduser()
        self.home = Path(config["state_dir"]).expanduser()
        self.home.mkdir(parents=True, exist_ok=True)
        self.ref = "refs/heads/" + config["backup_branch"]
        self.diagnostics = []
        self.deferred_paths = []
        self.started = time.perf_counter()
        self.phases = {}
        self.env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
                        GIT_NO_LAZY_FETCH="1", GIT_LITERAL_PATHSPECS="1",
                        GOMAXPROCS="2",
                        GIT_LFS_PROGRESS=str(self.home / "lfs-progress.log"),
                        PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

    def command(self, args, *, data=None, env=None, timeout=120, check=True, label=None):
        started = time.perf_counter()
        p = subprocess.Popen(args, cwd=self.root, env=env or self.env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = p.communicate(data, timeout=timeout)
        except BaseException as exc:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, signal.SIGTERM)
            try:
                p.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
            if isinstance(exc, subprocess.TimeoutExpired):
                operation = label or Path(args[0]).name
                self.diagnostics.append({"operation": operation, "category": "timeout",
                                         "timeout_seconds": timeout, "duration_seconds": round(time.perf_counter() - started, 3)})
                raise Blocked(f"{operation} exceeded {timeout} seconds; its child processes were stopped and will retry") from None
            raise
        if check and p.returncode:
            # Never write command output (which may contain user content/tokens)
            # into persistent logs or notification text.
            category, detail = classify_error(err)
            operation = label or Path(args[0]).name
            error_id = hashlib.sha256(err).hexdigest()[:16]
            self.diagnostics.append({"operation": operation, "category": category, "exit_code": p.returncode,
                                     "error_id": error_id, "stderr_bytes": len(err),
                                     "duration_seconds": round(time.perf_counter() - started, 3)})
            raise Blocked(f"{operation} failed (exit {p.returncode}, {category}); {detail}")
        return out, err, p.returncode

    @contextlib.contextmanager
    def phase(self, name):
        started = time.perf_counter()
        try:
            yield
        finally:
            self.phases[name] = round(self.phases.get(name, 0) + time.perf_counter() - started, 3)

    def git(self, *args, data=None, index=None, check=True, timeout=120):
        env = dict(self.env)
        if index:
            env["GIT_INDEX_FILE"] = str(index)
        cmd = [self.c.get("git", "/usr/bin/git"), "--git-dir=" + str(self.gd),
               "--work-tree=" + str(self.root), "-c", "gc.auto=0", "-c", "maintenance.auto=false",
               "-c", "pack.threads=1", "-c", "pack.windowMemory=64m", "-c", "pack.deltaCacheSize=32m",
               "-c", "core.compression=1", "-c", "lfs.concurrenttransfers=1", *args]
        return self.command(cmd, data=data, env=env, check=check, timeout=timeout, label="git " + args[0])[0]

    def ignored(self, path):
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in self.c.get("exclude", []))

    def generated(self, path):
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in self.c.get("quiet_exclude", []))

    def scan(self):
        for name in self.c["vaults"]:
            if not (self.root / name / ".obsidian").is_dir():
                raise Blocked(f"Vault or settings directory missing: {name}")
        files, pending = {}, []
        def fail(error):
            raise Blocked(f"Cannot enumerate vault: {error.filename}")
        for directory, dirs, names in os.walk(self.root, onerror=fail, followlinks=False):
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in names:
                if name == ".git":
                    continue
                p = Path(directory) / name
                rel = str(p.relative_to(self.root))
                s = p.lstat()
                if not stat.S_ISREG(s.st_mode):
                    raise Blocked(f"Unexpected non-regular file: {rel}")
                files[rel] = [s.st_size, s.st_mtime_ns]
                if (s.st_flags & getattr(stat, "SF_DATALESS", 0x40000000)
                        or (name.startswith(".") and name.endswith(".icloud"))):
                    pending.append(rel)
        if pending:
            raise Blocked(f"{len(pending)} iCloud files are not downloaded; first: {pending[0]}")
        return files

    def evaluate(self, files, baseline, deep):
        old = baseline.get("files", {})
        hashes = dict(baseline.get("hashes", {}))
        excluded = set(baseline.get("credential_exclusions", []))
        changed = [p for p, v in files.items() if old.get(p) != v]
        deleted = sorted(set(old) - set(files))
        anomalies, problems = [], []
        critical = lambda p: Path(p).suffix in TEXT and "/.trash/" not in p and not self.ignored(p)
        removed_notes = [p for p in deleted if critical(p)]
        if len(removed_notes) >= self.c.get("mass_delete_limit", 10):
            anomalies.append(f"{len(removed_notes)} notes/settings deleted at once")
        for rel in sorted(files if deep else changed):
            p = self.root / rel
            meta = files[rel]
            actual = digest(p)
            if deep and old.get(rel) == meta and rel in hashes and actual != hashes[rel]:
                problems.append(f"Checksum changed without a recorded edit: {rel}")
            hashes[rel] = actual
            if critical(rel) and rel in old and old[rel][0] > 0:
                if meta[0] == 0:
                    anomalies.append(f"Newly empty file: {rel}")
                elif old[rel][0] > (100 if p.suffix == ".json" else 500) and meta[0] < old[rel][0] * 0.2:
                    anomalies.append(f"File shrank by more than 80%: {rel}")
            if p.suffix in TEXT and meta[0] <= 32 * 1024 * 1024:
                try:
                    text = p.read_text(encoding="utf-8-sig")
                    if "\0" in text:
                        raise ValueError("null bytes")
                    if re.search(r"^<<<<<<< .+\n", text, re.M) and re.search(r"^>>>>>>> .+$", text, re.M):
                        raise ValueError("unresolved merge markers")
                    if p.suffix in {".json", ".canvas"}:
                        parsed = json.loads(text)
                        if "/.obsidian/plugins/" in "/" + rel and p.name == "data.json" and secret_fields(parsed):
                            excluded.add(rel)
                    if SECRET_VALUE.search(text):
                        excluded.add(rel)
                except (UnicodeError, ValueError) as e:
                    problems.append(f"Invalid text/JSON: {rel} ({type(e).__name__})")
        for rel in deleted:
            hashes.pop(rel, None)
        token = hashlib.sha256(json.dumps([files, anomalies], sort_keys=True).encode()).hexdigest()[:20]
        return changed, deleted, hashes, sorted(excluded), anomalies, problems, token

    def vault_id(self, vault):
        target = (self.root / vault).resolve()
        registry = load(Path.home() / "Library/Application Support/obsidian/obsidian.json", {})
        for key, item in registry.get("vaults", {}).items():
            if item.get("path") and Path(item["path"]).resolve() == target:
                return key
        raise Blocked("This vault is not registered with Obsidian; register it after a successful check")

    def open_vault(self, *, vault=None, deep=False, launch=True):
        """Check before requesting a launch; never update backup state or history."""
        started = time.perf_counter()
        status = {"operation": "open", "checked_at": time.time()}
        self.diagnostics = []
        try:
            vault = vault if vault is not None else self.c["vaults"][0]
            if vault not in self.c["vaults"]:
                raise Blocked("Choose a vault listed in the Guard configuration")
            baseline = load(self.home / "baseline.json", {})
            if not baseline.get("files") or not baseline.get("commit"):
                raise Blocked("No trusted backup baseline exists yet; complete and review a backup first")
            files = self.scan()
            changed, deleted, _, _, anomalies, problems, _ = self.evaluate(files, baseline, deep)
            missing = [p for p in deleted if not self.ignored(p) and not self.generated(p)]
            if missing:
                raise Blocked(f"{len(missing)} file(s) missing since the last snapshot; first: {missing[0]}. "
                              "Let iCloud finish downloading, or let Guard back up intentional deletions before retrying")
            if problems or anomalies:
                raise Blocked((problems + anomalies)[0])
            after = self.scan()
            if any(files.get(p) != after.get(p) for p in set(files) | set(after)
                   if not self.ignored(p) and not self.generated(p)):
                raise Blocked("Files changed during the launch check; let edits or syncing settle and try again")
            if launch:
                uri = "obsidian://open?vault=" + quote(self.vault_id(vault), safe="")
                self.command(["/usr/bin/open", uri], timeout=15, label="Open Obsidian")
            status.update(state="opened" if launch else "ready", files=len(files), vault=vault,
                          message="Checks passed; Obsidian was asked to open the vault" if launch else
                                  "Launch checks passed; Obsidian was not opened")
        except (Blocked, OSError, ValueError, subprocess.TimeoutExpired) as exc:
            status.update(state="blocked", message="Obsidian was not opened. " + str(exc))
        status.update(completed_at=time.time(), duration_seconds=round(time.perf_counter() - started, 3),
                      diagnostics=self.diagnostics)
        atomic_json(self.home / "open-status.json", status)
        return status

    def snapshot(self, files, baseline, changed, deleted, exclusions):
        active_ref = self.git("symbolic-ref", "-q", "HEAD", check=False).decode().strip()
        if active_ref == self.ref:
            raise Blocked("Backup branch is checked out; choose a dedicated branch before saving snapshots")
        prior = self.git("rev-parse", "--verify", self.ref, check=False).decode().strip()
        parent = prior or self.git("rev-parse", "HEAD").decode().strip()
        index = self.home / "backup.index"
        marker = load(self.home / "index-head.json", {})
        # Keep the last committed index intact. Failed attempts only discard a
        # disposable copy, preserving stat-cache entries and incremental retries.
        with tempfile.TemporaryDirectory(prefix="snapshot-", dir=self.home) as folder:
            attempt = Path(folder) / "index"
            if index.exists() and marker.get("commit") == parent:
                shutil.copyfile(index, attempt)
            else:
                self.git("read-tree", parent, index=attempt)
            commit = self.stage_snapshot(attempt, parent, prior, files, baseline, changed, deleted, exclusions)
            os.replace(attempt, index)
            atomic_json(self.home / "index-head.json", {"commit": commit})
            return commit

    def stage_snapshot(self, index, parent, prior, files, baseline, changed, deleted, exclusions):
        if not prior or baseline.get("commit") != parent:
            paths = set(self.git("ls-files", "--cached", "--others", "--exclude-standard", "-z", index=index).decode().split("\0"))
        else:
            paths = set(changed + deleted)
        paths.discard("")
        blocked = {p for p in paths if self.ignored(p) or p in exclusions}
        if blocked:
            self.git("update-index", "--force-remove", "-z", "--stdin", index=index,
                     data=b"\0".join(os.fsencode(p) for p in sorted(blocked)) + b"\0")
        candidates = paths - blocked
        # Respect the existing .gitignore for newly appearing paths. Deleted paths
        # already in the backup index must still be recorded.
        tracked = set(self.git("ls-files", "-z", index=index).decode().split("\0"))
        untracked = candidates - tracked
        if untracked:
            ignored = self.git("check-ignore", "--no-index", "-z", "--stdin", index=index,
                               data=b"\0".join(os.fsencode(p) for p in sorted(untracked)) + b"\0", check=False)
            candidates -= set(ignored.decode().split("\0"))
        if candidates:
            large = [p for p in candidates if p in files and files[p][0] >= 100 * 1024**2]
            if large:
                attrs = self.git("check-attr", "filter", "-z", "--stdin", index=index,
                                 data=b"\0".join(os.fsencode(p) for p in large) + b"\0").decode().split("\0")
                for offset in range(0, len(attrs) - 1, 3):
                    path, _, value = attrs[offset:offset + 3]
                    if value != "lfs":
                        raise Blocked(f"Large file needs a Git LFS rule before backup: {path}")
                    if files[path][0] >= 2 * 1024**3:
                        raise Blocked(f"File exceeds the configured 2 GiB LFS safety limit: {path}")
            self.git("add", "-A", "--pathspec-from-file=-", "--pathspec-file-nul", index=index,
                     data=b"\0".join(os.fsencode(p) for p in sorted(candidates)) + b"\0", timeout=600)
        after = self.scan()
        raced = {p for p in set(files) | set(after) if files.get(p) != after.get(p)}
        blocking = [p for p in raced if not self.generated(p) and not self.ignored(p)]
        if blocking:
            raise Blocked(f"{len(blocking)} file(s) changed during the snapshot; incremental retry will preserve the previous backup")
        self.deferred_paths = sorted(p for p in raced if self.generated(p) and not self.ignored(p))
        if self.deferred_paths:
            # Keep an earlier complete version of generated state rather than a
            # possible partial write. New racing paths stay absent until stable.
            self.git("update-index", "--force-remove", "-z", "--stdin", index=index,
                     data=b"\0".join(os.fsencode(p) for p in self.deferred_paths) + b"\0")
            previous = self.git("ls-tree", "-r", "-z", parent, "--", *self.deferred_paths)
            if previous:
                self.git("update-index", "-z", "--index-info", index=index, data=previous)
        tree = self.git("write-tree", index=index).decode().strip()
        previous_tree = self.git("rev-parse", parent + "^{tree}").decode().strip()
        if tree != previous_tree:
            message = "Vault backup " + dt.datetime.now().astimezone().isoformat(timespec="seconds") + "\n"
            commit = self.git("commit-tree", tree, "-p", parent, data=message.encode()).decode().strip()
        else:
            commit = parent
        self.git("update-ref", self.ref, commit, prior or "0" * 40)
        return commit

    def push(self, commit):
        actual = self.git("remote", "get-url", self.c["remote"]).decode().strip()
        if actual != self.c["remote_url"]:
            raise Blocked("Backup remote URL changed; review configuration")
        if repo := self.c.get("github_repo"):
            out, _, _ = self.command([self.c.get("gh", "/opt/homebrew/bin/gh"), "api", "repos/" + repo, "--jq", ".private"], timeout=30, label="GitHub privacy check")
            if out.strip() != b"true":
                raise Blocked("GitHub backup repository is not private; upload stopped")
        verified = load(self.home / "remote-lfs.json", {})
        if time.time() - verified.get("verified_at", 0) > self.c.get("deep_interval", 604800):
            self.verify_lfs(commit)
        # Existing pre-push hook uploads LFS content. Failures prevent the ref push.
        self.git("push", "--porcelain", self.c["remote"], commit + ":" + self.ref, timeout=900)
        remote = self.git("ls-remote", self.c["remote"], self.ref, timeout=30).decode().split()
        if not remote or remote[0] != commit:
            raise Blocked("Could not verify the backup commit on the remote")

    def verify_lfs(self, commit):
        """Verify and ensure all current attachment objects exist remotely."""
        small = set()
        for row in self.git("ls-tree", "-r", "-l", "-z", commit).split(b"\0"):
            if row:
                mode, kind, oid, size = row.split(b"\t", 1)[0].split()
                if kind == b"blob" and int(size) <= 1024:
                    small.add(oid)
        raw = self.git("cat-file", "--batch", data=b"\n".join(sorted(small)) + b"\n")
        objects, pos = {}, 0
        for _ in small:
            end = raw.index(b"\n", pos)
            size = int(raw[pos:end].split()[-1])
            blob = raw[end + 1:end + 1 + size]
            pos = end + 2 + size
            if blob.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                oid = re.search(rb"^oid sha256:([0-9a-f]{64})$", blob, re.M)
                length = re.search(rb"^size ([0-9]+)$", blob, re.M)
                if oid and length:
                    objects[oid[1].decode()] = int(length[1])
        for oid, size in objects.items():
            path = self.gd / "lfs/objects" / oid[:2] / oid[2:4] / oid
            if not path.is_file() or path.stat().st_size != size or digest(path) != oid:
                raise Blocked(f"Local LFS backup object missing or damaged: {oid[:12]}")
        if objects:
            self.git("lfs", "push", "--object-id", self.c["remote"], "--stdin",
                     data=("\n".join(sorted(objects)) + "\n").encode(), timeout=900)
        atomic_json(self.home / "remote-lfs.json", {"verified_at": time.time(), "objects": len(objects), "commit": commit})

    def lfs_busy(self):
        """Fail closed if Git LFS is running or the temporary directory is open."""
        try:
            active = subprocess.run(["/usr/bin/pgrep", "-x", "git-lfs"], capture_output=True, timeout=5)
            if active.returncode != 1:
                return True
            opened = subprocess.run(["/usr/sbin/lsof", "-nP", "+D", str(self.gd / "lfs/tmp")],
                                    capture_output=True, timeout=10)
            return opened.returncode != 1 or bool(opened.stdout or opened.stderr)
        except (OSError, subprocess.TimeoutExpired):
            return True

    def cleanup_lfs_tmp(self, *, min_age=3600):
        """Remove only unused, aged, provably redundant LFS scratch data.

        A partial file qualifies only when all its bytes match the beginning of
        a complete local object whose SHA-256 matches its object ID. Unique,
        changing, open, recent, and symlinked files are retained.
        """
        root = self.gd / "lfs"
        scratch = root / "tmp"
        result = {"checked_at": time.time(), "state": "complete", "removed_files": 0,
                  "removed_bytes": 0, "retained_files": 0, "retained_bytes": 0, "verified_objects": 0,
                  "removed_sample": []}
        def finish():
            if scratch.is_dir() and not scratch.is_symlink():
                for path in scratch.iterdir():
                    with contextlib.suppress(FileNotFoundError):
                        info = path.lstat()
                        if stat.S_ISREG(info.st_mode):
                            result["retained_files"] += 1
                            result["retained_bytes"] += info.st_size
            atomic_json(self.home / "lfs-cleanup.json", result)
            return result
        if not scratch.exists():
            return finish()
        if scratch.is_symlink() or root.is_symlink():
            result["state"] = "unsupported symlinked storage"
            return finish()
        now = time.time()
        pending = []
        for path in scratch.iterdir():
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and now - max(info.st_mtime, info.st_ctime) >= min_age:
                pending.append((path, info))
        if not pending:
            return finish()
        if self.lfs_busy():
            result["state"] = "busy"
            return finish()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        objects = []
        for path in (root / "objects").glob("*/*/*"):
            if (re.fullmatch(r"[0-9a-f]{64}", path.name) and path.is_file() and not path.is_symlink()
                    and not path.parent.is_symlink() and not path.parent.parent.is_symlink()):
                objects.append((path, path.stat()))
        prefixes, verified = {}, {}
        for path, before in pending:
            with contextlib.suppress(FileNotFoundError):
                if identity(path.lstat()) != identity(before):
                    continue
                redundant = before.st_size == 0
                if not redundant:
                    length = min(512, before.st_size)
                    if length not in prefixes:
                        table = {}
                        for obj, info in objects:
                            if info.st_size >= length:
                                with obj.open("rb") as f:
                                    key = hashlib.sha256(f.read(length)).digest()
                                table.setdefault(key, []).append((obj, info))
                        prefixes[length] = table
                    with path.open("rb") as f:
                        key = hashlib.sha256(f.read(length)).digest()
                    for obj, info in prefixes[length].get(key, []):
                        if info.st_size < before.st_size or identity(obj.stat()) != identity(info):
                            continue
                        if obj not in verified:
                            verified[obj] = digest(obj) == obj.name and identity(obj.stat()) == identity(info)
                        if not verified[obj]:
                            continue
                        with path.open("rb") as partial, obj.open("rb") as full:
                            remaining = before.st_size
                            while remaining:
                                chunk = partial.read(min(1024 * 1024, remaining))
                                if not chunk or chunk != full.read(len(chunk)):
                                    break
                                remaining -= len(chunk)
                            redundant = remaining == 0 and identity(obj.stat()) == identity(info)
                        if redundant:
                            break
                if redundant and identity(path.lstat()) == identity(before):
                    if self.lfs_busy():
                        result["state"] = "busy"
                        break
                    if identity(path.lstat()) != identity(before):
                        continue
                    path.unlink()
                    result["removed_files"] += 1
                    result["removed_bytes"] += before.st_size
                    if len(result["removed_sample"]) < 50:
                        result["removed_sample"].append({"temporary_file": path.name, "bytes": before.st_size,
                                                         "verified_object": obj.name if before.st_size else None})
        result["verified_objects"] = sum(verified.values())
        return finish()

    def report(self, status):
        before = load(self.home / "status.json", {})
        status.update(completed_at=time.time(), duration_seconds=round(time.perf_counter() - self.started, 3),
                      phases=self.phases, diagnostics=self.diagnostics)
        alert = status["state"] in {"blocked", "error"}
        last = load(self.home / "notification.json", {})
        recovered = status["state"] == "healthy" and (
            before.get("state") in {"blocked", "error"} or last.get("event_state") in {"blocked", "error"})
        key = status["state"] + status["message"]
        interval = 21600 if last.get("result") == "accepted" else 300
        if self.c.get("notifications", True) and (alert or recovered) and (last.get("key") != key or time.time() - last.get("time", 0) >= interval):
            script = 'on run argv\n display notification (item 1 of argv) with title "Obsidian Guard"\nend run'
            notice = {"key": key, "time": time.time(), "event_state": status["state"],
                      "result": "failed", "delivery_confirmed": False}
            try:
                result = subprocess.run(["/usr/bin/osascript", "-e", script, status["message"][:240]], capture_output=True, timeout=10)
                notice.update(exit_code=result.returncode, result="accepted" if result.returncode == 0 else "failed")
            except (OSError, subprocess.TimeoutExpired) as exc:
                notice["error_type"] = type(exc).__name__
            # An accepted AppleScript request cannot prove a banner was shown.
            atomic_json(self.home / "notification.json", notice)
            last = notice
        if last:
            status["notification"] = last
        atomic_json(self.home / "status.json", status)
        records = [("runs", 10 * 1024 * 1024)]
        if (before.get("state"), before.get("message")) != (status["state"], status["message"]):
            records.append(("events", 1024 * 1024))
        for name, limit in records:
            log = self.home / (name + ".jsonl")
            if log.exists() and log.stat().st_size > limit:
                os.replace(log, self.home / (name + ".previous.jsonl"))
            with log.open("a") as f:
                f.write(json.dumps(status, ensure_ascii=False) + "\n")

    def run(self, *, force=False, deep=False, check_only=False, accept=None):
        self.started = time.perf_counter()
        self.diagnostics = []
        self.deferred_paths = []
        self.phases = {}
        now = time.time()
        progress = self.home / "lfs-progress.log"
        if progress.exists() and progress.stat().st_size > 1024 * 1024:
            os.replace(progress, self.home / "lfs-progress.previous.log")
        baseline = load(self.home / "baseline.json", {})
        status = {"started_at": now, "checked_at": now, "last_snapshot_at": baseline.get("snapshot_at"),
                  "last_push_at": baseline.get("pushed_at"), "commit": baseline.get("commit")}
        try:
            push_error = None
            # An already completed snapshot is safe to upload while the live
            # vault is being edited. Offline uploads must not stop local history.
            if not check_only and self.c.get("push", True) and baseline.get("commit") and baseline.get("pushed_commit") != baseline["commit"]:
                try:
                    with self.phase("upload"):
                        self.push(baseline["commit"])
                    baseline.update(pushed_commit=baseline["commit"], pushed_at=time.time())
                    atomic_json(self.home / "baseline.json", baseline)
                    status["last_push_at"] = baseline["pushed_at"]
                except (Blocked, OSError, subprocess.TimeoutExpired) as e:
                    push_error = e
            now = time.time()
            status["checked_at"] = now
            with self.phase("scan"):
                files = self.scan()
            deep = deep or now - baseline.get("deep_at", 0) > self.c.get("deep_interval", 604800)
            with self.phase("validation"):
                changed, deleted, hashes, excluded, anomalies, problems, fingerprint = self.evaluate(files, baseline, deep)
            status.update(files=len(files), bytes=sum(v[0] for v in files.values()), changed=len(changed),
                          deleted=len(deleted), credential_exclusions=excluded, fingerprint=fingerprint,
                          anomalies=anomalies[:50], problems=problems[:50])
            if problems:
                raise Blocked(problems[0])
            if anomalies and accept != fingerprint:
                raise Blocked(anomalies[0] + "; review status and approve this fingerprint if intentional")
            free = shutil.disk_usage(self.gd).free
            if not check_only and free < self.c.get("minimum_free_bytes", 3 * 1024**3):
                with self.phase("maintenance"):
                    status["cleanup"] = self.cleanup_lfs_tmp()
                free = shutil.disk_usage(self.gd).free
            if free < self.c.get("minimum_free_bytes", 3 * 1024**3):
                raise Blocked("Insufficient free disk space; backup paused. Review LFS cleanup status and free space before retrying")
            latest = max((files[p][1] / 1e9 for p in changed if not self.ignored(p)
                          and not any(fnmatch.fnmatchcase(p, pattern)
                                      for pattern in self.c.get("quiet_exclude", []))), default=0)
            if changed and now - latest < self.c.get("quiet_seconds", 30):
                if now - baseline.get("pushed_at", baseline.get("snapshot_at", now)) > 21600:
                    status.update(state="blocked", message="Backup overdue by more than six hours; file edits have not settled")
                else:
                    status.update(state="waiting", message="Waiting for file edits to settle")
            elif check_only:
                status.update(state="checked", message="Vault check passed; no snapshot or upload requested")
            elif (not force and now - baseline.get("snapshot_at", 0) < self.c.get("snapshot_interval", 900)
                  and not deep and (not self.c.get("push", True) or baseline.get("pushed_commit") == baseline.get("commit"))):
                status.update(state="healthy", message="Vault is downloaded; next snapshot not due yet")
            else:
                with self.phase("snapshot"):
                    commit = self.snapshot(files, baseline, changed, deleted, excluded)
                # A generated file that raced retained its parent's Git entry.
                # Keep the matching baseline too so a later run retries it.
                for path in self.deferred_paths:
                    if path in baseline.get("files", {}):
                        files[path] = baseline["files"][path]
                        if path in baseline.get("hashes", {}):
                            hashes[path] = baseline["hashes"][path]
                        else:
                            hashes.pop(path, None)
                    else:
                        files.pop(path, None)
                        hashes.pop(path, None)
                status["deferred_files"] = self.deferred_paths
                baseline.update(files=files, hashes=hashes, credential_exclusions=excluded, commit=commit, snapshot_at=now)
                if deep:
                    baseline["deep_at"] = now
                atomic_json(self.home / "baseline.json", baseline)
                status.update(commit=commit, last_snapshot_at=now)
                if not push_error and self.c.get("push", True) and (baseline.get("pushed_commit") != commit or now - baseline.get("pushed_at", 0) > 86400):
                    with self.phase("upload"):
                        self.push(commit)
                    baseline.update(pushed_commit=commit, pushed_at=time.time())
                    atomic_json(self.home / "baseline.json", baseline)
                message = "Vault is downloaded; backup is current" if self.c.get("push", True) else "Local snapshot saved; upload not requested"
                status.update(last_push_at=baseline.get("pushed_at"), state="healthy", message=message)
            if push_error:
                raise Blocked(f"Local history retained; remote backup failed: {push_error}")
            if not check_only:
                cleanup = load(self.home / "lfs-cleanup.json", {})
                if now - cleanup.get("checked_at", 0) >= 86400:
                    try:
                        with self.phase("maintenance"):
                            cleanup = self.cleanup_lfs_tmp()
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        cleanup = {"state": "failed", "error_type": type(exc).__name__}
                status["cleanup"] = cleanup
            self.report(status)
        except (Blocked, OSError, subprocess.TimeoutExpired, ValueError) as e:
            status.update(state="blocked" if isinstance(e, Blocked) else "error", message=str(e))
            self.report(status)
        return status


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "check", "status", "approve", "cleanup", "open"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--now", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of the human summary")
    parser.add_argument("--details", action="store_true", help="Include the snapshot commit and excluded file paths")
    parser.add_argument("--local-only", action="store_true", help="Save a local snapshot without uploading")
    parser.add_argument("--fingerprint")
    parser.add_argument("--vault", help="Configured vault to open; defaults to the first configured vault")
    parser.add_argument("--check-only", action="store_true", help="Validate the checked launcher without opening Obsidian")
    args = parser.parse_args()
    args.config = args.config.expanduser()
    if not args.config.is_file():
        parser.error("Configuration not found. Copy config.example.json to " + str(args.config) + " and edit it first.")
    guard = Guard(load(args.config))
    if args.local_only:
        guard.c["push"] = False
    if args.command == "status":
        status = load(guard.home / "status.json", {"state": "not_started"})
        status["stale"] = time.time() - status.get("completed_at", status.get("checked_at", 0)) > 900
    else:
        if args.command == "approve" and not args.fingerprint:
            parser.error("approve requires --fingerprint from a reviewed status")
        with (guard.home / "run.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if not args.quiet:
                    busy = {"state": "busy", "message": "Another vault check is already running"}
                    print(json.dumps(busy) if args.json else busy["message"])
                return 1 if args.command == "open" else 0
            with contextlib.suppress(OSError):
                os.nice(10)
            def timeout_handler(signum, frame):
                raise Blocked("Launch check exceeded one minute; try again after syncing settles" if args.command == "open"
                              else "Vault job exceeded 20 minutes; stopped and will retry")
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(60 if args.command == "open" else 1200)
            if args.command == "cleanup":
                status = {"state": "maintenance", "cleanup": guard.cleanup_lfs_tmp(min_age=60 if args.now else 3600)}
            elif args.command == "open":
                status = guard.open_vault(vault=args.vault, deep=args.deep, launch=not args.check_only)
            else:
                status = guard.run(force=args.now or args.command == "approve", deep=args.deep,
                                   check_only=args.command == "check", accept=args.fingerprint)
            signal.alarm(0)
    if not args.quiet:
        print(json.dumps(status, ensure_ascii=False, indent=2) if args.json
              else format_status(status, details=args.details))
    return int(status.get("state") in {"blocked", "error"})


if __name__ == "__main__":
    sys.exit(main())
