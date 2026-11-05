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

DEFAULT_CONFIG = Path.home() / "Library/Application Support/ObsidianGuard/config.json"
TEXT = {".md", ".json", ".canvas", ".base"}
SECRET_KEY = re.compile(r"apikey|accesstoken|refreshtoken|personalaccesstoken|password|clientsecret|authorization", re.I)
SECRET_VALUE = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-proj-[A-Za-z0-9_-]{40,})")


class Blocked(Exception):
    pass


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
    elif excluded:
        lines += ["", "Use --details to see excluded files, or --json for machine-readable output."]
    return "\n".join(lines)


class Guard:
    def __init__(self, config):
        self.c = config
        self.root = Path(config["vault_root"]).expanduser()
        self.gd = Path(config["git_dir"]).expanduser()
        self.home = Path(config["state_dir"]).expanduser()
        self.home.mkdir(parents=True, exist_ok=True)
        self.ref = "refs/heads/" + config["backup_branch"]
        self.env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
                        GIT_NO_LAZY_FETCH="1", GIT_LITERAL_PATHSPECS="1",
                        GOMAXPROCS="2",
                        PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

    def command(self, args, *, data=None, env=None, timeout=120, check=True, label=None):
        p = subprocess.Popen(args, cwd=self.root, env=env or self.env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = p.communicate(data, timeout=timeout)
        except BaseException:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, signal.SIGTERM)
            try:
                p.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
            raise
        if check and p.returncode:
            # Never write command output (which may contain user content/tokens)
            # into persistent logs or notification text.
            detail = "inspect manually"
            lower = err.lower()
            if b"quota" in lower or b"budget" in lower:
                detail = "remote storage/bandwidth quota needs attention"
            elif b"authentication" in lower or b"permission denied" in lower:
                detail = "authentication or access needs attention"
            elif b"could not resolve" in lower or b"timed out" in lower or b"network" in lower:
                detail = "network unavailable; will retry"
            raise Blocked(f"{label or Path(args[0]).name} failed (exit {p.returncode}); {detail}")
        return out, err, p.returncode

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
                if s.st_flags & getattr(stat, "SF_DATALESS", 0x40000000):
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

    def snapshot(self, files, baseline, changed, deleted, exclusions):
        active_ref = self.git("symbolic-ref", "-q", "HEAD", check=False).decode().strip()
        if active_ref == self.ref:
            raise Blocked("Backup branch is checked out; choose a dedicated branch before saving snapshots")
        prior = self.git("rev-parse", "--verify", self.ref, check=False).decode().strip()
        parent = prior or self.git("rev-parse", "HEAD").decode().strip()
        index = self.home / "backup.index"
        marker = load(self.home / "index-head.json", {})
        initial = not prior or not index.exists() or marker.get("commit") != parent
        # A failed/racing staging operation must never be reused as a clean index.
        with contextlib.suppress(FileNotFoundError):
            (self.home / "index-head.json").unlink()
        if initial:
            # A private index avoids touching the user's staged changes. Snapshot
            # commits intentionally use plumbing: user commit hooks may edit notes.
            with contextlib.suppress(FileNotFoundError):
                index.unlink()
            self.git("read-tree", parent, index=index)
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
        if self.scan() != files:
            raise Blocked("Files changed during the snapshot; retry after editing settles")
        tree = self.git("write-tree", index=index).decode().strip()
        previous_tree = self.git("rev-parse", parent + "^{tree}").decode().strip()
        if tree != previous_tree:
            message = "Vault backup " + dt.datetime.now().astimezone().isoformat(timespec="seconds") + "\n"
            commit = self.git("commit-tree", tree, "-p", parent, data=message.encode()).decode().strip()
        else:
            commit = parent
        self.git("update-ref", self.ref, commit, prior or "0" * 40)
        atomic_json(self.home / "index-head.json", {"commit": commit})
        return commit

    def push(self, commit):
        actual = self.git("remote", "get-url", self.c["remote"]).decode().strip()
        if actual != self.c["remote_url"]:
            raise Blocked("Backup remote URL changed; review configuration")
        if repo := self.c.get("github_repo"):
            out, _, _ = self.command([self.c.get("gh", "/opt/homebrew/bin/gh"), "api", "repos/" + repo, "--jq", ".private"], timeout=30)
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

    def report(self, status):
        before = load(self.home / "status.json", {})
        atomic_json(self.home / "status.json", status)
        if (before.get("state"), before.get("message")) != (status["state"], status["message"]):
            log = self.home / "events.jsonl"
            if log.exists() and log.stat().st_size > 1024 * 1024:
                os.replace(log, self.home / "events.previous.jsonl")
            with log.open("a") as f:
                f.write(json.dumps(status, ensure_ascii=False) + "\n")
        alert = status["state"] in {"blocked", "error"}
        recovered = status["state"] == "healthy" and before.get("state") in {"blocked", "error"}
        last = load(self.home / "notification.json", {})
        key = status["state"] + status["message"]
        if self.c.get("notifications", True) and (alert or recovered) and (last.get("key") != key or time.time() - last.get("time", 0) > 21600):
            script = 'on run argv\n display notification (item 1 of argv) with title "Obsidian Guard"\nend run'
            # The OS controls whether banners are displayed; status/logs remain
            # available even if notification permission is disabled.
            subprocess.run(["/usr/bin/osascript", "-e", script, status["message"][:240]], capture_output=True, timeout=10)
            atomic_json(self.home / "notification.json", {"key": key, "time": time.time()})

    def run(self, *, force=False, deep=False, check_only=False, accept=None):
        now = time.time()
        baseline = load(self.home / "baseline.json", {})
        status = {"checked_at": now, "last_snapshot_at": baseline.get("snapshot_at"),
                  "last_push_at": baseline.get("pushed_at"), "commit": baseline.get("commit")}
        try:
            push_error = None
            # An already completed snapshot is safe to upload while the live
            # vault is being edited. Offline uploads must not stop local history.
            if not check_only and self.c.get("push", True) and baseline.get("commit") and baseline.get("pushed_commit") != baseline["commit"]:
                try:
                    self.push(baseline["commit"])
                    baseline.update(pushed_commit=baseline["commit"], pushed_at=time.time())
                    atomic_json(self.home / "baseline.json", baseline)
                    status["last_push_at"] = baseline["pushed_at"]
                except (Blocked, OSError, subprocess.TimeoutExpired) as e:
                    push_error = e
            now = time.time()
            status["checked_at"] = now
            files = self.scan()
            deep = deep or now - baseline.get("deep_at", 0) > self.c.get("deep_interval", 604800)
            changed, deleted, hashes, excluded, anomalies, problems, fingerprint = self.evaluate(files, baseline, deep)
            status.update(files=len(files), bytes=sum(v[0] for v in files.values()), changed=len(changed),
                          deleted=len(deleted), credential_exclusions=excluded, fingerprint=fingerprint,
                          anomalies=anomalies[:50], problems=problems[:50])
            if problems:
                raise Blocked(problems[0])
            if anomalies and accept != fingerprint:
                raise Blocked(anomalies[0] + "; review status and approve this fingerprint if intentional")
            free = shutil.disk_usage(self.gd).free
            if free < self.c.get("minimum_free_bytes", 3 * 1024**3):
                raise Blocked("Less than 3 GiB disk space available; backup paused")
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
                commit = self.snapshot(files, baseline, changed, deleted, excluded)
                baseline.update(files=files, hashes=hashes, credential_exclusions=excluded, commit=commit, snapshot_at=now)
                if deep:
                    baseline["deep_at"] = now
                atomic_json(self.home / "baseline.json", baseline)
                status.update(commit=commit, last_snapshot_at=now)
                if not push_error and self.c.get("push", True) and (baseline.get("pushed_commit") != commit or now - baseline.get("pushed_at", 0) > 86400):
                    self.push(commit)
                    baseline.update(pushed_commit=commit, pushed_at=time.time())
                    atomic_json(self.home / "baseline.json", baseline)
                message = "Vault is downloaded; backup is current" if self.c.get("push", True) else "Local snapshot saved; upload not requested"
                status.update(last_push_at=baseline.get("pushed_at"), state="healthy", message=message)
            if push_error:
                raise Blocked(f"Local history retained; remote backup failed: {push_error}")
            self.report(status)
        except (Blocked, OSError, subprocess.TimeoutExpired, ValueError) as e:
            status.update(state="blocked" if isinstance(e, Blocked) else "error", message=str(e))
            self.report(status)
        return status


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run", "check", "status", "approve"])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--now", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of the human summary")
    parser.add_argument("--details", action="store_true", help="Include the snapshot commit and excluded file paths")
    parser.add_argument("--local-only", action="store_true", help="Save a local snapshot without uploading")
    parser.add_argument("--fingerprint")
    args = parser.parse_args()
    args.config = args.config.expanduser()
    if not args.config.is_file():
        parser.error("Configuration not found. Copy config.example.json to " + str(args.config) + " and edit it first.")
    guard = Guard(load(args.config))
    if args.local_only:
        guard.c["push"] = False
    if args.command == "status":
        status = load(guard.home / "status.json", {"state": "not_started"})
        status["stale"] = time.time() - status.get("checked_at", 0) > 900
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
                return 0
            with contextlib.suppress(OSError):
                os.nice(10)
            def timeout_handler(signum, frame):
                raise Blocked("Vault job exceeded 20 minutes; stopped and will retry")
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(1200)
            status = guard.run(force=args.now or args.command == "approve", deep=args.deep,
                               check_only=args.command == "check", accept=args.fingerprint)
            signal.alarm(0)
    if not args.quiet:
        print(json.dumps(status, ensure_ascii=False, indent=2) if args.json
              else format_status(status, details=args.details))
    return int(status.get("state") in {"blocked", "error"})


if __name__ == "__main__":
    sys.exit(main())
