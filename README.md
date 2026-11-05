# Obsidian Guard

Small macOS background checks and incremental Git backups for Obsidian vaults.
The vault can stay in iCloud Drive. The tool checks for cloud-only files and
suspicious changes before saving an append-only snapshot on a separate branch.
No Obsidian plugin, archive compression, or running editor is required.

```text
Obsidian Guard - Healthy
Vault is downloaded; backup is current

  Last check       2 minutes ago (01 Jan 2026, 12:00 UTC)
  Local snapshot   7 minutes ago (01 Jan 2026, 11:55 UTC)
  Remote verified  7 minutes ago (01 Jan 2026, 11:55 UTC)
  Files checked    1,234 (1.5 GB)
  Last scan        2 changed, 0 deleted
```

This example is synthetic. Real output uses your local time zone. Use
`obsidian-guard status --json` for scripts, or `--details` for the snapshot commit
and credential-exclusion paths. Status displays the last completed check; it
does not scan the vault again. An old result is clearly marked as overdue.

## How it works

- A launchd job can check every five minutes while the Mac is awake and logged in.
- Snapshots are normally at least fifteen minutes apart, after thirty seconds
  without recent edits. Changed files are hashed; a full checksum scan runs weekly.
- A private Git index and a dedicated backup branch leave the worktree, HEAD,
  normal staging area, and other local branches alone.
- One job runs at a time, with background priority, one Git packing thread and
  one LFS transfer. There are no full-vault archives or automatic Git pruning.
- Private GitHub uploads are verified by comparing the remote commit. Current
  LFS objects are also hashed and their remote availability checked periodically.

The tool never pulls, merges, restores files, force-pushes, or deletes old backups.
Snapshot commits use Git plumbing to avoid commit hooks that might edit files;
the repository's existing LFS pre-push hook is still used for uploads.

## Install and configure

Requires macOS, Python 3.10 or newer, Git, Git LFS, and the GitHub CLI (`gh`) for
GitHub privacy checks. This version expects an **existing Git worktree with at
least one commit** and Git LFS already configured, including its pre-push hook.
It does not initialize or migrate a vault repository for you.

From a checkout of this repository:

```sh
mkdir -p "$HOME/.local/bin" "$HOME/Library/Application Support/ObsidianGuard"
install -m 755 guard.py "$HOME/.local/bin/obsidian-guard"
cp -n config.example.json "$HOME/Library/Application Support/ObsidianGuard/config.json"
```

Add `~/.local/bin` to your shell's PATH if needed. Edit the copied configuration:

- `vault_root` is the existing Git worktree root. Everything beneath it, except
  `.git` directories/files, is scanned, including files excluded from backups.
- `vaults` lists vault directories relative to that root. Use `["."]` when the
  worktree root is itself a vault. Each vault must have a `.obsidian` directory.
- `git_dir` is the actual Git metadata directory. Find it with
  `git -C /path/to/worktree rev-parse --absolute-git-dir`. Keeping it outside iCloud
  avoids cloud eviction of the index, history, and LFS objects. Moving an existing
  Git directory requires a separate, careful migration.
- `state_dir` must be outside the vault and iCloud. It holds local filenames,
  checksums, the private index, logs, and status; do not publish it.
- `backup_branch` must be a dedicated branch, distinct from the branch you edit.
- `remote_url` and `github_repo` must identify your **private vault backup
  repository**, not this public source repository. Authenticate with `gh` and
  configure Git credentials first. Adjust the executable paths for your system.

Paths support `~`. The example starts with `push: false` so you can review local
operation before enabling uploads:

```sh
obsidian-guard check --deep
obsidian-guard run --now --local-only
obsidian-guard status --details
```

Inspect the backup branch and your `.gitignore`, then set `push` to `true` and run
`obsidian-guard run --now`. When `github_repo` is set, uploads stop if GitHub says
the repository is public. For other Git hosts, privacy is your responsibility;
the remote URL is still checked against configuration.

## Schedule checks

After a successful manual backup, create a launchd job with the following command.
It reads your configured state directory and writes only a local plist. It refuses
to overwrite an existing job file.

```sh
python3 - <<'PY'
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

home = Path.home()
program = home / ".local/bin/obsidian-guard"
config = home / "Library/Application Support/ObsidianGuard/config.json"
state = Path(json.loads(config.read_text())["state_dir"]).expanduser()
assert program.is_file(), "Install the program first"
state.mkdir(parents=True, exist_ok=True)
label = "local.obsidian-guard"
plist = home / "Library/LaunchAgents" / (label + ".plist")
plist.parent.mkdir(parents=True, exist_ok=True)
job = {
    "Label": label,
    "ProgramArguments": [shutil.which("python3"), str(program), "run", "--quiet"],
    "RunAtLoad": True,
    "StartInterval": 300,
    "ProcessType": "Background",
    "LowPriorityIO": True,
    "Nice": 10,
    "EnvironmentVariables": {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
    "StandardOutPath": str(state / "launchd.stdout.log"),
    "StandardErrorPath": str(state / "launchd.stderr.log"),
}
with plist.open("xb") as file:
    plistlib.dump(job, file)
subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)], check=True)
PY
```

Check `obsidian-guard status` after installation. To stop the scheduled job:

```sh
launchctl bootout "gui/$(id -u)/local.obsidian-guard"
```

To restart it, bootstrap `~/Library/LaunchAgents/local.obsidian-guard.plist` again.
macOS controls notification permissions and banners. Status and event logs remain
available even if notifications are disabled.

## When a backup pauses

The tool flags cloud-only or unreadable files, missing vaults, invalid text/JSON,
ten or more simultaneously deleted notes/settings, newly empty files, truncations
greater than 80%, unexpected checksum changes, low disk space, and upload failures.
An already completed snapshot can still upload while the live vault is being
edited. Network failures do not prevent new local history from being recorded.

```sh
obsidian-guard status
obsidian-guard check --deep
obsidian-guard run --now
```

Intentional deletions or empty files can trigger a warning. Review the named files
before using the exact `approve --fingerprint ...` command shown in the status.
Approval permits those structural changes; it does not bypass unreadable files,
invalid JSON, checksum mismatches, or upload failures. `check` creates no snapshot
and uploads nothing, although it updates local status and logs.

If a plugin constantly rewrites a generated heartbeat file, its relative path can
go in `quiet_exclude`. Such files remain checked and backed up; their timestamps
do not restart the editing quiet period. `exclude` instead omits matching files
from new snapshots. Both lists use Python `fnmatch` patterns.

## Coverage and limits

The existing repository's `.gitignore` rules apply to new files. Detected
credential-containing files and configured exclusions are left out of new
snapshots, while local files remain untouched. **Credential detection is a
heuristic, not a complete secret scanner.** It does not sanitize historical
commits, and Git history inherited by the backup branch may contain old secrets.
Keep the backup repository private and review its coverage yourself.

Checksums can detect content changes that lack a recorded timestamp/size change.
They cannot establish whether an ordinary edit was wanted, or prove that every
document or attachment is semantically intact. A live vault snapshot is not an
atomic filesystem snapshot. Confirm restoration periodically and keep an
independent backup for important data.

Checks do not keep files downloaded, prevent iCloud eviction, or control when
Obsidian opens. Jobs run only while this Mac is awake and logged in. History is
not pruned automatically, so local disk usage and remote Git/LFS quotas can grow.

## Recovery

Restore to a separate non-iCloud folder with enough free space. Substitute your
private backup URL and configured branch:

```sh
git clone --branch backup/local YOUR_PRIVATE_BACKUP_URL ~/RecoveredVault
git -C ~/RecoveredVault lfs pull
```

Inspect the restored notes and attachments before opening them as a vault or
copying selected files into the live vault. For an older version, select that
commit in the recovery clone and retrieve its LFS objects. Do not reset the live
iCloud worktree as a shortcut.

## Development

```sh
python3 -m unittest -v test_guard.py
```

Tests use disposable repositories and synthetic data, including a local Git LFS
upload and restore. They do not access a real vault or a GitHub account. Do not
attach your config, state directory, real vault screenshots, or unsanitized logs
to public issues; even hashes and file paths can reveal private information.
