import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from guard import Blocked, Guard, atomic_json, format_status, load


class StatusTest(unittest.TestCase):
    def test_human_summary_hides_machine_fields_and_private_paths(self):
        status = {'state': 'healthy', 'message': 'Vault is downloaded; backup is current',
                  'checked_at': 1000, 'last_snapshot_at': 940, 'last_push_at': 950,
                  'files': 1234, 'bytes': 1500000000, 'changed': 2, 'deleted': 0,
                  'commit': 'a' * 40, 'credential_exclusions': ['Notes/private-settings.json']}
        text = format_status(status, now=1060)
        self.assertIn('Obsidian Guard - Healthy', text)
        self.assertIn('1 minute ago', text)
        self.assertIn('1,234 (1.5 GB)', text)
        self.assertIn('2 changed, 0 deleted', text)
        self.assertNotIn('checked_at', text)
        self.assertNotIn(status['commit'], text)
        self.assertNotIn('private-settings.json', text)
        detailed = format_status(status, details=True, now=1060)
        self.assertIn(status['commit'], detailed)
        self.assertIn('Notes/private-settings.json', detailed)

    def test_stale_success_is_not_presented_as_healthy(self):
        text = format_status({'state': 'healthy', 'stale': True, 'checked_at': 1000,
                              'message': 'Previously passed'}, now=3000)
        self.assertIn('Needs attention - check is overdue', text.splitlines()[0])
        self.assertIn('Last result: Previously passed', text)
        self.assertIn('obsidian-guard check', text)

    def test_blocked_summary_explains_review_without_auto_approval(self):
        text = format_status({'state': 'blocked', 'message': 'Backup paused',
                              'anomalies': ['Newly empty file: Notes/example.md'],
                              'fingerprint': 'reviewed-change-id'}, now=1000)
        self.assertIn('Newly empty file: Notes/example.md', text)
        self.assertIn('If these changes are intentional', text)
        self.assertIn('approve --fingerprint reviewed-change-id', text)

    def test_missing_history_and_terminal_control_characters(self):
        text = format_status({'state': 'not_started'}, now=1000)
        self.assertIn('Not started', text)
        self.assertIn('Not yet', text)
        text = format_status({'state': 'blocked', 'message': 'Bad name: \x1b[2Jnote.md'}, now=1000)
        self.assertNotIn('\x1b', text)
        self.assertIn('\\x1b', text)


class BackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "vault with spaces"
        self.root.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.root / "Notes/.obsidian").mkdir(parents=True)
        (self.root / "Notes/.obsidian/app.json").write_text('{}')
        (self.root / "Notes/hello.md").write_text('Original note\n' * 50)
        self.git("add", ".")
        self.git("commit", "-m", "Initial")
        self.original_head = self.git("rev-parse", "HEAD").strip()
        self.config = {"vault_root": str(self.root), "git_dir": str(self.root / '.git'),
                       "vaults": ["Notes"], "state_dir": str(self.base / "state"),
                       "backup_branch": "backup/test", "remote": "origin", "remote_url": "",
                       "push": False, "notifications": False, "minimum_free_bytes": 0,
                       "quiet_seconds": 0, "snapshot_interval": 0, "deep_interval": 1000000,
                       "exclude": ["**/.DS_Store"]}
        self.guard = Guard(self.config)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True,
                              check=True).stdout.decode()

    def run_ok(self, **kwargs):
        status = self.guard.run(**kwargs)
        self.assertEqual(status["state"], "healthy", status)
        return status

    def test_snapshots_preserve_head_index_notes_and_old_versions(self):
        self.run_ok()
        (self.root / "Notes/staged.md").write_text("User staging")
        self.git("add", "Notes/staged.md")
        index = (self.root / '.git/index').read_bytes()
        p = self.root / "Notes/hello.md"
        p.write_text("Updated note\n" * 50)
        state = self.run_ok()
        self.assertEqual((self.root / '.git/index').read_bytes(), index)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.original_head)
        self.assertEqual(p.read_text(), "Updated note\n" * 50)
        self.assertEqual(self.git("show", state['commit'] + ':Notes/hello.md'), p.read_text())
        self.assertEqual(self.git("show", self.original_head + ':Notes/hello.md'), "Original note\n" * 50)

    def test_cloud_only_file_stops_before_git_writes(self):
        self.run_ok()
        before = (self.guard.home / 'baseline.json').read_bytes()
        original = Path.lstat
        target = self.root / 'Notes/hello.md'
        def cloud_stat(p, *args, **kwargs):
            s = original(p, *args, **kwargs)
            if p == target:
                return types.SimpleNamespace(st_mode=s.st_mode, st_size=s.st_size,
                    st_mtime_ns=s.st_mtime_ns, st_flags=0x40000000)
            return s
        with patch.object(Path, 'lstat', cloud_stat):
            status = self.guard.run()
        self.assertEqual(status['state'], 'blocked')
        self.assertIn('not downloaded', status['message'])
        self.assertEqual((self.guard.home / 'baseline.json').read_bytes(), before)

    def test_empty_note_requires_exact_review_fingerprint(self):
        self.run_ok()
        (self.root / 'Notes/hello.md').write_text('')
        status = self.guard.run()
        self.assertEqual(status['state'], 'blocked')
        self.assertEqual(self.guard.run(accept='wrong')['state'], 'blocked')
        self.run_ok(accept=status['fingerprint'])

    def test_mass_deletion_and_invalid_json_are_blocked(self):
        for i in range(12):
            (self.root / f'Notes/{i}.md').write_text('A note')
        self.run_ok()
        for i in range(12):
            (self.root / f'Notes/{i}.md').unlink()
        state = self.guard.run()
        self.assertEqual(state['state'], 'blocked')
        self.assertIn('deleted', state['message'])
        (self.root / 'Notes/.obsidian/app.json').write_text('{broken')
        state = self.guard.run(accept=state['fingerprint'])
        self.assertEqual(state['state'], 'blocked')
        self.assertIn('Invalid text/JSON', state['message'])

    def test_credentials_are_excluded_without_modifying_source(self):
        p = self.root / 'Notes/.obsidian/plugins/example/data.json'
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({'personalAccessToken': 'test-secret-value'}))
        state = self.run_ok()
        tree = self.git('ls-tree', '-r', '--name-only', state['commit'])
        self.assertNotIn('plugins/example/data.json', tree)
        self.assertIn('test-secret-value', p.read_text())

    def test_single_vault_root_also_excludes_plugin_credentials(self):
        self.config['vaults'] = ['.']
        p = self.root / '.obsidian/plugins/example/data.json'
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps({'personalAccessToken': 'test-secret-value'}))
        status = self.run_ok()
        self.assertNotIn('.obsidian/plugins/example/data.json',
                         self.git('ls-tree', '-r', '--name-only', status['commit']))

    def test_backup_cannot_advance_checked_out_branch(self):
        self.guard.ref = 'refs/heads/main'
        (self.root / 'Notes/new.md').write_text('Uncommitted note')
        status = self.guard.run()
        self.assertEqual(status['state'], 'blocked')
        self.assertIn('checked out', status['message'])
        self.assertEqual(self.git('rev-parse', 'HEAD').strip(), self.original_head)

    def test_checksum_change_with_preserved_metadata_is_blocked(self):
        self.run_ok()
        p = self.root / 'Notes/hello.md'; s = p.stat()
        p.write_bytes(b'X' + p.read_bytes()[1:])
        os.utime(p, ns=(s.st_atime_ns, s.st_mtime_ns))
        state = self.guard.run(deep=True)
        self.assertEqual(state['state'], 'blocked')
        self.assertIn('Checksum changed', state['message'])

    def test_racing_snapshot_does_not_leak_stale_staging(self):
        self.run_ok()
        p = self.root / 'Notes/transient.md'; p.write_text('temporary')
        original = self.guard.scan
        calls = 0
        def race():
            nonlocal calls
            calls += 1
            if calls == 2:
                p.unlink()
            return original()
        with patch.object(self.guard, 'scan', race):
            state = self.guard.run()
        self.assertEqual(state['state'], 'blocked')
        state = self.run_ok()
        self.assertNotIn('transient.md', self.git('ls-tree', '-r', '--name-only', state['commit']))

    def test_failed_push_is_retried_and_never_reported_healthy(self):
        self.config.update(push=True, snapshot_interval=900)
        with patch.object(self.guard, 'push', side_effect=Blocked('offline')) as push:
            self.assertEqual(self.guard.run()['state'], 'blocked')
            (self.root / 'Notes/offline.md').write_text('Saved while offline')
            status = self.guard.run()
            self.assertEqual(status['state'], 'blocked')
            self.assertEqual(self.git('show', status['commit'] + ':Notes/offline.md'), 'Saved while offline')
            self.assertEqual(push.call_count, 2)

    def test_large_file_without_lfs_is_blocked(self):
        with (self.root / 'Notes/huge.bin').open('wb') as f:
            f.truncate(101 * 1024**2)
        status = self.guard.run()
        self.assertEqual(status['state'], 'blocked')
        self.assertIn('LFS rule', status['message'])

    def test_check_never_uploads_pending_snapshot_or_changes_history(self):
        self.run_ok()
        baseline = (self.guard.home / 'baseline.json').read_bytes()
        self.config['push'] = True
        with patch.object(self.guard, 'push') as push, patch.object(self.guard, 'snapshot') as snapshot:
            self.assertEqual(self.guard.run(check_only=True)['state'], 'checked')
            push.assert_not_called()
            snapshot.assert_not_called()
        self.assertEqual((self.guard.home / 'baseline.json').read_bytes(), baseline)

    def test_plugin_heartbeat_does_not_postpone_note_backups(self):
        self.run_ok()
        self.config.update(quiet_seconds=60, quiet_exclude=['Notes/heartbeat.md'])
        (self.root / 'Notes/heartbeat.md').write_text('Generated sync status')
        status = self.run_ok()
        self.assertEqual(self.git('show', status['commit'] + ':Notes/heartbeat.md'), 'Generated sync status')
        (self.root / 'Notes/hello.md').write_text('Updated note\n' * 50)
        self.assertEqual(self.guard.run()['state'], 'waiting')

    def test_existing_ignore_rules_and_empty_canvas(self):
        (self.root / '.gitignore').write_text('ignored.bin\n')
        (self.root / 'ignored.bin').write_bytes(b'not for backup')
        (self.root / 'Notes/empty.canvas').write_text('{}')
        state = self.run_ok()
        self.assertNotIn('ignored.bin', self.git('ls-tree', '-r', '--name-only', state['commit']))

    def test_remote_restore_including_lfs_attachment(self):
        remote = self.base / 'remote.git'
        subprocess.run(['git', 'init', '--bare', str(remote)], capture_output=True, check=True)
        self.git('lfs', 'install', '--local')
        self.git('remote', 'add', 'origin', str(remote))
        self.config.update(push=True, remote_url=str(remote))
        (self.root / '.gitattributes').write_text('*.png filter=lfs diff=lfs merge=lfs -text\n')
        content = os.urandom(4096)
        (self.root / 'Notes/image.png').write_bytes(content)
        state = self.run_ok()
        restored = self.base / 'restored'
        subprocess.run(['git', 'clone', '-b', 'backup/test', str(remote), str(restored)],
                       check=True, capture_output=True)
        self.assertEqual((restored / 'Notes/image.png').read_bytes(), content)
        self.assertEqual((restored / 'Notes/hello.md').read_text(), 'Original note\n' * 50)

    def test_cli_defaults_to_human_output_and_preserves_json(self):
        expected = self.run_ok()
        config = self.base / 'config.json'
        atomic_json(config, self.config)
        command = [sys.executable, str(Path(__file__).with_name('guard.py')), 'status', '--config', str(config)]
        human = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        self.assertIn('Obsidian Guard - Healthy', human)
        self.assertNotIn('checked_at', human)
        raw = subprocess.run(command + ['--json'], check=True, capture_output=True, text=True).stdout
        self.assertEqual(json.loads(raw)['commit'], expected['commit'])
        self.assertEqual(json.loads(raw)['stale'], False)
        quiet = subprocess.run(command + ['--quiet'], check=True, capture_output=True, text=True).stdout
        self.assertEqual(quiet, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
