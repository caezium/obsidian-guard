#!/usr/bin/env python3
"""Build a small macOS app that runs Guard's checked launcher."""
import argparse
import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import tempfile


def apple_string(text):
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script', type=Path, default=Path(__file__).with_name('guard.py'))
    parser.add_argument('--destination', type=Path, default=Path.home() / 'Applications/Obsidian Checked.app')
    args = parser.parse_args()
    script, destination = args.script.expanduser().resolve(), args.destination.expanduser()
    if not script.is_file():
        parser.error('Guard script does not exist')
    if destination.exists():
        parser.error('Destination already exists; choose a new location')
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = shlex.join([sys.executable, str(script), 'open'])
    source = ('try\n  do shell script ' + apple_string(command) + '\n'
              'on error messageText\n'
              '  display dialog messageText with title "Obsidian Guard" '
              'buttons {"OK"} default button "OK" with icon caution\n'
              'end try\n')
    with tempfile.TemporaryDirectory(prefix='.guard-launcher-', dir=destination.parent) as folder:
        app = Path(folder) / destination.name
        subprocess.run(['/usr/bin/osacompile', '-o', str(app), '-'], input=source.encode(), check=True)
        info = app / 'Contents/Info.plist'
        value = plistlib.loads(info.read_bytes())
        value.update(CFBundleIdentifier='local.obsidian-guard.checked-launcher',
                     CFBundleName='Obsidian Checked', CFBundleDisplayName='Obsidian Checked')
        info.write_bytes(plistlib.dumps(value))
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(app)], check=True, capture_output=True)
        os.rename(app, destination)
    print(destination)


if __name__ == '__main__':
    main()
