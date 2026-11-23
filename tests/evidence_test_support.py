"""Native filesystem fixtures for evidence tests."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


WINDOWS = sys.platform == 'win32'


def assert_darwin_identity(process, earliest_ns, latest_ns):
    boot = subprocess.check_output(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'],
                                   encoding='ascii').strip()
    assert process['boot_session_uuid'] == boot, process
    microseconds = process['start_usec']
    assert 0 <= microseconds < 1_000_000, process
    created_us = process['start_sec'] * 1_000_000 + microseconds
    assert earliest_ns // 1_000 <= created_us <= latest_ns // 1_000, process


def link_directory(alias, destination):
    if WINDOWS:
        # Directory junctions are available without the symlink privilege.
        command = os.environ['COMSPEC']
        subprocess.run([command, '/d', '/c', 'mklink', '/J', str(alias), str(destination)],
                       check=True, capture_output=True)
    else:
        alias.symlink_to(destination, target_is_directory=True)


def link_file(test, alias, destination):
    try:
        alias.symlink_to(destination)
    except OSError as exc:
        if not WINDOWS or exc.winerror != 1314:  # ERROR_PRIVILEGE_NOT_HELD
            raise
        test.skipTest('The Windows token cannot create file symlinks')


def writable_tree(path):
    if WINDOWS:
        def regular_entry(entry):
            return not entry.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT

        for root, directories, files in os.walk(path):
            parent = Path(root)
            directories[:] = [name for name in directories if regular_entry(parent / name)]
            for name in files:
                filename = parent / name
                if regular_entry(filename):
                    filename.chmod(stat.S_IWRITE)


def remove_tree(path):
    writable_tree(path)
    shutil.rmtree(path)


def expected_mode(posix):
    if WINDOWS:
        return 0o666 if posix & stat.S_IWUSR else 0o444
    return posix
