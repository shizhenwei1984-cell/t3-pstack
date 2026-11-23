"""Exercise the shared filesystem boundary on real host files."""
from contextlib import nullcontext
import ctypes as C
import importlib.util
import os
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from evidence_test_support import WINDOWS, link_directory, writable_tree

SCRIPT = Path(__file__).resolve().parents[1] / 'plugins/pstack/skills/poteto-mode/scripts/evidence_fs.py'


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ.get('PSTACK_EVIDENCE_TEST_ROOT',
                                     Path.home() / '.local/state/pstack-evidence-tests')).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        fixture = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name).resolve()
        self.addCleanup(writable_tree, self.root)

    def load_filesystem(self):
        spec = importlib.util.spec_from_file_location('evidence_fs', SCRIPT)
        fs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fs)
        return fs

    def test_darwin_absent_excluded_root_matches_unicode_equivalence(self):
        fs = self.load_filesystem()
        root = self.root / 'Caf\u00e9'
        equivalent = self.root / 'Cafe\u0301' / 'state'
        alternate_case = self.root / 'CAFE\u0301' / 'state'
        for case_sensitive in (True, False):
            with self.subTest(case_sensitive=case_sensitive), patch.object(
                    fs, 'DARWIN', True), patch.object(
                    fs, '_darwin_case_sensitive', return_value=case_sensitive):
                self.assertTrue(fs.contains_path(equivalent, root))
                self.assertEqual(not case_sensitive, fs.contains_path(alternate_case, root))
                self.assertFalse(fs.contains_path(self.root / 'Cafeteria' / 'state', root))

    def test_exclusive_publish_preserves_destination_and_cleans_staged_file(self):
        fs = self.load_filesystem()
        final = self.root / 'résumé with spaces'
        fs.owned_directory(self.root)
        with fs.stage(self.root, b'first') as staged:
            fs.publish_new(staged, final)
        original = fs.identity(final)
        with self.assertRaises(FileExistsError), fs.stage(self.root, b'second', mode=0o444) as staged:
            fs.publish_new(staged, final)
        self.assertEqual(list(self.root.iterdir()), [final])
        self.assertEqual(final.read_bytes(), b'first')
        self.assertEqual(fs.identity(final), original)


    def test_atomic_replacement_keeps_delete_sharing_reader_on_original_bytes(self):
        fs = self.load_filesystem()
        final = self.root / 'reviewed.md'
        with fs.stage(self.root, b'prior', mode=0o444) as staged:
            fs.publish_new(staged, final)
        if WINDOWS:
            import msvcrt
            handle = fs._open_win(final, fs._READ)
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        else:
            fd = os.open(final, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as reader, fs.stage(self.root, b'reviewed', mode=0o444) as staged:
            fs.replace_existing(staged, final)
            self.assertEqual(reader.read(), b'prior')
        self.assertEqual(final.read_bytes(), b'reviewed')
        self.assertFalse(final.stat().st_mode & stat.S_IWUSR)

    def test_windows_delete_sharing_denial_prevents_posix_rename(self):
        fs = self.load_filesystem()
        target = self.root / 'reviewed.md'
        target.write_bytes(b'prior')

        class RenameInfo(C.Structure):
            _fields_ = [('flags', C.c_uint32), ('length', C.c_uint32), ('name', C.c_wchar * 1)]

        def open_handle(path, access, **_options):
            if path == target and access & fs._DELETE:
                raise PermissionError('target reader denied delete sharing')
            return nullcontext(42)

        api = SimpleNamespace(RenameInfo=RenameInfo, set=lambda *_: True)
        with fs.stage(self.root, b'new') as staged:
            with patch.object(fs, 'WINDOWS', True), patch.object(fs, '_win', return_value=api), patch.object(
                    fs, '_write_parent', return_value=nullcontext(43)), patch.object(
                    fs, '_final_path', side_effect=lambda _, path: path), patch.object(fs, '_volume', return_value=1), patch.object(
                    fs, '_win_identity', return_value=(1, b'file-id')), patch.object(fs, '_win_info'), patch.object(
                    fs, '_win_path', side_effect=str), patch.object(fs, '_handle', side_effect=open_handle):
                with self.assertRaises(PermissionError):
                    fs.replace_existing(staged, target)
        self.assertEqual(b'prior', target.read_bytes())
        self.assertEqual([target], list(self.root.iterdir()))

    def test_rejects_alias_into_owned_root_and_invalid_windows_names(self):
        fs = self.load_filesystem()
        durable = self.root / 'owned'
        fs.ensure_directory(durable)
        fs.owned_directory(durable)
        original = durable / 'original.txt'
        original.write_bytes(b'content')
        alias = self.root / 'alias'
        link_directory(alias, durable)
        with self.assertRaises(OSError):
            fs.owned_directory(alias)
        with self.assertRaises(fs.UnsupportedFile):
            fs.read_regular(alias / original.name, anchor=self.root)
        if WINDOWS:
            for name in ('C:drive-relative', r'\\.\C:\device', r'\\?\GLOBALROOT\Device',
                         str(durable / 'a.txt:stream'), str(durable / 'AUX.txt'), str(durable / 'COM¹')):
                with self.subTest(path=name), self.assertRaises(ValueError):
                    fs.validate_path(name)

    @unittest.skipIf(WINDOWS, 'Darwin POSIX path observation fixture')
    def test_darwin_reads_a_case_variant_but_rejects_a_symlink_ancestor(self):
        import fcntl

        fs = self.load_filesystem()
        directory = self.root / 'Mixed Dir'
        directory.mkdir()
        file = directory / 'Actual.txt'
        file.write_bytes(b'content')
        alias = self.root / 'alias'
        alias.symlink_to(directory, target_is_directory=True)
        alternate = directory.parent / directory.name.upper() / 'ACTUAL.TXT'
        lstat, open_fd = Path.lstat, os.open

        def lookup(path):
            return {alternate: file, alternate.parent: directory}.get(path, path)

        def realpath(path):
            return lookup(path).resolve(strict=True)

        with patch.object(fs, 'DARWIN', True), patch.object(fs, '_darwin_realpath', realpath, create=True), patch.object(
                Path, 'lstat', lambda path, *args, **kwargs: lstat(lookup(path), *args, **kwargs)), patch.object(
                os, 'open', lambda path, *args, **kwargs: open_fd(lookup(path), *args, **kwargs)), patch.object(
                fcntl, 'fcntl', return_value=os.fsencode(file) + b'\0'):
            self.assertEqual(b'content', fs.read_regular(alternate, anchor=self.root)[0])
            self.assertEqual(file, fs.canonical_path(alternate))
            self.assertEqual(directory / 'absent', fs.canonical_path(alternate.parent / 'absent'))
            with self.assertRaises(fs.UnsupportedFile):
                fs.read_regular(alias / file.name, anchor=self.root)

    @unittest.skipUnless(WINDOWS, 'Windows directory security descriptor')
    def test_windows_created_directory_has_protected_dacl(self):
        from ctypes import wintypes as W

        fs = self.load_filesystem()
        directory = self.root / 'new root'
        fs.ensure_directory(directory)
        fs.owned_directory(directory)
        get_control = C.WinDLL('advapi32').GetSecurityDescriptorControl
        get_control.argtypes = [C.c_void_p, C.POINTER(W.WORD), C.POINTER(W.DWORD)]
        get_control.restype = W.BOOL
        owner, dacl, descriptor = C.c_void_p(), C.c_void_p(), C.c_void_p()
        with fs._handle(directory, 0x20000, flags=0x02000000) as handle:
            api = fs._win()
            self.assertEqual(0, api.get_security(handle, 1, 5, C.byref(owner), None,
                                                 C.byref(dacl), None, C.byref(descriptor)))
            try:
                control, revision = W.WORD(), W.DWORD()
                self.assertTrue(get_control(descriptor, C.byref(control), C.byref(revision)))
                self.assertEqual(0x1004, control.value & 0x1004)  # SE_DACL_PROTECTED | SE_DACL_PRESENT
                self.assertTrue(dacl.value)
                with fs._token_sid(1) as user:
                    self.assertTrue(api.equal_sid(owner, user))
            finally:
                api.free(descriptor)

    @unittest.skipUnless(WINDOWS, 'Windows directory security descriptor')
    def test_windows_directory_with_null_dacl_is_rejected(self):
        from ctypes import wintypes as W

        fs = self.load_filesystem()
        directory = self.root / 'null dacl'
        fs.ensure_directory(directory)
        set_security = C.WinDLL('advapi32').SetSecurityInfo
        set_security.argtypes = [W.HANDLE, C.c_int, W.DWORD, *([C.c_void_p] * 4)]
        set_security.restype = W.DWORD
        dacl, descriptor = C.c_void_p(), C.c_void_p()
        with fs._handle(directory, 0x60000, flags=0x02000000) as handle:  # READ_CONTROL | WRITE_DAC
            api = fs._win()
            self.assertEqual(0, api.get_security(handle, 1, 4, None, None, C.byref(dacl),
                                                 None, C.byref(descriptor)))
            try:
                self.assertEqual(0, set_security(handle, 1, 4, None, None, None, None))
                with self.assertRaises(PermissionError):
                    fs.owned_directory(directory)
            finally:
                restored = set_security(handle, 1, 0x80000004, None, None, dacl, None)
                api.free(descriptor)
                self.assertEqual(0, restored)
        fs.owned_directory(directory)

    @unittest.skipUnless(WINDOWS, 'Windows directory security descriptor')
    def test_windows_directory_owned_by_unrelated_sid_is_rejected(self):
        from ctypes import wintypes as W

        fs = self.load_filesystem()
        directory = self.root / 'alternate owner'
        fs.ensure_directory(directory)
        security = C.WinDLL('advapi32', use_last_error=True)
        make_sid = security.CreateWellKnownSid
        make_sid.argtypes = [C.c_int, C.c_void_p, C.c_void_p, C.POINTER(W.DWORD)]
        make_sid.restype = W.BOOL
        set_security = security.SetSecurityInfo
        set_security.argtypes = [W.HANDLE, C.c_int, W.DWORD, *([C.c_void_p] * 4)]
        set_security.restype = W.DWORD
        sid = C.create_string_buffer(68)  # SECURITY_MAX_SID_SIZE
        size = W.DWORD(len(sid))
        self.assertTrue(make_sid(23, None, sid, C.byref(size)))  # WinLocalServiceSid
        with fs._token_sid(1) as user, fs._handle(directory, 0x80000, flags=0x02000000) as handle:
            if fs._win().equal_sid(user, sid):
                self.skipTest('test runner itself uses the Local Service SID')
            status = set_security(handle, 1, 1, sid, None, None, None)
            if status in (5, 1307, 1314):  # ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER, ERROR_PRIVILEGE_NOT_HELD
                self.skipTest(f'token cannot assign the Local Service owner SID (WinError {status})')
            self.assertEqual(0, status)
            try:
                with self.assertRaises(PermissionError):
                    fs.owned_directory(directory)
            finally:
                self.assertEqual(0, set_security(handle, 1, 1, user, None, None, None))
        fs.owned_directory(directory)

    @unittest.skipUnless(WINDOWS, 'native Windows volume capabilities')
    def test_windows_unsupported_volume_refuses_create(self):
        parent = os.environ.get('PSTACK_EVIDENCE_UNSUPPORTED_VOLUME')
        if not parent:
            self.skipTest('set PSTACK_EVIDENCE_UNSUPPORTED_VOLUME to an empty fixture directory on a non-NTFS local volume')
        fs = self.load_filesystem()
        parent = Path(parent).resolve(strict=True)
        directory = parent / f'pstack-unsupported-volume-{uuid4().hex}'
        with self.assertRaises(fs.CapabilityError):
            fs.ensure_directory(directory, exist_ok=False)
            self.addCleanup(directory.rmdir)
        self.assertFalse(directory.exists())
