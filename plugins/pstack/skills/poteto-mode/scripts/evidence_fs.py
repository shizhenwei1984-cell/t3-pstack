"""Filesystem operations shared by the evidence commands."""

from contextlib import contextmanager
import ctypes as C
import errno
from functools import lru_cache
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import struct
import sys
import tempfile
import time
import unicodedata
from types import SimpleNamespace

WINDOWS = sys.platform == 'win32'
DARWIN = sys.platform == 'darwin'


class CapabilityError(OSError):
    """The host or volume does not provide a required filesystem operation."""


class UnsupportedFile(OSError):
    pass


class SourceChanged(OSError):
    pass


class SizeLimit(OSError):
    pass


class LockBusy(OSError):
    pass


def configure_stdio_utf8():
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='strict')


def validate_path(value):
    if not WINDOWS:
        return
    text = os.fspath(value).replace('/', '\\')
    if text.startswith(('\\\\?\\', '\\\\.\\')):
        raise ValueError('Device and extended path prefixes are reserved')
    path = PureWindowsPath(text)
    if not path.is_absolute() or not re.fullmatch('[A-Za-z]:', path.drive):
        raise ValueError('Expected an absolute path on a local Windows drive')
    for part in path.parts[1:]:
        if part in ('.', '..'):
            continue
        if (part.endswith((' ', '.')) or any(ch in part for ch in ':<>|?*"')
                or any(ord(ch) < 32 for ch in part)
                or re.fullmatch(r'CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³]',
                                part.partition('.')[0].rstrip(), re.I)):
            raise ValueError('Reserved Windows path component: ' + part)


def _win_path(path):
    validate_path(path)
    text = os.path.normpath(path)
    return '\\\\?\\' + text if len(text.encode('utf-16-le')) // 2 >= 248 else text


@lru_cache(maxsize=1)
def _win():
    from ctypes import wintypes as W

    class HandleInfo(C.Structure):
        _fields_ = [('attributes', W.DWORD), ('created', W.FILETIME),
                    ('accessed', W.FILETIME), ('written', W.FILETIME),
                    ('volume', W.DWORD), ('size_high', W.DWORD), ('size_low', W.DWORD),
                    ('links', W.DWORD), ('index_high', W.DWORD), ('index_low', W.DWORD)]

    class FileId(C.Structure):
        _fields_ = [('volume', C.c_uint64), ('id', C.c_ubyte * 16)]

    class BasicInfo(C.Structure):
        _fields_ = [('created', C.c_int64), ('accessed', C.c_int64),
                    ('written', C.c_int64), ('changed', C.c_int64), ('attributes', W.DWORD)]

    class RenameInfo(C.Structure):
        _fields_ = [('flags', W.DWORD), ('root', W.HANDLE), ('length', W.DWORD),
                    ('name', W.WCHAR * 1)]

    class Overlapped(C.Structure):
        _fields_ = [('internal', C.c_size_t), ('internal_high', C.c_size_t),
                    ('offset', W.DWORD), ('offset_high', W.DWORD), ('event', W.HANDLE)]

    class SecurityAttributes(C.Structure):
        _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit', W.BOOL)]

    kernel = C.WinDLL('kernel32', use_last_error=True)
    security = C.WinDLL('advapi32', use_last_error=True)

    def bind(library, name, result, *args):
        function = getattr(library, name)
        function.argtypes = args
        function.restype = result
        return function

    ptr = C.c_void_p
    out = C.POINTER(W.DWORD)
    sid = C.POINTER(ptr)
    return SimpleNamespace(
        HandleInfo=HandleInfo, FileId=FileId, BasicInfo=BasicInfo, RenameInfo=RenameInfo,
        Overlapped=Overlapped, SecurityAttributes=SecurityAttributes, DWORD=W.DWORD,
        open=bind(kernel, 'CreateFileW', W.HANDLE, W.LPCWSTR, W.DWORD, W.DWORD,
                  ptr, W.DWORD, W.DWORD, W.HANDLE),
        close=bind(kernel, 'CloseHandle', W.BOOL, W.HANDLE),
        kind=bind(kernel, 'GetFileType', W.DWORD, W.HANDLE),
        info=bind(kernel, 'GetFileInformationByHandle', W.BOOL, W.HANDLE, C.POINTER(HandleInfo)),
        get=bind(kernel, 'GetFileInformationByHandleEx', W.BOOL, W.HANDLE, C.c_int, ptr, W.DWORD),
        set=bind(kernel, 'SetFileInformationByHandle', W.BOOL, W.HANDLE, C.c_int, ptr, W.DWORD),
        final=bind(kernel, 'GetFinalPathNameByHandleW', W.DWORD, W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD),
        volume=bind(kernel, 'GetVolumeInformationByHandleW', W.BOOL, W.HANDLE, W.LPWSTR,
                    W.DWORD, out, out, out, W.LPWSTR, W.DWORD),
        drive_type=bind(kernel, 'GetDriveTypeW', W.UINT, W.LPCWSTR),
        flush=bind(kernel, 'FlushFileBuffers', W.BOOL, W.HANDLE),
        lock=bind(kernel, 'LockFileEx', W.BOOL, W.HANDLE, W.DWORD, W.DWORD, W.DWORD,
                  W.DWORD, C.POINTER(Overlapped)),
        unlock=bind(kernel, 'UnlockFileEx', W.BOOL, W.HANDLE, W.DWORD, W.DWORD, W.DWORD,
                    C.POINTER(Overlapped)),
        mkdir=bind(kernel, 'CreateDirectoryW', W.BOOL, W.LPCWSTR, C.POINTER(SecurityAttributes)),
        free=bind(kernel, 'LocalFree', ptr, ptr),
        process=bind(kernel, 'GetCurrentProcess', W.HANDLE),
        token=bind(security, 'OpenProcessToken', W.BOOL, W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)),
        token_info=bind(security, 'GetTokenInformation', W.BOOL, W.HANDLE, C.c_int, ptr, W.DWORD, out),
        get_security=bind(security, 'GetSecurityInfo', W.DWORD, W.HANDLE, C.c_int, W.DWORD,
                          sid, sid, sid, sid, sid),
        equal_sid=bind(security, 'EqualSid', W.BOOL, ptr, ptr),
        known_sid=bind(security, 'IsWellKnownSid', W.BOOL, ptr, C.c_int),
        sid_string=bind(security, 'ConvertSidToStringSidW', W.BOOL, ptr, C.POINTER(W.LPWSTR)),
        descriptor=bind(security, 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
                        W.BOOL, W.LPCWSTR, W.DWORD, sid, out),
    )


def _win_error(operation, path, code=None):
    code = C.get_last_error() if code is None else code
    if code in (2, 3):
        raise FileNotFoundError(errno.ENOENT, operation, str(path), code)
    if code in (80, 183):
        raise FileExistsError(errno.EEXIST, operation, str(path), code)
    if code in (1, 17, 50, 87, 120, 124):
        raise CapabilityError(f'{operation} unavailable (WinError {code}): {path}')
    raise OSError(0, f'{operation}: {C.FormatError(code).strip()}', str(path), code)


# CreateFileW access, sharing and flags.
_READ = 0x80000000
_WRITE = 0x40000000
_DELETE = 0x10000
_READ_CONTROL = 0x20000
_LIST_DIRECTORY = 1
_READ_ATTRIBUTES = 0x80
_WRITE_ATTRIBUTES = 0x100
_SHARE_ALL = 7
_OPEN_EXISTING = 3
_REPARSE_POINT = 0x00200000
_BACKUP_SEMANTICS = 0x02000000
_WRITE_THROUGH = 0x80000000
_READONLY = 1
_DIRECTORY = 0x10
_ATTR_REPARSE = 0x400


def _open_win(path, access, share=_SHARE_ALL, creation=_OPEN_EXISTING, flags=_REPARSE_POINT):
    handle = _win().open(_win_path(path), access, share, None, creation, flags, None)
    if handle == C.c_void_p(-1).value:
        _win_error('CreateFileW', path)
    return handle


@contextmanager
def _handle(path, access, share=_SHARE_ALL, creation=_OPEN_EXISTING, flags=_REPARSE_POINT):
    handle = _open_win(path, access, share, creation, flags)
    try:
        yield handle
    finally:
        _win().close(handle)


def _get_info(handle, kind, info, path):
    if not _win().get(handle, kind, C.byref(info), C.sizeof(info)):
        _win_error('GetFileInformationByHandleEx', path)
    return info


def _win_identity(handle, path):
    info = _get_info(handle, 18, _win().FileId(), path)  # FileIdInfo
    if not any(info.id):
        raise CapabilityError(f'Filesystem has no stable file identity: {path}')
    return info.volume, bytes(info.id)


def _win_info(handle, path, *, directory=False, max_links=None):
    api = _win()
    info = api.HandleInfo()
    if api.kind(handle) != 1:  # FILE_TYPE_DISK
        raise UnsupportedFile(f'Expected a disk file: {path}')
    if not api.info(handle, C.byref(info)):
        _win_error('GetFileInformationByHandle', path)
    if (bool(info.attributes & _DIRECTORY) != directory or info.attributes & _ATTR_REPARSE
            or max_links is not None and not 1 <= info.links <= max_links):
        raise UnsupportedFile(f'Expected an unaliased {"directory" if directory else "regular file"}: {path}')
    return info


def _final_path(handle, path):
    api = _win()
    length = api.final(handle, None, 0, 0)
    if not length:
        _win_error('GetFinalPathNameByHandleW', path)
    buffer = C.create_unicode_buffer(length)
    if not 0 < api.final(handle, buffer, length, 0) < length:
        _win_error('GetFinalPathNameByHandleW', path)
    text = buffer.value
    if not text.startswith('\\\\?\\') or text.startswith('\\\\?\\UNC\\'):
        raise CapabilityError(f'Expected a local Windows volume: {path}')
    final = Path(text[4:])
    validate_path(final)
    return final


@lru_cache(maxsize=1)
def _darwin_libc():
    libc = C.CDLL(None, use_errno=True)
    libc.realpath.argtypes = [C.c_char_p, C.c_void_p]
    libc.realpath.restype = C.c_void_p
    libc.getattrlist.argtypes = [C.c_char_p, C.c_void_p, C.c_void_p, C.c_size_t, C.c_ulong]
    libc.getattrlist.restype = C.c_int
    return libc


def _darwin_realpath(path):
    result = C.create_string_buffer(1024)  # Darwin PATH_MAX
    if not _darwin_libc().realpath(os.fsencode(path), result):
        code = C.get_errno()
        raise OSError(code, os.strerror(code), str(path))
    return Path(os.fsdecode(result.value))


def canonical_path(path, *, strict=False):
    path = Path(path)
    validate_path(path)
    if not WINDOWS:
        try:
            resolved = path.resolve(strict=strict)
        except RuntimeError as exc:
            # Python 3.12 and earlier report symlink loops as RuntimeError.
            raise OSError(errno.ELOOP, 'Cannot resolve symlink loop', str(path)) from exc
        if not DARWIN:
            return resolved
        # Darwin libc realpath queries stored component names. pathlib's
        # POSIX symlink resolution preserves the caller's case spelling.
        for existing in (resolved, *resolved.parents):
            try:
                canonical = _darwin_realpath(existing)
                return canonical.joinpath(*resolved.parts[len(existing.parts):])
            except (FileNotFoundError, NotADirectoryError):
                if strict or existing == existing.parent:
                    raise
    # Follow aliases here so callers can detect and reject them. Actual reads
    # and writes open without following the final component.
    try:
        with _handle(path, _READ_ATTRIBUTES, flags=_BACKUP_SEMANTICS) as handle:
            return _final_path(handle, path)
    except FileNotFoundError:
        if strict or path == path.parent:
            raise
        return canonical_path(path.parent) / path.name


def unaliased_path(path):
    canonical = canonical_path(path)
    if canonical != path and (not DARWIN or any(p.is_symlink() for p in (path, *path.parents))):
        raise UnsupportedFile(f'Path has a filesystem alias: {path}')
    return canonical


def _darwin_case_sensitive(directory):
    # attrlist with ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES.
    request = struct.pack('=HH5I', 5, 0, 0, 0x80020000, 0, 0, 0)
    result = (C.c_uint32 * 9)()  # Length, four capability words, four validity words.
    if _darwin_libc().getattrlist(os.fsencode(directory), request, result, C.sizeof(result), 0):
        code = C.get_errno()
        raise OSError(code, os.strerror(code), str(directory))
    case_sensitive = 0x100  # VOL_CAP_FMT_CASE_SENSITIVE
    if result[0] != C.sizeof(result) or not result[5] & case_sensitive:
        raise CapabilityError(f'Cannot determine filesystem case sensitivity: {directory}')
    return bool(result[1] & case_sensitive)


def contains_path(path, root):
    """Compare canonical paths, including paths whose final names are absent."""
    if path.is_relative_to(root):
        return True
    if not DARWIN or len(path.parts) < len(root.parts) or root.exists():
        return False
    prefix = unicodedata.normalize('NFD', str(Path(*path.parts[:len(root.parts)])))
    normalized_root = unicodedata.normalize('NFD', str(root))
    if prefix == normalized_root:
        return True
    if prefix.casefold() != normalized_root.casefold():
        return False
    existing_parent = next(parent for parent in root.parents if parent.is_dir())
    return not _darwin_case_sensitive(existing_parent)


def excluded_roots():
    values = ['/tmp', '/var/tmp', '/dev/shm', '/run', '/private/tmp', '/private/var/tmp'] if not WINDOWS else []
    values.append(tempfile.gettempdir())
    variables = ['TMPDIR', 'TEMP', 'TMP', 'XDG_RUNTIME_DIR']
    if WINDOWS:
        variables += ['SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramData', 'PUBLIC']
        if os.environ.get('SystemRoot'):
            values.append(str(Path(os.environ['SystemRoot']) / 'Temp'))
    if DARWIN:
        values.append(os.confstr(os.confstr_names.get('CS_DARWIN_USER_TEMP_DIR', 65537)))
    values.extend(os.environ.get(key) for key in variables)
    return {canonical_path(Path(value).absolute()) for value in values if value}


def _volume_info(handle, path):
    api = _win()
    flags = api.DWORD()
    filesystem = C.create_unicode_buffer(32)
    if not api.volume(handle, None, 0, None, None, C.byref(flags), filesystem, len(filesystem)):
        _win_error('GetVolumeInformationByHandleW', path)
    return filesystem.value, flags.value


def _volume(handle, path):
    filesystem, flags = _volume_info(handle, path)
    if (filesystem != 'NTFS' or not flags & 8 or flags & 0x80000
            or _win().drive_type(_final_path(handle, path).anchor) != 3):
        raise CapabilityError(f'Evidence writes require writable local NTFS with persistent ACLs: {path}')
    return _win_identity(handle, path)[0]


@contextmanager
def _write_parent(path):
    # Keep the directory itself open without FILE_SHARE_DELETE.
    with _handle(path, _LIST_DIRECTORY | _READ_ATTRIBUTES, share=3,
                 flags=_REPARSE_POINT | _BACKUP_SEMANTICS) as handle:
        _win_info(handle, path, directory=True)
        if _final_path(handle, path) != path:
            raise UnsupportedFile(f'Write directory has an alias: {path}')
        yield handle


@contextmanager
def _token_sid(kind):
    api = _win()
    token = C.c_void_p()
    if not api.token(api.process(), 8, C.byref(token)):  # TOKEN_QUERY
        _win_error('OpenProcessToken', 'current user')
    try:
        length = api.DWORD()
        api.token_info(token, kind, None, 0, C.byref(length))
        if not length.value:
            _win_error('GetTokenInformation', 'current user')
        info = C.create_string_buffer(length.value)
        if not api.token_info(token, kind, info, length, C.byref(length)):
            _win_error('GetTokenInformation', 'current user')
        # TOKEN_USER and TOKEN_OWNER both begin with a pointer to the SID.
        yield C.cast(info, C.POINTER(C.c_void_p))[0]
    finally:
        api.close(token)


def owned_directory(path):
    if WINDOWS:
        api = _win()
        with _handle(path, _READ_CONTROL | _READ_ATTRIBUTES,
                     flags=_REPARSE_POINT | _BACKUP_SEMANTICS) as handle:
            _win_info(handle, path, directory=True)
            _, flags = _volume_info(handle, path)
            if not flags & 8:  # FILE_PERSISTENT_ACLS
                raise CapabilityError(f'Evidence ownership requires persistent ACLs: {path}')
            owner, dacl, descriptor = C.c_void_p(), C.c_void_p(), C.c_void_p()
            code = api.get_security(handle, 1, 5, C.byref(owner), None,
                                    C.byref(dacl), None, C.byref(descriptor))
            if code:
                _win_error('GetSecurityInfo', path, code)
            try:
                with _token_sid(1) as user, _token_sid(4) as default_owner:
                    if dacl and owner and (api.equal_sid(owner, user)
                            or (api.known_sid(default_owner, 26) and api.equal_sid(owner, default_owner))):
                        return
            finally:
                api.free(descriptor)
    else:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if os.fstat(fd).st_uid == os.geteuid():
                return
        finally:
            os.close(fd)
    raise PermissionError(f'Directory must be owned by the invoking user with a protected filesystem: {path}')


def require_same_volume(first, second):
    if WINDOWS:
        def volume(path):
            with _handle(path, _READ_ATTRIBUTES, flags=_REPARSE_POINT | _BACKUP_SEMANTICS) as handle:
                _win_info(handle, path, directory=True)
                return _volume(handle, path)
        if volume(first) != volume(second):
            raise CapabilityError(f'Evidence writes require a single NTFS volume: {first}, {second}')


def _mkdir(path):
    if not WINDOWS:
        path.mkdir()
        return
    api = _win()
    with _token_sid(1) as user:
        string = C.c_wchar_p()
        if not api.sid_string(user, C.byref(string)):
            _win_error('ConvertSidToStringSidW', path)
        try:
            sid = string.value
            sddl = f'O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        finally:
            api.free(C.cast(string, C.c_void_p))
    descriptor = C.c_void_p()
    if not api.descriptor(sddl, 1, C.byref(descriptor), None):
        _win_error('ConvertStringSecurityDescriptorToSecurityDescriptorW', path)
    try:
        attributes = api.SecurityAttributes(C.sizeof(api.SecurityAttributes), descriptor, False)
        with _write_parent(path.parent) as parent:
            _volume(parent, path.parent)
            if not api.mkdir(_win_path(path), C.byref(attributes)):
                _win_error('CreateDirectoryW', path)
    finally:
        api.free(descriptor)


def ensure_directory(path, *, parents=False, exist_ok=True):
    try:
        _mkdir(path)
    except FileNotFoundError:
        if not parents or path == path.parent:
            raise
        ensure_directory(path.parent, parents=True)
        ensure_directory(path, exist_ok=exist_ok)
    except FileExistsError:
        if not exist_ok:
            raise
        if not path.is_dir() or canonical_path(path) != path:
            raise UnsupportedFile(f'Expected an unaliased directory: {path}')
        if WINDOWS:
            with _handle(path, _READ_ATTRIBUTES, flags=_REPARSE_POINT | _BACKUP_SEMANTICS) as handle:
                _win_info(handle, path, directory=True)
    else:
        sync_directory(path.parent)


def stage_directory(parent, prefix):
    if not WINDOWS:
        return Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    from uuid import uuid4
    path = parent / (prefix + uuid4().hex)
    ensure_directory(path, exist_ok=False)
    return path


def identity(path):
    if WINDOWS:
        with _handle(path, _READ_ATTRIBUTES) as handle:
            _win_info(handle, path)
            return _win_identity(handle, path)
    info = path.stat()
    return info.st_dev, info.st_ino


def _posix_signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _windows_signature(handle, path, max_links):
    info = _win_info(handle, path, max_links=max_links)
    basic = _get_info(handle, 0, _win().BasicInfo(), path)  # FileBasicInfo
    return (_win_identity(handle, path), info.attributes, info.links,
            (info.size_high << 32) | info.size_low, basic.written, basic.changed)


def _win_fd(handle, flags):
    import msvcrt
    try:
        return msvcrt.open_osfhandle(handle, flags | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        _win().close(handle)
        raise


def read_regular(path, *, max_bytes=None, max_links=None, anchor=None):
    validate_path(path)
    pre = path.lstat()
    if not stat.S_ISREG(pre.st_mode):
        raise UnsupportedFile(f'Expected a regular file: {path}')
    if not WINDOWS and max_links is not None and not 1 <= pre.st_nlink <= max_links:
        raise UnsupportedFile(f'Expected a regular file with permitted link count: {path}')
    if WINDOWS:
        with _handle(path, _READ_ATTRIBUTES) as probe:
            before = _windows_signature(probe, path, max_links)
        handle = _open_win(path, _READ)
        fd = _win_fd(handle, os.O_RDONLY)
        signature = lambda: _windows_signature(handle, path, max_links)
        mode = 0o444 if before[1] & _READONLY else 0o666
        size = before[3]
    else:
        before = _posix_signature(pre)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        signature = lambda: _posix_signature(os.fstat(fd))
        mode = stat.S_IMODE(pre.st_mode)
        size = pre.st_size
    with os.fdopen(fd, 'rb') as stream:
        if anchor is not None:
            path_checked, anchor_checked = path, anchor
            if WINDOWS:
                actual = _final_path(handle, path)
            elif DARWIN:
                import fcntl
                actual = Path(os.fsdecode(fcntl.fcntl(fd, 50, bytes(1024)).split(b'\0', 1)[0]))  # F_GETPATH
                actual = canonical_path(actual, strict=True)
                path_checked = unaliased_path(path)
                anchor_checked = unaliased_path(anchor)
            else:
                actual = Path(os.readlink(f'/proc/self/fd/{fd}'))
            if not actual.is_relative_to(anchor_checked) or actual != path_checked:
                raise UnsupportedFile(f'Opened file escapes its expected location: {path}')
        if signature() != before:
            raise SourceChanged(f'File changed during open: {path}')
        if max_bytes is not None and size > max_bytes:
            raise SizeLimit(f'File exceeds size limit: {path}')
        data = stream.read() if max_bytes is None else stream.read(max_bytes + 1)
        after = signature()
        if WINDOWS:
            with _handle(path, _READ_ATTRIBUTES) as current:
                latest = _windows_signature(current, path, max_links)
        else:
            latest = _posix_signature(path.lstat())
        if not before == after == latest:
            raise SourceChanged(f'File changed during read: {path}')
    if max_bytes is not None and len(data) > max_bytes:
        raise SizeLimit(f'File exceeds size limit: {path}')
    return data, mode


def sync_file(fd):
    if DARWIN:
        import fcntl
        try:
            fcntl.fcntl(fd, getattr(fcntl, 'F_FULLFSYNC', 51))
        except OSError as exc:
            if exc.errno in (errno.EINVAL, errno.ENOTTY, errno.ENOTSUP):
                raise CapabilityError(f'Filesystem does not support F_FULLFSYNC (errno {exc.errno})') from exc
            raise
    elif WINDOWS:
        import msvcrt
        if not _win().flush(msvcrt.get_osfhandle(fd)):
            _win_error('FlushFileBuffers', 'regular file')
    else:
        os.fsync(fd)


def sync_directory(path):
    if WINDOWS:
        # Win32 has no supported unprivileged directory-entry flush.
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _set_info(handle, kind, info, path):
    if not _win().set(handle, kind, C.byref(info), C.sizeof(info)):
        _win_error('SetFileInformationByHandle', path)


def _set_readonly(handle, path, readonly):
    basic = _win().BasicInfo()  # Zero timestamps leave the current times in place.
    basic.attributes = _READONLY if readonly else 0x80  # FILE_ATTRIBUTE_NORMAL
    _set_info(handle, 0, basic, path)


class _StagedFile:
    def __init__(self, path, handle):
        self.path = path
        self.handle = handle
        self.published = False


@contextmanager
def stage(parent, data, *, mode=None, prefix='.partial-'):
    if WINDOWS:
        from uuid import uuid4
        path = parent / (prefix + uuid4().hex)
        with _write_parent(parent) as directory:
            _volume(directory, parent)
            handle = _open_win(path, _WRITE | _DELETE | _READ_ATTRIBUTES | _WRITE_ATTRIBUTES,
                               1, 1, _REPARSE_POINT | _WRITE_THROUGH)  # CREATE_NEW
        fd = _win_fd(handle, os.O_WRONLY)
    else:
        fd, name = tempfile.mkstemp(prefix=prefix, dir=parent)
        path, handle = Path(name), None
    staged = _StagedFile(path, handle)
    try:
        # Keep the Windows handle pinned until the publication or cleanup.
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
        if mode is not None:
            if WINDOWS:
                _set_readonly(handle, path, not mode & stat.S_IWUSR)
            else:
                os.fchmod(fd, mode)
        sync_file(fd)
        yield staged
    finally:
        try:
            if not staged.published and WINDOWS:
                _set_readonly(handle, path, False)
                _set_info(handle, 4, C.c_ubyte(1), path)  # FileDispositionInfo.DeleteFile
            elif not staged.published:
                path.unlink(missing_ok=True)
        finally:
            os.close(fd)


@lru_cache(maxsize=1)
def _posix_rename():
    libc = C.CDLL(None, use_errno=True)
    name = 'renamex_np' if DARWIN else 'renameat2'
    rename = getattr(libc, name, None)
    if rename is None:
        raise CapabilityError(f'Host does not provide {name}')
    rename.argtypes = ([C.c_char_p, C.c_char_p, C.c_uint] if DARWIN else
                       [C.c_int, C.c_char_p, C.c_int, C.c_char_p, C.c_uint])
    rename.restype = C.c_int
    return rename


def _rename_win(handle, source, destination, replace, *, directory=False):
    api = _win()
    _win_info(handle, source, directory=directory, max_links=None if directory else 1)
    with _write_parent(destination.parent) as parent:
        final = destination.parent
        if _final_path(handle, source) != source:
            raise UnsupportedFile(f'Rename source or destination has an alias: {destination}')
        if _volume(parent, final) != _win_identity(handle, source)[0]:
            raise CapabilityError(f'Atomic rename requires a single NTFS volume: {destination}')
        encoded = _win_path(final / destination.name).encode('utf-16-le')
        offset = api.RenameInfo.name.offset
        buffer = C.create_string_buffer(max(C.sizeof(api.RenameInfo), offset + len(encoded) + 2))
        info = api.RenameInfo.from_buffer(buffer)
        info.length = len(encoded)
        C.memmove(C.addressof(buffer) + offset, encoded, len(encoded))
        if replace:
            # Require delete sharing explicitly before requesting POSIX-style replacement.
            with _handle(destination, _DELETE | _READ_ATTRIBUTES) as previous:
                prior = _win_info(previous, destination, max_links=1)
                if _final_path(previous, destination) != destination:
                    raise UnsupportedFile(f'Replacement target has an alias: {destination}')
                info.flags = 0x43  # REPLACE_IF_EXISTS | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE
                if api.set(handle, 22, buffer, C.sizeof(buffer)):  # FileRenameInfoEx
                    return
                code = C.get_last_error()
                if code not in (1, 50, 87, 120, 124):
                    _win_error('FileRenameInfoEx', destination, code)
                if prior.attributes & _READONLY:
                    raise CapabilityError(f'Atomic read-only replacement requires FileRenameInfoEx: {destination}')
        info.flags = int(replace)
        if not api.set(handle, 3, buffer, C.sizeof(buffer)):  # FileRenameInfo
            _win_error('FileRenameInfo', destination)


def _publish(source, destination, *, replace):
    stage = source if isinstance(source, _StagedFile) else None
    path = stage.path if stage is not None else source
    if WINDOWS:
        if stage is not None:
            _rename_win(stage.handle, path, destination, replace)
        else:
            with _handle(path, _DELETE | _READ_ATTRIBUTES,
                         flags=_REPARSE_POINT | _BACKUP_SEMANTICS) as handle:
                _rename_win(handle, path, destination, replace, directory=source.is_dir())
    elif replace:
        os.replace(path, destination)
    else:
        args = (os.fsencode(path), os.fsencode(destination), 4) if DARWIN else (
            -100, os.fsencode(path), -100, os.fsencode(destination), 1)
        if _posix_rename()(*args):
            code = C.get_errno()
            if code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EXDEV):
                raise CapabilityError(f'Filesystem does not support no-clobber rename (errno {code}): {destination}')
            raise OSError(code, os.strerror(code), str(destination))
    if stage is not None:
        stage.published = True


def publish_new(source, destination):
    _publish(source, destination, replace=False)


def replace_existing(source, destination):
    _publish(source, destination, replace=True)


@contextmanager
def sidecar_lock(path, timeout):
    overlapped = None
    if WINDOWS:
        # Share reads and writes, but deny delete and rename while locked.
        with _write_parent(path.parent) as parent:
            _volume(parent, path.parent)
            handle = _open_win(path, _READ | _WRITE, 3, 4)  # OPEN_ALWAYS
        fd = _win_fd(handle, os.O_RDWR)
    else:
        import fcntl
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    try:
        if WINDOWS:
            api = _win()
            _win_info(handle, path, max_links=1)
            if _final_path(handle, path) != path:
                raise UnsupportedFile(f'Lock path has an alias: {path}')
        else:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise UnsupportedFile(f'Unsupported lock file: {path}')
        deadline = time.monotonic() + timeout
        while True:
            if WINDOWS:
                attempt = api.Overlapped()
                if api.lock(handle, 3, 0, 1, 0, C.byref(attempt)):
                    overlapped = attempt
                    break
                code = C.get_last_error()
                if code != 33:  # ERROR_LOCK_VIOLATION
                    _win_error('LockFileEx', path, code)
            else:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    pass
            if time.monotonic() >= deadline:
                raise LockBusy('Target lock is busy')
            time.sleep(0.02)
        if not WINDOWS and _posix_signature(info)[:2] != _posix_signature(path.lstat())[:2]:
            raise SourceChanged(f'Lock path changed: {path}')
        yield fd
    finally:
        if overlapped is not None:
            api.unlock(handle, 0, 1, 0, C.byref(overlapped))
        os.close(fd)
