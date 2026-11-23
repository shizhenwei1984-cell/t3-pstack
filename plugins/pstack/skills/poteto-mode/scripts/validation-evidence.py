#!/usr/bin/env python3
"""Read-only, bounded fixture/source/evidence checks. See references/validation-evidence.md."""
import argparse
import ctypes as C
from functools import lru_cache
import hashlib
import importlib.util
import json
import posixpath
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from types import SimpleNamespace

# Load the installed sibling without creating bytecode or searching sys.path.
def _load_filesystem():
    path = Path(__file__).resolve().with_name('evidence_fs.py')
    spec = importlib.util.spec_from_file_location('_pstack_evidence_fs', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


_fs = _load_filesystem()


def sha_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def required_text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('expected nonempty string')
    return value


def object_value(value):
    if not isinstance(value, dict):
        raise ValueError('expected object')
    return value


def container_path(value):
    text = required_text(value)
    if not text.startswith('/'):
        raise ValueError('container paths must be absolute')
    # Lexical POSIX normalization only; host resolve cannot resolve container symlinks.
    return PurePosixPath('/' + posixpath.normpath(text).lstrip('/'))


def absolute(value):
    text = required_text(value)
    _fs.validate_path(text)
    path = Path(text)
    if not path.is_absolute():
        raise ValueError('file paths must be absolute')
    return path


def checked_bytes(path, sha):
    path = absolute(path)
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('expected SHA-256')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha:
        raise ValueError('hash mismatch: ' + str(path))
    return data


def checked_file(path, sha):
    return checked_bytes(path, sha).decode('utf-8')


def fixture(d, prepare=False):
    result = {'candidate': d.get('candidate'), 'outcome': 'uncovered', 'scope': 'artifact checks only'}
    try:
        required_text(d['candidate'])
        if d['adapter'] != 'literal-files-v1':
            raise ValueError('unsupported fixture adapter')
        route = required_text(d['route'])
        if route != route.strip() or ' -> ' in route or '\n' in route or '\r' in route:
            raise ValueError('invalid literal route')
        routes = d['supported_routes']
        if not isinstance(routes, dict) or routes.get(d['route']) != d['template']:
            raise ValueError('route/template binding unsupported')
        source = object_value(d['source'])
        source_text = checked_file(source['path'], source['sha256'])
        # Exact whole-line binding, not a boolean claim about a factory.
        bindings = [line for line in source_text.splitlines()
                    if line.split(' -> ', 1)[0].strip() == route]
        if bindings != [required_text(source['binding'])]:
            raise ValueError('route binding missing or ambiguous in source')
        # Contract uses a deliberately small, explicit binding syntax.
        expected_binding = d['route'] + ' -> ' + Path(d['template']).name
        if source['binding'] != expected_binding:
            raise ValueError('binding does not identify requested route/template')
        if (_fs.canonical_path(absolute(source['path'])).parent / Path(d['template']).name) != _fs.canonical_path(absolute(d['template'])):
            raise ValueError('literal binding template must be beside source file')
        template = checked_file(d['template'], d['template_sha256'])
        if required_text(d['slot_literal']) not in template:
            raise ValueError('target slot absent from template')
        if prepare:
            result.update(outcome='ready', scope='literal route/template preparation only')
            return result
        extraction = object_value(d['extract'])
        start = required_text(extraction['start'])
        end = required_text(extraction['end'])
        canary = required_text(d['canary'])
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', canary):
            raise ValueError('literal canary must use ASCII letters, digits, underscore, dot or dash')
        expected = required_text(d['benign_expected'])
        outputs = object_value(d['outputs'])
        paths = [_fs.canonical_path(absolute(outputs[name]), strict=True)
                 for name in ('target', 'positive', 'benign')]
        identities = {_fs.identity(p) for p in paths}
        if len(identities) != 3:
            raise ValueError('target and controls must be distinct physical files')
        extracts = {}
        for name, path in zip(('target', 'positive', 'benign'), paths):
            raw = path.read_text(encoding='utf-8')
            if raw.count(start) != 1:
                raise ValueError('ambiguous or absent start delimiter: ' + name)
            tail = raw.split(start, 1)[1]
            if tail.count(end) != 1:
                raise ValueError('ambiguous or absent end delimiter: ' + name)
            extracts[name] = required_text(tail.split(end, 1)[0])
        if canary not in extracts['positive']:
            raise ValueError('positive control did not expose seeded canary')
        if extracts['benign'] != expected or canary in extracts['benign']:
            raise ValueError('benign control mismatch or canary present')
        result.update(outcome='fail' if canary in extracts['target'] else 'pass',
                      extracted_lengths={key: len(value) for key, value in extracts.items()})
    except (KeyError, TypeError, ValueError, OSError) as exc:
        result['reason'] = str(exc)
    return result


def parse_stat(raw):
    # comm is parenthesized and may itself contain spaces or parentheses.
    opening, closing = raw.index('('), raw.rindex(')')
    fields = raw[closing + 1:].split()  # begins with Linux field 3, state
    return {'pid': int(raw[:opening].strip()), 'comm': raw[opening + 1:closing],
            'start_ticks': int(fields[19]), 'state': fields[0]}  # Linux field 22, NOT field 23


def docker(container, *args):
    required_text(container)
    if container.startswith('-'):
        raise ValueError('container identifier cannot begin with dash')
    command = (['docker', 'inspect', '--type', 'container', '--', container]
               if args == ('inspect',) else ['docker', *args[:1], container, *args[1:]])
    completed = subprocess.run(command,
                               capture_output=True, check=True, timeout=15)
    return completed.stdout


def visible_bytes(path, container=None):
    if container:
        return docker(container, 'exec', 'cat', '--', str(container_path(path)))
    return absolute(path).read_bytes()


def read_process(pid, container=None):
    if type(pid) is not int or pid <= 0:
        raise ValueError('pid must be a positive integer; no name search is performed')
    stat_path = f'/proc/{pid}/stat'
    try:
        before = parse_stat(visible_bytes(stat_path, container).decode('utf-8'))
    except (ValueError, IndexError) as exc:
        raise OSError('unreadable Linux stat record') from exc
    raw_cmd = visible_bytes(f'/proc/{pid}/cmdline', container)
    if not raw_cmd:
        raise OSError('empty process cmdline')
    argv = (raw_cmd[:-1] if raw_cmd.endswith(b'\0') else raw_cmd).split(b'\0')
    try:
        after = parse_stat(visible_bytes(stat_path, container).decode('utf-8'))
    except (ValueError, IndexError) as exc:
        raise OSError('unreadable Linux stat record') from exc
    if before['state'] in ('Z', 'X', 'x') or after['state'] in ('Z', 'X', 'x'):
        raise OSError('process is dead or zombie')
    if any(before[key] != after[key] for key in ('pid', 'comm', 'start_ticks')) or after['pid'] != pid:
        raise OSError('process changed during read')
    after['boot_id'] = visible_bytes('/proc/sys/kernel/random/boot_id', container).decode('utf-8').strip()
    after['argv'] = [item.decode('utf-8', errors='surrogateescape') for item in argv]
    return after


@lru_cache(maxsize=1)
def _darwin_api():
    # proc_bsdinfo in <sys/proc_info.h>.
    class BsdInfo(C.Structure):
        _fields_ = [
            ('flags', C.c_uint32), ('status', C.c_uint32), ('xstatus', C.c_uint32),
            ('pid', C.c_uint32), ('ppid', C.c_uint32), ('uid', C.c_uint32),
            ('gid', C.c_uint32), ('ruid', C.c_uint32), ('rgid', C.c_uint32),
            ('svuid', C.c_uint32), ('svgid', C.c_uint32), ('reserved', C.c_uint32),
            ('comm', C.c_char * 16), ('name', C.c_char * 32),
            ('nfiles', C.c_uint32), ('pgid', C.c_uint32), ('pjobc', C.c_uint32),
            ('tdev', C.c_uint32), ('tpgid', C.c_uint32), ('nice', C.c_int32),
            ('start_sec', C.c_uint64), ('start_usec', C.c_uint64),
        ]

    libc = C.CDLL(None, use_errno=True)
    size_pointer = C.POINTER(C.c_size_t)
    sysctl = libc.sysctl
    sysctl.argtypes = [C.POINTER(C.c_int), C.c_uint, C.c_void_p, size_pointer, C.c_void_p, C.c_size_t]
    sysctl.restype = C.c_int
    sysctlbyname = libc.sysctlbyname
    sysctlbyname.argtypes = [C.c_char_p, C.c_void_p, size_pointer, C.c_void_p, C.c_size_t]
    sysctlbyname.restype = C.c_int
    try:
        proc_info = C.CDLL('/usr/lib/libproc.dylib', use_errno=True).proc_pidinfo
    except AttributeError as exc:
        raise OSError('Darwin proc_pidinfo is unavailable') from exc
    proc_info.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
    proc_info.restype = C.c_int
    return SimpleNamespace(BsdInfo=BsdInfo, proc_info=proc_info, sysctl=sysctl, sysctlbyname=sysctlbyname)


def _darwin_argv(raw, pointer_size):
    if len(raw) < 4 or pointer_size not in (4, 8):
        raise OSError('Unreadable Darwin KERN_PROCARGS2 record')
    argc = int.from_bytes(raw[:4], sys.byteorder, signed=True)
    path_end = raw.find(b'\0', 4) + 1
    if path_end <= 5 or argc <= 0:
        raise OSError('Invalid Darwin process argument count')
    # XNU exec_extract_strings aligns the saved path including its terminator
    # to the target pointer width. sysctl_procargsx removes executable_path=
    # (16 bytes), which preserves that alignment relative to the path start.
    argv_start = 4 + ((path_end - 4 + pointer_size - 1) // pointer_size) * pointer_size
    if any(raw[path_end:argv_start]) or argc > len(raw) - argv_start:
        raise OSError('Invalid Darwin process argument boundary')
    args = raw[argv_start:].split(b'\0', argc)
    if len(args) != argc + 1:
        raise OSError('Truncated Darwin process argument record')
    return [part.decode('utf-8', errors='surrogateescape') for part in args[:argc]]


def _read_darwin_process(pid):
    api = _darwin_api()

    def identity():
        proc = api.BsdInfo()
        capacity = C.sizeof(proc)
        if api.proc_info(pid, 3, 0, C.byref(proc), capacity) != capacity:  # PROC_PIDTBSDINFO
            raise OSError(f'proc_pidinfo unavailable (errno {C.get_errno()})')
        if proc.pid != pid or proc.status in (0, 5) or proc.flags & 4:  # SZOMB, PROC_FLAG_INEXIT
            raise OSError('Darwin process has exited or is exiting')
        boot = C.create_string_buffer(128)
        size = C.c_size_t(len(boot))
        if api.sysctlbyname(b'kern.bootsessionuuid', boot, C.byref(size), None, 0):
            raise OSError(f'kern.bootsessionuuid unavailable (errno {C.get_errno()})')
        if not boot.value:
            raise OSError('Empty Darwin boot session UUID')
        pointer_size = 8 if proc.flags & 0x10 else 4  # PROC_FLAG_LP64
        return boot.value.decode('ascii'), proc.start_sec, proc.start_usec, pointer_size

    before = identity()
    argmax = C.c_int()
    size = C.c_size_t(C.sizeof(argmax))
    if api.sysctlbyname(b'kern.argmax', C.byref(argmax), C.byref(size), None, 0):
        raise OSError(f'kern.argmax unavailable (errno {C.get_errno()})')
    if not 0 < argmax.value <= 16 * 1024 * 1024:
        raise OSError('Darwin process argument capacity outside supported bounds')
    raw = C.create_string_buffer(argmax.value + 4)  # XNU excludes argc from ARG_MAX.
    mib = (C.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    size = C.c_size_t(len(raw))
    if api.sysctl(mib, len(mib), raw, C.byref(size), None, 0):
        raise OSError(f'KERN_PROCARGS2 unavailable (errno {C.get_errno()})')
    if size.value >= len(raw):
        raise OSError('Darwin process argument record may be truncated')
    if before != identity():
        raise OSError('Darwin process identity changed during inspection')
    boot, seconds, microseconds, pointer_size = before
    argv = _darwin_argv(raw[:size.value], pointer_size)
    return {'profile': 'darwin', 'pid': pid, 'boot_session_uuid': boot,
            'start_sec': seconds, 'start_usec': microseconds, 'argv': argv}


@lru_cache(maxsize=1)
def _windows_api():
    from ctypes import wintypes as W

    def bind(name, result, *args):
        function = getattr(kernel, name)
        function.argtypes = args
        function.restype = result
        return function

    kernel = C.WinDLL('kernel32', use_last_error=True)
    ft = C.POINTER(W.FILETIME)
    return SimpleNamespace(
        FileTime=W.FILETIME,
        open=bind('OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD),
        close=bind('CloseHandle', W.BOOL, W.HANDLE),
        wait=bind('WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD),
        times=bind('GetProcessTimes', W.BOOL, W.HANDLE, ft, ft, ft, ft),
        command_line=bind('GetCommandLineW', W.LPCWSTR),
        system_directory=bind('GetSystemDirectoryW', W.UINT, W.LPWSTR, W.UINT),
    )


def _windows_command_line(api, pid):
    if pid == os.getpid():
        return api.command_line()
    directory = C.create_unicode_buffer(32768)
    if not 0 < api.system_directory(directory, len(directory)) < len(directory):
        raise OSError(f'GetSystemDirectoryW failed (WinError {C.get_last_error()})')
    shell = Path(directory.value) / 'WindowsPowerShell/v1.0/powershell.exe'
    command = ("[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); "
               "$ErrorActionPreference = 'Stop'; "
               f"$row = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; "
               'ConvertTo-Json -InputObject $row.CommandLine -Compress')
    result = subprocess.run([str(shell), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, check=True, timeout=15)
    try:
        return json.loads(result.stdout.decode('utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise OSError('Unreadable Windows CIM process command line') from exc


def _read_windows_process(pid):
    api = _windows_api()
    query, synchronize = 0x1000, 0x100000  # PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE
    handle = api.open(query | synchronize, False, pid)
    if not handle:
        raise OSError(f'OpenProcess with query and synchronize access failed (WinError {C.get_last_error()})')

    def require_running():
        waited = api.wait(handle, 0)
        if waited == 0:  # WAIT_OBJECT_0
            raise OSError('Windows process has exited')
        if waited != 258:  # WAIT_TIMEOUT
            raise OSError(f'WaitForSingleObject failed (WinError {C.get_last_error()})')

    try:
        require_running()
        creation, exit_time, kernel, user = (api.FileTime() for _ in range(4))
        if not api.times(handle, C.byref(creation), C.byref(exit_time), C.byref(kernel), C.byref(user)):
            raise OSError(f'GetProcessTimes failed (WinError {C.get_last_error()})')
        command = _windows_command_line(api, pid)
        if not isinstance(command, str) or not command:
            raise OSError('Windows process command line unavailable')
        require_running()
        filetime = str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
        return {'profile': 'windows', 'pid': pid, 'creation_filetime': filetime, 'command_line': command}
    finally:
        api.close(handle)


def _local_profile():
    if sys.platform.startswith('linux'):
        return 'linux'
    return {'darwin': 'darwin', 'win32': 'windows'}.get(sys.platform)


def read_local_process(pid):
    profile = _local_profile()
    if profile == 'linux':
        return read_process(pid)
    limit = 0xffffffff if profile == 'windows' else 0x7fffffff
    if type(pid) is not int or not 0 < pid <= limit:
        raise ValueError('pid must be a positive integer within the host PID range')
    probe = {'darwin': _read_darwin_process, 'windows': _read_windows_process}.get(profile)
    if probe is None:
        raise OSError('Local process inspection is unavailable on this host')
    return probe(pid)


def _process_fields(expected, profile):
    if profile == 'windows':
        raw_time = expected['creation_filetime']
        if (not isinstance(raw_time, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', raw_time)
                or int(raw_time) >= 1 << 64):
            raise ValueError('expected creation_filetime must be an unsigned 64-bit decimal string')
        required_text(expected['command_line'])
        return ('pid', 'creation_filetime', 'command_line')
    if not isinstance(expected['argv'], list) or not expected['argv'] or not all(
            isinstance(value, str) for value in expected['argv']):
        raise ValueError('expected argv must be a nonempty string array')
    if profile == 'darwin':
        required_text(expected['boot_session_uuid'])
        time_fields = ('start_sec', 'start_usec')
        boot_field = 'boot_session_uuid'
    else:
        required_text(expected['boot_id'])
        time_fields = ('start_ticks',)
        boot_field = 'boot_id'
    for key in time_fields:
        if type(expected[key]) is not int or expected[key] < 0:
            raise ValueError(f'expected {key} must be nonnegative integer')
    if profile == 'darwin' and expected['start_usec'] >= 1_000_000:
        raise ValueError('expected start_usec must be below one million')
    return ('pid', 'argv', boot_field, *time_fields)


def covering_mount(mounts, visible):
    if not isinstance(mounts, list):
        raise ValueError('mounts must be an array')
    path = container_path(visible)
    matches = []
    destinations = set()
    for entry in mounts:
        mount = object_value(entry).copy()
        destination = container_path(mount['Destination'])
        if destination in destinations:
            raise ValueError('ambiguous mount destination')
        destinations.add(destination)
        mount['Destination'] = str(destination)
        if path == destination or destination in path.parents:
            matches.append(mount)
    return max(matches, key=lambda m: len(PurePosixPath(m['Destination']).parts), default=None)


def preflight(d):
    result = {'candidate': d.get('candidate'), 'outcome': 'uncovered',
              'source_mode': d.get('source_mode'),
              'source_status': 'unknown', 'process_status': 'unknown',
              'loaded_candidate': 'unknown',
              'load_reason': 'visible bytes and process identity do not prove resident code loading'}
    mode = d.get('source_mode')
    if mode not in ('local', 'docker-bind', 'docker-image'):
        result.update(source_status='unsupported', reason='explicit supported source_mode required')
        return result
    container = None if mode == 'local' else d.get('container')
    container_ready = mode == 'local'
    try:
        required_text(d['candidate'])
        if mode != 'local':
            required_text(container)
            info = json.loads(docker(container, 'inspect'))
            if not isinstance(info, list) or not info or not isinstance(info[0], dict):
                raise OSError('unsupported Docker inspect response')
            if len(info) != 1 or object_value(info[0]['State'])['Running'] is not True:
                raise OSError('container is not running')
            info = info[0]
            container = required_text(info['Id'])
            if container.startswith('-'):
                raise ValueError('invalid inspected container ID')
            result['runtime_id'] = container
            if mode == 'docker-image' and info['Image'] != required_text(d['image_id']):
                raise ValueError('image identity mismatch')
            container_ready = True
        files = d['files']
        if not isinstance(files, list) or not files:
            raise ValueError('at least one source file required')
        observed = []
        for row in files:
            row = object_value(row)
            host = absolute(row['host'])
            visible = absolute(row['visible']) if mode == 'local' else container_path(row['visible'])
            checked_bytes(str(host), row['sha256'])
            if mode == 'local' and _fs.canonical_path(host) != _fs.canonical_path(visible):
                raise ValueError('local mode requires the same physical host/visible file')
            if mode != 'local':
                mount = covering_mount(info['Mounts'], str(visible))
                if mode == 'docker-image' and mount:
                    raise ValueError('image file shadowed by mount')
                if mode == 'docker-bind':
                    if not mount or mount['Type'] != 'bind':
                        raise ValueError('visible file is not bind-mounted')
                    try:
                        mount_source = _fs.canonical_path(absolute(mount['Source']), strict=_fs.WINDOWS)
                    except ValueError as exc:
                        if _fs.WINDOWS and isinstance(mount['Source'], str) and mount['Source'].startswith('/'):
                            raise OSError('Docker mount source has no verified native Windows mapping') from exc
                        raise
                    mapped = _fs.canonical_path(mount_source / visible.relative_to(mount['Destination']), strict=_fs.WINDOWS)
                    if not mapped.is_relative_to(mount_source):
                        raise ValueError('bind mapping escapes mount source')
                    resolved_host = _fs.canonical_path(host)
                    if mapped != resolved_host or _fs.identity(mapped) != _fs.identity(resolved_host):
                        raise ValueError('bind source does not match host file')
            actual = hashlib.sha256(visible_bytes(str(visible), container)).hexdigest()
            if actual != row['sha256']:
                raise ValueError('visible candidate hash mismatch')
            observed.append({'host': str(host), 'visible': str(visible), 'sha256': actual})
        result.update(source_status='verified', files=observed)
    except (KeyError, TypeError, ValueError) as exc:
        result.update(source_status='mismatch', source_reason=str(exc))
    except (OSError, subprocess.SubprocessError) as exc:
        result['source_reason'] = str(exc)
    try:
        if not container_ready:
            raise OSError('container identity/running check failed; process not inspected')
        expected = object_value(d['process'])
        profile = expected.get('profile', 'linux')
        if profile not in ('linux', 'darwin', 'windows'):
            raise ValueError('unrecognized process profile')
        if container and profile != 'linux':
            raise ValueError('Docker processes require the Linux profile')
        fields = _process_fields(expected, profile)
        if container:
            actual = read_process(expected['pid'], container)
        elif profile == _local_profile():
            actual = read_local_process(expected['pid'])
        else:
            raise OSError(f'{profile} process inspection is unavailable on this host')
        result['process_status'] = ('verified' if all(actual[field] == expected[field] for field in fields)
                                    else 'mismatch')
        result['process'] = ({key: value for key, value in actual.items() if key != 'argv'}
                             if profile == 'darwin' and result['process_status'] != 'verified'
                             else actual)
    except (KeyError, TypeError, ValueError) as exc:
        result.update(process_status='mismatch', process_reason=str(exc))
    except (OSError, subprocess.SubprocessError) as exc:
        result['process_reason'] = str(exc)
    return result


def summarize(d):
    result = {'candidate': d.get('candidate'), 'outcome': 'fail', 'records': [], 'errors': []}
    try:
        candidate = required_text(d['candidate'])
        if not isinstance(d['notes'], list):
            raise ValueError('notes must be an array of absolute paths')
        notes = {_fs.canonical_path(absolute(path)) for path in d['notes']}
        note_ids = set()
        for path in notes:
            try:
                note_ids.add(_fs.identity(path))
            except FileNotFoundError:
                continue  # A mutable note may not have been created yet.
        records = d['records']
        if not isinstance(records, list) or not records:
            raise ValueError('nonempty structured records required')
        for row in records:
            row = object_value(row)
            errors = []
            if row['candidate'] != candidate:
                errors.append('wrong candidate')
            if row['outcome'] != 'pass' or type(row['exit']) is not int or row['exit'] != 0:
                errors.append('outcome/exit is not pass/0')
            if not isinstance(row['evidence'], list) or not row['evidence']:
                errors.append('missing sealed evidence')
            else:
                for evidence in row['evidence']:
                    try:
                        evidence = object_value(evidence)
                        path = _fs.canonical_path(absolute(evidence['path']), strict=True)
                        if path in notes or _fs.identity(path) in note_ids:
                            raise ValueError('mutable note also listed as sealed evidence')
                        if not checked_bytes(str(path), evidence['sha256']):
                            raise ValueError('empty sealed evidence: ' + str(path))
                    except (KeyError, TypeError, ValueError, OSError) as exc:
                        errors.append(str(exc))
            result['records'].append({'candidate': row['candidate'], 'outcome': row['outcome'],
                                      'exit': row['exit'], 'errors': errors})
        if not any(row['errors'] for row in result['records']):
            result['outcome'] = 'pass'
    except (KeyError, TypeError, ValueError, OSError) as exc:
        result['errors'].append(str(exc))
    return result


def main():
    _fs.configure_stdio_utf8()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['fixture-plan', 'fixture', 'preflight', 'summary'])
    parser.add_argument('input', type=Path, help='JSON contract; absolute artifact paths')
    args = parser.parse_args()
    try:
        d = json.loads(args.input.read_text(encoding='utf-8'))
        if not isinstance(d, dict):
            raise ValueError('input must be an object')
        result = {'fixture-plan': lambda data: fixture(data, prepare=True),
                  'fixture': fixture, 'preflight': preflight, 'summary': summarize}[args.operation](d)
    except (ValueError, OSError, TypeError) as exc:
        result = {'outcome': 'invalid', 'reason': str(exc)}
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0 if result['outcome'] in ('pass', 'ready') else 1


if __name__ == '__main__':
    raise SystemExit(main())
