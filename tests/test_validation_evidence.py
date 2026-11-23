#!/usr/bin/env python3
"""Behavior checks for the bounded artifact adapters and evidence gate."""
import importlib.util
import ctypes as C
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evidence_test_support import assert_darwin_identity, link_directory, link_file

SCRIPT = Path(__file__).resolve().parents[1] / 'plugins/pstack/skills/poteto-mode/scripts/validation-evidence.py'


class CliPackagingTests(unittest.TestCase):
    def test_plugin_exposes_expected_commands(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--help'],
                                capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        for operation in ('fixture-plan', 'fixture', 'preflight', 'summary'):
            self.assertIn(operation, result.stdout)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('validation_evidence', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        parent = Path(os.environ.get('PSTACK_EVIDENCE_TEST_ROOT',
                                     Path.home() / '.local/state/pstack-evidence-tests')).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def put(self, name, content):
        path = self.root / name
        path.write_text(content, encoding='utf-8')
        return str(path)

    def fixture(self):
        source = self.put('routes', 'normal:confirm -> confirm.tpl')
        template = self.put('confirm.tpl', '<slot>{{field}}</slot>')
        outputs = {name: self.put(name, '<slot>' + value + '</slot>') for name, value in
                   [('target', 'safe'), ('positive', 'PRIVATE'), ('benign', 'ordinary')]}
        return {'adapter': 'literal-files-v1', 'candidate': 'c1',
                'route': 'normal:confirm', 'template': template,
                'source': {'path': source, 'sha256': self.m.sha_file(source),
                           'binding': 'normal:confirm -> confirm.tpl'},
                'template_sha256': self.m.sha_file(template), 'slot_literal': '{{field}}',
                'supported_routes': {'normal:confirm': template},
                'extract': {'start': '<slot>', 'end': '</slot>'},
                'canary': 'PRIVATE', 'benign_expected': 'ordinary',
                'outputs': outputs}

    def test_fixture_reads_sources_and_controls(self):
        f = self.fixture()
        self.assertEqual(self.m.fixture(f)['outcome'], 'pass')
        for mutate in [lambda d: d.update(route='embedded:confirm'),
                       lambda d: d.update(supported_routes=True),
                       lambda d: d.update(template_sha256='0' * 64),
                       lambda d: Path(d['outputs']['target']).write_text('<slot> </slot>'),
                       lambda d: Path(d['outputs']['positive']).write_text('<slot>no</slot>'),
                       lambda d: Path(d['outputs']['benign']).write_text('<slot>PRIVATE</slot>'),
                       lambda d: Path(d['template']).write_text('no field')]:
            f = self.fixture()
            mutate(f)
            self.assertNotEqual(self.m.fixture(f)['outcome'], 'pass')

    def test_fixture_preparation_checks_source_before_outputs_exist(self):
        d = self.fixture()
        del d['outputs']
        self.assertEqual(self.m.fixture(d, prepare=True)['outcome'], 'ready')
        self.assertEqual(self.m.fixture(d)['outcome'], 'uncovered')
        d['route'] = 'unsupported'
        self.assertEqual(self.m.fixture(d, prepare=True)['outcome'], 'uncovered')

    def test_proc_parser_uses_field_22_after_final_parenthesis(self):
        # Fields 3..21, followed by starttime (22), then misleading field 23.
        raw = '42 (worker (with) spaces)) ' + ' '.join(['S'] + ['0'] * 18 + ['12345', '999'])
        self.assertEqual(self.m.parse_stat(raw), {'pid': 42, 'comm': 'worker (with) spaces)', 'start_ticks': 12345, 'state': 'S'})

    def local_preflight(self):
        path = self.put('candidate', 'candidate bytes')
        proc = self.m.read_local_process(os.getpid())
        return {'source_mode': 'local', 'candidate': 'c1', 'files': [
            {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}], 'process': proc}

    def docker_preflight(self):
        path = self.put('candidate', 'candidate bytes')
        return {'source_mode': 'docker-bind', 'candidate': 'c1', 'files': [
            {'host': path, 'visible': '/app/candidate', 'sha256': self.m.sha_file(path)}],
            'process': {'pid': 42, 'start_ticks': 123, 'boot_id': 'guest-boot', 'argv': ['worker']}}

    def test_preflight_checks_exact_identity_and_hashes(self):
        d = self.local_preflight()
        result = self.m.preflight(d)
        self.assertEqual(result['source_status'], 'verified')
        self.assertEqual(result['process_status'], 'verified', result)
        self.assertEqual(result['loaded_candidate'], 'unknown')
        fields = {'linux': [('argv', ['grep', 'worker']), ('start_ticks', -1), ('boot_id', 'wrong-boot')],
                  'darwin': [('argv', ['grep', 'worker']), ('start_usec', -1), ('boot_session_uuid', 'wrong-boot')],
                  'windows': [('command_line', 'grep worker'), ('creation_filetime', 123), ('creation_filetime', '1')]}
        for key, value in fields[d['process'].get('profile', 'linux')]:
            d = self.local_preflight()
            d['process'][key] = value
            self.assertEqual(self.m.preflight(d)['process_status'], 'mismatch')
        d = self.local_preflight()
        d['files'][0]['sha256'] = '0' * 64
        self.assertEqual(self.m.preflight(d)['source_status'], 'mismatch')

    def test_preflight_rejects_unknown_process_profiles(self):
        path = self.put('profile-source', 'candidate bytes')
        proc = {'pid': 42, 'start_ticks': 123, 'argv': ['worker'], 'boot_id': 'boot'}
        request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
            {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
            'process': {**proc, 'profile': 'unrecognized'}}
        with patch.object(self.m, 'read_process', return_value=proc):
            self.assertEqual(self.m.preflight(request)['process_status'], 'mismatch')

    def test_docker_guest_paths_do_not_use_host_path_flavor(self):
        with patch.object(self.m, 'Path', PureWindowsPath), patch.object(self.m, 'docker', return_value=b'guest') as docker:
            self.assertEqual(self.m.visible_bytes('/proc/42/stat', 'guest-id'), b'guest')
        docker.assert_called_once_with('guest-id', 'exec', 'cat', '--', '/proc/42/stat')

    def test_darwin_procargs_parser_discards_environment_and_preserves_empty_argument(self):
        # XNU aligns executable_path= plus the saved path including its NUL.
        record = (3).to_bytes(4, sys.byteorder) + b'/bin/worker\0\0\0\0\0other-name\0x=y\0\0HARMLESS_ENV=marker\0'
        self.assertEqual(self.m._darwin_argv(record, 8), ['other-name', 'x=y', ''])
        with self.assertRaises(OSError):
            self.m._darwin_argv(record[:12], 8)

    def test_darwin_empty_first_argument_never_consumes_environment(self):
        path = self.put('darwin source', 'candidate bytes')
        boot = 'deadbeef-0000-1000-8000-000000000000'
        record = (2).to_bytes(4, sys.byteorder) + b'/bin/worker\0\0\0\0\0\0second\0HARMLESS_ENV=marker\0'

        class BsdInfo(C.Structure):
            _fields_ = [(name, C.c_uint64) for name in
                        ('flags', 'status', 'pid', 'start_sec', 'start_usec')]

        def proc_info(pid, _kind, _arg, destination, size):
            C.memmove(destination, C.byref(BsdInfo(0x10, 1, pid, 123, 456)), size)
            return size

        def sysctlbyname(name, destination, _size, _new, _new_size):
            data = (4096).to_bytes(4, sys.byteorder) if name == b'kern.argmax' else boot.encode() + b'\0'
            C.memmove(destination, data, len(data))
            return 0

        def sysctl(_mib, _length, destination, size, _new, _new_size):
            C.memmove(destination, record, len(record))
            size._obj.value = len(record)
            return 0

        request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
            {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
            'process': {'profile': 'darwin', 'pid': 42, 'boot_session_uuid': boot,
                        'start_sec': 123, 'start_usec': 456, 'argv': ['', 'second']}}
        api = SimpleNamespace(BsdInfo=BsdInfo, proc_info=proc_info, sysctl=sysctl, sysctlbyname=sysctlbyname)
        with patch.object(self.m, '_darwin_api', return_value=api), patch.object(
                self.m, '_local_profile', return_value='darwin'):
            result = self.m.preflight(request)
            self.assertNotIn('HARMLESS_ENV', json.dumps(result))
            self.assertEqual('verified', result['process_status'], result)
            request['process']['argv'] = ['wrong', 'second']
            result = self.m.preflight(request)
            self.assertEqual('mismatch', result['process_status'], result)
            self.assertNotIn('argv', result['process'])
            self.assertNotIn('HARMLESS_ENV', json.dumps(result))

    def test_darwin_mismatch_does_not_disclose_rewritten_stack_arguments(self):
        path = self.put('rewritten source', 'candidate bytes')
        expected = {'profile': 'darwin', 'pid': 42, 'boot_session_uuid': 'boot',
                    'start_sec': 123, 'start_usec': 456, 'argv': ['worker', 'arg']}
        observed = {**expected, 'argv': ['rewritten title', 'HARMLESS_ENV=marker']}
        request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
            {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
            'process': expected}
        with patch.object(self.m, '_local_profile', return_value='darwin'), patch.object(
                self.m, 'read_local_process', return_value=observed):
            result = self.m.preflight(request)
        self.assertEqual('mismatch', result['process_status'])
        self.assertNotIn('argv', result['process'])
        self.assertNotIn('HARMLESS_ENV', json.dumps(result))
        self.assertEqual(42, result['process']['pid'])
        self.assertEqual('unknown', result['loaded_candidate'])

    def test_windows_waitable_process_ignores_undefined_exit_time(self):
        class FileTime(C.Structure):
            _fields_ = [('dwLowDateTime', C.c_uint32), ('dwHighDateTime', C.c_uint32)]

        def times(_handle, creation, exit_time, _kernel, _user):
            creation._obj.dwHighDateTime = 1 << 28
            creation._obj.dwLowDateTime = 42
            exit_time._obj.dwHighDateTime = 99
            return True

        for states, expected in [([258, 258], 'verified'), ([258, 0], 'unknown')]:
            with self.subTest(states=states):
                waits = iter(states)
                closed = []
                api = SimpleNamespace(FileTime=FileTime, open=lambda *_: 123,
                                      wait=lambda *_: next(waits), times=times, close=closed.append)
                path = self.put('windows source', 'candidate bytes')
                request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
                    {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
                    'process': {'profile': 'windows', 'pid': 42, 'creation_filetime': str((1 << 60) + 42),
                                'command_line': 'worker "two words"'}}
                with patch.object(self.m, '_windows_api', return_value=api), patch.object(
                        self.m, '_local_profile', return_value='windows'), patch.object(
                        self.m, '_windows_command_line', return_value='worker "two words"'):
                    result = self.m.preflight(request)
                self.assertEqual(expected, result['process_status'], result)
                self.assertEqual([123], closed)

    def test_windows_process_without_wait_access_is_unknown(self):
        path = self.put('windows source', 'candidate bytes')
        request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
            {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
            'process': {'profile': 'windows', 'pid': 42, 'creation_filetime': '0',
                        'command_line': 'worker'}}
        from ctypes import wintypes
        api = SimpleNamespace(FileTime=wintypes.FILETIME, times=lambda *_: True, close=lambda _: None,
                              open=lambda access, *_: 0 if access & 0x100000 else 123)
        with patch.object(self.m, '_windows_api', return_value=api), patch.object(
                self.m, '_local_profile', return_value='windows'), patch.object(
                C, 'get_last_error', return_value=5, create=True), patch.object(
                self.m, '_windows_command_line', return_value='worker'):
            result = self.m.preflight(request)
        self.assertEqual('unknown', result['process_status'], result)
        self.assertNotIn('process', result)

    def test_native_preflight_observes_live_child_and_rejects_stale_identity(self):
        path = self.put('native source', 'candidate bytes')
        argv = [sys.executable, '-c', 'import sys; print("ready", flush=True); sys.stdin.read()',
                '名前 with spaces', 'quote"and\\slash', '']
        earliest = time.time_ns()
        with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as child:
            try:
                latest = time.time_ns()
                self.assertEqual(child.stdout.readline().rstrip(), b'ready')
                proc = self.m.read_local_process(child.pid)
                request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
                    {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
                    'process': proc.copy()}
                self.assertEqual(proc['pid'], child.pid)
                if sys.platform == 'win32':
                    self.assertEqual(proc['command_line'], subprocess.list2cmdline(argv))
                    self.assertTrue(proc['creation_filetime'].isdecimal())
                    key = 'creation_filetime'
                    wrong = str(int(proc[key]) + 1)
                else:
                    self.assertEqual(proc['argv'], argv)
                    if sys.platform == 'darwin':
                        assert_darwin_identity(proc, earliest, latest)
                    key = 'start_sec' if sys.platform == 'darwin' else 'start_ticks'
                    wrong = proc[key] + 1
                result = self.m.preflight(request)
                self.assertEqual(result['source_status'], 'verified', result)
                self.assertEqual(result['process_status'], 'verified', result)
                self.assertEqual(result['loaded_candidate'], 'unknown')
                request['process'][key] = wrong
                self.assertEqual(self.m.preflight(request)['process_status'], 'mismatch')
                request['process'] = proc
            finally:
                child.kill()
                child.wait(timeout=10)
            stale = self.m.preflight(request)
            self.assertEqual(stale['process_status'], 'unknown', stale)

    @unittest.skipUnless(sys.platform == 'darwin', 'native Darwin exec and KERN_PROCARGS2')
    def test_native_darwin_empty_first_argument_preflight(self):
        path = self.put('native source', 'candidate bytes')
        argv = ['', '60']
        earliest = time.time_ns()
        with subprocess.Popen(argv, executable='/bin/sleep',
                              env={**os.environ, 'HARMLESS_ENV': 'darwin-argv-fixture'}) as child:
            try:
                latest = time.time_ns()
                process = self.m.read_local_process(child.pid)
                assert_darwin_identity(process, earliest, latest)
                self.assertEqual(argv, process['argv'])
                request = {'source_mode': 'local', 'candidate': 'c1', 'files': [
                    {'host': path, 'visible': path, 'sha256': self.m.sha_file(path)}],
                    'process': {**process, 'argv': ['mismatch', '60']}}
                checked = self.m.preflight(request)
                self.assertEqual('mismatch', checked['process_status'], checked)
                self.assertNotIn('argv', checked['process'])
                self.assertNotIn('HARMLESS_ENV', json.dumps(checked))
            finally:
                child.kill()

    def test_preflight_unknowns_do_not_pass(self):
        d = self.local_preflight()
        d['source_mode'] = 'branch'
        self.assertEqual(self.m.preflight(d)['source_status'], 'unsupported')
        d['source_mode'] = 'local'
        with patch.object(self.m, 'read_local_process', side_effect=FileNotFoundError('gone')):
            self.assertEqual(self.m.preflight(d)['process_status'], 'unknown')
        d['source_mode'] = 'docker-image'
        d['container'] = 'absent'
        d['image_id'] = 'sha256:absent'
        with patch.object(self.m.subprocess, 'run', side_effect=FileNotFoundError('docker')):
            self.assertEqual(self.m.preflight(d)['source_status'], 'unknown')

    def index(self):
        raw = self.put('both-green.log', 'raw failure bytes')
        note = self.put('plan.md', 'mutable')
        return {'candidate': 'c1', 'notes': [note], 'records': [
            {'candidate': 'c1', 'outcome': 'pass', 'exit': 0,
             'evidence': [{'path': raw, 'sha256': self.m.sha_file(raw)}]}]}

    def test_index_uses_structured_records_and_seals_only_evidence(self):
        d = self.index()
        self.assertEqual(self.m.summarize(d)['outcome'], 'pass')
        Path(d['notes'][0]).write_text('updated')
        self.assertEqual(self.m.summarize(d)['outcome'], 'pass')
        for key, value in [('exit', 2), ('candidate', 'c2'), ('outcome', 'uncovered')]:
            d = self.index()
            d['records'][0][key] = value
            self.assertNotEqual(self.m.summarize(d)['outcome'], 'pass')
        d = self.index()
        Path(d['records'][0]['evidence'][0]['path']).unlink()
        self.assertNotEqual(self.m.summarize(d)['outcome'], 'pass')
        d = self.index()
        Path(d['records'][0]['evidence'][0]['path']).write_text('changed raw')
        self.assertNotEqual(self.m.summarize(d)['outcome'], 'pass')
        d = self.index()
        d['records'][0]['evidence'] = []
        self.assertNotEqual(self.m.summarize(d)['outcome'], 'pass')
        d = self.index()
        d['notes'] = [d['records'][0]['evidence'][0]['path']]
        self.assertNotEqual(self.m.summarize(d)['outcome'], 'pass')

    def test_binary_evidence_is_sealable_without_decoding(self):
        d = self.index()
        raw = Path(d['records'][0]['evidence'][0]['path'])
        raw.write_bytes(b'\xff\x00raw')
        d['records'][0]['evidence'][0]['sha256'] = self.m.sha_file(raw)
        self.assertEqual(self.m.summarize(d)['outcome'], 'pass')
        self.assertEqual(raw.read_bytes(), b'\xff\x00raw')

    def test_malformed_proc_is_unknown_not_a_crash(self):
        d = self.docker_preflight()
        d['source_mode'] = 'local'
        with patch.object(self.m, '_local_profile', return_value='linux'), \
             patch.object(self.m, 'visible_bytes', return_value=b'42 (bad) S'):
            self.assertEqual(self.m.preflight(d)['process_status'], 'unknown')

    def test_docker_bind_and_image_modes_and_safe_argv(self):
        d = self.docker_preflight()
        host = d['files'][0]['host']
        d.update(source_mode='docker-bind', container='runtime')
        d['files'][0]['visible'] = '/app/candidate'
        info = [{'Id': 'container-id', 'Image': 'sha256:image', 'State': {'Running': True},
                 'Mounts': [{'Type': 'bind', 'Source': str(self.root), 'Destination': '/app'}]}]
        proc = d['process']
        with patch.object(self.m, 'docker', return_value=json.dumps(info).encode()), \
             patch.object(self.m, 'visible_bytes', return_value=Path(host).read_bytes()), \
             patch.object(self.m, 'read_process', return_value=proc):
            self.assertEqual(self.m.preflight(d)['source_status'], 'verified')
            d['source_mode'] = 'docker-image'
            d['image_id'] = 'sha256:image'
            self.assertEqual(self.m.preflight(d)['source_status'], 'mismatch')
            info[0]['Mounts'] = []
        with patch.object(self.m, 'docker', return_value=json.dumps(info).encode()), \
             patch.object(self.m, 'visible_bytes', return_value=Path(host).read_bytes()), \
             patch.object(self.m, 'read_process', return_value=proc):
            self.assertEqual(self.m.preflight(d)['source_status'], 'verified')
            d['image_id'] = 'sha256:wrong'
            self.assertEqual(self.m.preflight(d)['source_status'], 'mismatch')
        with patch.object(self.m.subprocess, 'run') as run:
            self.m.visible_bytes('/app/name;echo secret', 'runtime')
            self.assertEqual(run.call_args.args[0],
                             ['docker', 'exec', 'runtime', 'cat', '--', '/app/name;echo secret'])

    def test_invalid_fixture_and_missing_control_stay_uncovered(self):
        for change in [lambda d: d.update(adapter='arbitrary-shell'),
                       lambda d: d['source'].update(binding='missing -> confirm.tpl'),
                       lambda d: d['outputs'].pop('positive'),
                       lambda d: Path(d['outputs']['target']).write_text('404'),
                       lambda d: Path(d['outputs']['target']).write_text('<slot>x</slot><slot>y</slot>')]:
            d = self.fixture()
            change(d)
            self.assertEqual(self.m.fixture(d)['outcome'], 'uncovered')
        d = self.fixture()
        Path(d['outputs']['target']).write_text('<slot>PRIVATE</slot>')
        self.assertEqual(self.m.fixture(d)['outcome'], 'fail')

    def test_cli_fixture_plan_and_unknown_preflight(self):
        d = self.fixture()
        del d['outputs']
        manifest = self.put('cli.json', json.dumps(d))
        result = subprocess.run([sys.executable, str(SCRIPT), 'fixture-plan', manifest],
                                capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['outcome'], 'ready')
        Path(manifest).write_text(json.dumps({'source_mode': 'unsupported'}))
        result = subprocess.run([sys.executable, str(SCRIPT), 'preflight', manifest],
                                capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['source_status'], 'unsupported')

    def test_cli_invalid_input_and_nonzero_result(self):
        manifest = self.put('input.json', json.dumps(self.index()))
        completed = subprocess.run([sys.executable, str(SCRIPT), 'summary', manifest], capture_output=True, encoding='utf-8')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        d = self.index()
        d['records'][0]['exit'] = 2
        Path(manifest).write_text(json.dumps(d))
        completed = subprocess.run([sys.executable, str(SCRIPT), 'summary', manifest], capture_output=True, encoding='utf-8')
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout)['outcome'], 'fail')
        Path(manifest).write_text('{')
        completed = subprocess.run([sys.executable, str(SCRIPT), 'summary', manifest], capture_output=True, encoding='utf-8')
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout)['outcome'], 'invalid')


    def cli(self, operation, data, env=None):
        manifest = self.put('regression.json', json.dumps(data, ensure_ascii=False))
        completed = subprocess.run([sys.executable, '-B', str(SCRIPT), operation, manifest],
                                   capture_output=True, env=env)
        self.assertEqual(completed.stderr, b'')
        return completed.returncode, json.loads(completed.stdout)

    def test_fixture_rejects_same_symlink_and_hardlink_captures(self):
        for alias in ('same', 'symlink', 'hardlink'):
            with self.subTest(alias=alias):
                d = self.fixture()
                benign = Path(d['outputs']['benign'])
                target = Path(d['outputs']['target'])
                target.unlink()
                if alias == 'same':
                    d['outputs']['target'] = str(benign)
                elif alias == 'symlink':
                    link_file(self, target, benign)
                else:
                    os.link(benign, target)
                rc, result = self.cli('fixture', d)
                self.assertEqual(rc, 1)
                self.assertEqual(result['outcome'], 'uncovered')
                target.unlink(missing_ok=True)

    def test_fixture_rejects_ambiguous_and_invalid_routes(self):
        for route, lines in [('normal:confirm', 'normal:confirm -> wrong.tpl\nnormal:confirm -> confirm.tpl'),
                             ('normal:confirm', 'normal:confirm -> confirm.tpl\nnormal:confirm -> confirm.tpl'),
                             ('  ', '   -> confirm.tpl'),
                             (' normal:confirm', ' normal:confirm -> confirm.tpl'),
                             ('a -> b', 'a -> b -> confirm.tpl')]:
            with self.subTest(route=route, lines=lines):
                d = self.fixture()
                d.update(route=route, supported_routes={route: d['template']})
                Path(d['source']['path']).write_text(lines, encoding='utf-8')
                d['source'].update(sha256=self.m.sha_file(d['source']['path']),
                                   binding=route + ' -> confirm.tpl')
                for operation in ('fixture-plan', 'fixture'):
                    self.assertEqual(self.cli(operation, d)[0], 1)

    def test_fixture_template_must_be_physical_sibling_of_resolved_source(self):
        d = self.fixture()
        outside = self.root / 'outside'
        outside.mkdir()
        real = outside / 'confirm.tpl'
        Path(d['template']).rename(real)
        link_file(self, Path(d['template']), real)
        self.assertEqual(self.cli('fixture-plan', d)[0], 1)
        # A source symlink with the real template beside the real source is valid.
        real_source = outside / 'routes'
        Path(d['source']['path']).rename(real_source)
        link_file(self, Path(d['source']['path']), real_source)
        d.update(template=str(real), supported_routes={d['route']: str(real)})
        self.assertEqual(self.cli('fixture-plan', d)[0], 0)

    def test_fixture_rejects_escapable_canary(self):
        d = self.fixture()
        d['canary'] = 'CANARY_<SECRET>'
        Path(d['outputs']['positive']).write_text('<slot>CANARY_<SECRET></slot>', encoding='utf-8')
        Path(d['outputs']['target']).write_text('<slot>CANARY_&lt;SECRET&gt;</slot>', encoding='utf-8')
        self.assertEqual(self.cli('fixture', d)[0], 1)

    def test_fixture_reads_utf8_in_c_locale(self):
        d = self.fixture()
        Path(d['outputs']['target']).write_text('<slot>安全な出力</slot>', encoding='utf-8')
        Path(d['outputs']['positive']).write_text('<slot>秘密_PRIVATE</slot>', encoding='utf-8')
        Path(d['outputs']['benign']).write_text('<slot>通常の出力</slot>', encoding='utf-8')
        d['benign_expected'] = '通常の出力'
        rc, result = self.cli('fixture', d, dict(os.environ, LC_ALL='C', LANG='C', PYTHONUTF8='0'))
        self.assertEqual(rc, 0)
        self.assertEqual(result['outcome'], 'pass')

    def test_summary_rejects_empty_bytes_and_malformed_schema(self):
        for mutation in ('empty', 'notes-string', 'notes-object', 'row', 'evidence'):
            with self.subTest(mutation=mutation):
                d = self.index()
                if mutation == 'empty':
                    ev = d['records'][0]['evidence'][0]
                    Path(ev['path']).write_bytes(b'')
                    ev['sha256'] = self.m.sha_file(ev['path'])
                elif mutation.startswith('notes'):
                    d['notes'] = '/' if mutation == 'notes-string' else {'/': True}
                elif mutation == 'row':
                    d['records'] = ['invalid']
                else:
                    d['records'][0]['evidence'] = ['invalid']
                rc, result = self.cli('summary', d)
                self.assertEqual(rc, 1)
                self.assertEqual(result['outcome'], 'fail')

    def test_docker_paths_are_canonical_and_runtime_is_pinned(self):
        # Fixed subprocess responses exercise CLI argument construction, not live Docker.
        d = self.docker_preflight()
        host = d['files'][0]['host']
        proc = d['process']
        info = {'Id': 'immutable-id', 'Image': 'sha256:image', 'State': {'Running': True},
                'Mounts': [{'Type': 'bind', 'Source': str(self.root), 'Destination': '/app/.'}]}
        d.update(source_mode='docker-bind', container='mutable-name')
        d['files'][0]['visible'] = '/tmp/../app/candidate'
        def run(argv, **kwargs):
            from types import SimpleNamespace
            if argv[1] == 'inspect':
                return SimpleNamespace(stdout=json.dumps([info]).encode())
            self.assertEqual(argv[2], 'immutable-id')
            path = argv[-1]
            if path.endswith('/stat'):
                data = (f"{proc['pid']} (worker) " + ' '.join(['S'] + ['0'] * 18 +
                        [str(proc['start_ticks'])])).encode()
            elif path.endswith('/cmdline'):
                data = b'\0'.join(x.encode() for x in proc['argv']) + b'\0'
            elif path.endswith('/boot_id'):
                data = proc['boot_id'].encode()
            else:
                self.assertEqual(path, '/app/candidate')
                data = Path(host).read_bytes()
            return SimpleNamespace(stdout=data)
        with patch.object(self.m.subprocess, 'run', side_effect=run) as mocked:
            result = self.m.preflight(d)
            self.assertEqual(result['source_status'], 'verified')
            self.assertEqual(result['process_status'], 'verified')
            self.assertEqual(result['loaded_candidate'], 'unknown')
            self.assertEqual(result['outcome'], 'uncovered')
            self.assertEqual(mocked.call_args_list[0].args[0],
                             ['docker', 'inspect', '--type', 'container', '--', 'mutable-name'])

    def test_docker_dot_segments_cannot_bypass_mounts(self):
        for mode, visible, mounts in [
                ('docker-image', '/tmp/../app/candidate', [{'Type': 'bind', 'Source': str(self.root), 'Destination': '/app'}]),
                ('docker-bind', '/app/../etc/candidate', [{'Type': 'bind', 'Source': str(self.root), 'Destination': '/app'}]),
                ('docker-bind', '/app/other/../shadowed/candidate', [
                    {'Type': 'bind', 'Source': str(self.root), 'Destination': '/app'},
                    {'Type': 'tmpfs', 'Source': '', 'Destination': '/app/shadowed'}])]:
            with self.subTest(mode=mode, visible=visible):
                d = self.docker_preflight()
                d.update(source_mode=mode, container='mutable', image_id='sha256:image')
                d['files'][0]['visible'] = visible
                if mode == 'docker-bind':
                    app = self.root / 'app'
                    app.mkdir(exist_ok=True)
                    mounts[0]['Source'] = str(app)
                    host = (self.root / 'etc/candidate' if '/etc/' in visible else app / 'shadowed/candidate')
                    host.parent.mkdir(exist_ok=True)
                    host.write_bytes(b'candidate bytes')
                    d['files'][0]['host'] = str(host)
                proc = d['process']
                info = [{'Id': 'id', 'Image': 'sha256:image', 'State': {'Running': True}, 'Mounts': mounts}]
                with patch.object(self.m, 'docker', return_value=json.dumps(info).encode()), \
                     patch.object(self.m, 'visible_bytes', return_value=b'candidate bytes'), \
                     patch.object(self.m, 'read_process', return_value=proc):
                    self.assertNotEqual(self.m.preflight(d)['source_status'], 'verified')

    def test_wrong_image_or_invalid_inspect_never_reads_process(self):
        for change in ({'Image': 'wrong'}, {'State': {'Running': False}}, {'Id': ''}, {'State': {'Running': 'yes'}}):
            with self.subTest(change=change):
                d = self.docker_preflight()
                d.update(source_mode='docker-image', container='name', image_id='sha256:image')
                info = {'Id': 'id', 'Image': 'sha256:image', 'State': {'Running': True}, 'Mounts': []}
                info.update(change)
                with patch.object(self.m, 'docker', return_value=json.dumps([info]).encode()), \
                     patch.object(self.m, 'read_process') as read:
                    result = self.m.preflight(d)
                    self.assertNotEqual(result['process_status'], 'verified')
                    read.assert_not_called()

    def test_process_rejects_dead_or_empty_cmdline_preserves_empty_argument(self):
        def stat(state):
            return ('42 (worker) ' + ' '.join([state] + ['0'] * 18 + ['12345'])).encode()
        for state, cmd in [('Z', b''), ('X', b'worker\0'), ('x', b'worker\0'), ('S', b'')]:
            with self.subTest(state=state, cmd=cmd):
                with patch.object(self.m, 'visible_bytes', side_effect=[stat(state), cmd, stat(state), b'boot']):
                    with self.assertRaises(OSError):
                        self.m.read_process(42)
        with patch.object(self.m, 'visible_bytes', side_effect=[stat('S'), b'worker\0\0', stat('R'), b'boot']):
            self.assertEqual(self.m.read_process(42)['argv'], ['worker', ''])

    def test_summary_does_not_ignore_unresolvable_note(self):
        d = self.index()
        loop = self.root / 'loop'
        link_file(self, loop, loop)
        d['notes'] = [str(loop)]
        rc, result = self.cli('summary', d)
        self.assertEqual(rc, 1)
        self.assertTrue(result['errors'])

    def test_malformed_nested_contracts_return_structured_nonpass(self):
        for key in ('source', 'extract', 'outputs', 'supported_routes'):
            with self.subTest(operation='fixture', key=key):
                d = self.fixture()
                d[key] = []
                rc, result = self.cli('fixture', d)
                self.assertEqual(rc, 1)
                self.assertEqual(result['outcome'], 'uncovered')
        for key, value in [('files', [None]), ('files', {}), ('process', [])]:
            with self.subTest(operation='preflight', key=key):
                d = self.local_preflight()
                d[key] = value
                rc, result = self.cli('preflight', d)
                self.assertEqual(rc, 1)
                self.assertEqual(result['loaded_candidate'], 'unknown')
                self.assertEqual(result['source_status' if key == 'files' else 'process_status'], 'mismatch')
        for key, value in [('notes', None), ('records', {}), ('records', [None])]:
            with self.subTest(operation='summary', key=key):
                d = self.index()
                d[key] = value
                self.assertEqual(self.cli('summary', d)[0], 1)

    def test_mount_destinations_normalize_and_bind_mapping_stays_inside_source(self):
        mount = {'Type': 'tmpfs', 'Source': '', 'Destination': '/app/other/../shadowed'}
        self.assertEqual(self.m.covering_mount([mount], '/app/shadowed/file')['Destination'], '/app/shadowed')
        d = self.docker_preflight()
        host = d['files'][0]['host']
        bound = self.root / 'bound'
        bound.mkdir()
        link_directory(bound / 'escape', self.root)
        d.update(source_mode='docker-bind', container='name')
        d['files'][0]['visible'] = '/app/escape/candidate'
        info = [{'Id': 'id', 'State': {'Running': True}, 'Mounts': [
            {'Type': 'bind', 'Source': str(bound), 'Destination': '/app'}]}]
        with patch.object(self.m, 'docker', return_value=json.dumps(info).encode()), \
             patch.object(self.m, 'visible_bytes', return_value=Path(host).read_bytes()), \
             patch.object(self.m, 'read_process', return_value={}):
            d['process'] = {}  # The source containment result is independent of process identity.
            self.assertEqual(self.m.preflight(d)['source_status'], 'mismatch')


if __name__ == '__main__':
    unittest.main()
