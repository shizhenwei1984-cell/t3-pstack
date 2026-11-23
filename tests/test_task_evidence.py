from contextlib import nullcontext
import copy
import ctypes as C
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error


from evidence_test_support import WINDOWS, expected_mode, link_directory, link_file, remove_tree

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'plugins/pstack/skills/poteto-mode/scripts/task_evidence.py'
GUARD_SCRIPT = SCRIPT.with_name('guarded_document.py')
FS_SCRIPT = SCRIPT.with_name('evidence_fs.py')


class CliPackagingTests(unittest.TestCase):
    def test_plugin_exposes_expected_commands(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--help'],
                                capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        for operation in ('preserve', 'check', 'render', 'publication'):
            self.assertIn(operation, result.stdout)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global evidence
        spec = importlib.util.spec_from_file_location('task_evidence', SCRIPT)
        evidence = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = evidence
        spec.loader.exec_module(evidence)

    def setUp(self):
        parent = Path(os.environ.get('PSTACK_EVIDENCE_TEST_ROOT',
                                     Path.home() / '.local/state/pstack-evidence-tests')).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.durable = Path(tempfile.mkdtemp(prefix='owned-', dir=parent))
        self.addCleanup(remove_tree, self.durable)
        self.source = Path(tempfile.mkdtemp(prefix='pstack-source-')).resolve()
        self.addCleanup(lambda: shutil.rmtree(self.source, ignore_errors=True))
        (self.source / 'worker-a').mkdir()
        (self.source / 'worker-b').mkdir()
        self.sentinel = self.durable / 'must-not-execute'
        self.candidate_bytes = b'def records(scope): return {"scope": scope, "rows": [1, 2]}\n'
        self.candidate_sha = evidence.digest(self.candidate_bytes)
        self.request = {
            'schema': 'pstack-evidence/1', 'task_id': 'task-1', 'owner': 'owner',
            'retention': {'owner': 'owner', 'durable_root': str(self.durable), 'cleanup_after': None},
            'actors': [{'id': 'owner', 'role': 'owner'}, {'id': 'author', 'role': 'author'},
                       {'id': 'verifier', 'role': 'verifier'}, {'id': 'reviewer', 'role': 'reviewer'}],
            'candidates': [{'id': 'fixed', 'sha256': self.candidate_sha, 'author': 'author', 'artifact': 'candidate-source'}],
            'resources': [{'id': 'runtime', 'owner': 'owner', 'generation': 'start-1', 'environment': 'env-1',
                           'observed_at': '2026-11-17T00:00:00Z', 'expires_at': '2026-11-18T00:00:00Z'}],
            'artifacts': [], 'records': [], 'cases': [], 'reviews': [], 'notes': [],
            'review_inventory': {'owner': 'owner', 'revision': 'r1', 'items': [
                {'id': 'entry-review', 'candidate': 'fixed', 'subject': 'diff', 'description': 'Inspect entry parameter binding'}]},
        }
        self.artifact('raw', 'raw', b'{"scope":"public","rows":[1,2]}\n', 'worker-a')
        self.artifact('stderr', 'raw', b'', 'worker-a')
        self.artifact('environment', 'environment', b'Python stdlib; in-process fixture\n', 'worker-b')
        self.artifact('diff', 'diff', b'- internal scope\n+ public scope\n', 'worker-b')
        self.artifact('recorder', 'recorder', b'{"proposed_producer":"future recorder"}', 'worker-b')
        self.artifact('candidate-source', 'source', self.candidate_bytes, 'worker-a')
        self.request['records'] = [self.record()]
        self.request['cases'] = [{
            'id': 'fixed-public', 'candidate': 'fixed', 'scenario': 'public', 'scenario_sha256': 'b' * 64,
            'entry': 'GET /records/public', 'expected': {'kind': 'json_equal', 'value': {'scope': 'public', 'rows': [1, 2]}},
            'actual': {'kind': 'artifact', 'artifact': 'raw', 'format': 'json'}, 'records': ['run-1']}]
        self.request['reviews'] = [self.review()]

    def artifact(self, ident, kind, data, worker='worker-a'):
        path = self.source / worker / ident
        path.write_bytes(data)
        self.request['artifacts'].append({'id': ident, 'kind': kind, 'state': 'available',
                                         'source': {'path': str(path), 'host': 'local'},
                                         'sha256': evidence.digest(data), 'media_type': 'application/octet-stream'})
        return path

    def record(self):
        return {'id': 'run-1', 'candidate': 'fixed', 'observer': 'author',
                'observed_at': '2026-11-17T00:00:03Z', 'expires_at': '2026-11-18T00:00:00Z',
                'resource': 'runtime', 'resource_owner': 'owner', 'resource_generation': 'start-1', 'environment': 'env-1',
                'evidence_type': 'executed', 'declared_outcome': 'pass', 'rechecks': None, 'limitation': None,
                'artifacts': ['raw', 'stderr', 'environment', 'diff', 'recorder'],
                'command': {'argv': [sys.executable, '-c', 'open(' + repr(str(self.sentinel)) + ',"w").write("unsafe")'],
                            'cwd': str(self.source), 'exit_code': 0, 'started_at': '2026-11-17T00:00:01Z',
                            'finished_at': '2026-11-17T00:00:02Z', 'execution_id': 'execution-1'},
                'harness': {'description': 'In-process observation', 'substitutions': [
                    {'component': 'database', 'replacement': 'fixed rows', 'impact': 'real persistence unverified'}],
                    'boundaries': ['No socket or proxy exercised']},
                'producer': {'name': 'opaque proposed recorder example', 'artifact': 'recorder'}}

    def review(self):
        return {'item': 'entry-review', 'reviewer': 'reviewer', 'candidate_sha256': self.candidate_sha,
                'subject_sha256': next(a['sha256'] for a in self.request['artifacts'] if a['id'] == 'diff'),
                'inventory_sha256': evidence.inventory_digest(self.request['review_inventory']),
                'disposition': 'accept', 'reason': 'The route binds scope before querying.', 'evidence': ['diff'], 'limitation': None}

    def cli(self, *args, expected=0, script=SCRIPT, syntax_error=False, env=None):
        argv = [sys.executable, str(script), *map(str, args)]
        result = subprocess.run(argv, capture_output=True, encoding='utf-8',
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', **(env or {})})
        if os.environ.get('PSTACK_EVIDENCE_CLI_LOG'):
            with open(os.environ['PSTACK_EVIDENCE_CLI_LOG'], 'a') as stream:
                stream.write(json.dumps({'command': argv, 'exit': result.returncode, 'stdout': result.stdout,
                                         'stderr': result.stderr, 'limitations': 'Synthetic evidence declarations; stored argv never executed'}) + '\n')
        self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
        if syntax_error:
            self.assertIn('must be supplied together', result.stderr)
            self.assertEqual('', result.stdout)
            return
        self.assertEqual('', result.stderr)
        return json.loads(result.stdout)

    def preserve(self, expected=0):
        path = self.durable / 'import.json'
        path.write_text(json.dumps(self.request))
        return self.cli('preserve', '--input', path, '--store', self.durable / 'archive', expected=expected)

    def snapshot(self):
        result = self.preserve()
        return evidence.Snapshot.read(result['snapshot'], result['snapshot_sha256'])

    def check_cli(self, snapshot, context=None, expected=0):
        args = ['check', '--snapshot', snapshot.path, '--sha256', snapshot.sha256]
        if context is not None:
            path = self.durable / 'context.json'
            path.write_text(json.dumps(context))
            args.extend(['--context', path])
        return self.cli(*args, expected=expected)

    def context(self, behavior=True):
        path = self.durable / 'current.json'
        raw = self.durable / 'current.raw'
        raw.write_bytes(b'Independent fresh verifier capture: rows 1,2\n')
        observation = {'schema': 'pstack-current-observation/1', 'candidate': {'id': 'fixed', 'sha256': self.candidate_sha},
                       'observer': 'verifier', 'observed_at': '2026-11-17T01:00:00Z',
                       'resource': {**self.request['resources'][0], 'observed_at': '2026-11-17T01:00:00Z'},
                       'evidence_type': 'independent_recheck' if behavior else 'environment_snapshot',
                       'execution_id': 'verifier-execution' if behavior else None, 'rechecks': 'run-1' if behavior else None,
                       'raw': {'path': str(raw), 'sha256': evidence.digest(raw.read_bytes())},
                       'producer': 'independent fixture observation', 'limitations': []}
        path.write_bytes(evidence.canonical(observation))
        context = {'schema': 'pstack-reuse/1', 'candidate': observation['candidate'], 'observer': 'verifier',
                   'purpose': 'independent_behavior' if behavior else 'navigation', 'checked_at': '2026-11-17T01:00:01Z',
                   'inventory_sha256': evidence.inventory_digest(self.request['review_inventory']),
                   'observations': [{'path': str(path), 'sha256': evidence.digest(path.read_bytes())}]}
        return context, observation, path

    def change_observation(self, context, observation, path):
        path.write_bytes(evidence.canonical(observation))
        context['observations'][0]['sha256'] = evidence.digest(path.read_bytes())

    def codes(self, result):
        return {f['code'] for f in result['findings']}

    def render(self, snapshot, links=None, name='render'):
        args = ['render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256, '--out', self.durable / name]
        if links is not None:
            path = self.durable / 'links.json'
            path.write_text(json.dumps(links))
            args += ['--links', path]
        return self.cli(*args)

    def test_cli_render_proposal_explicit_merge_and_old_replays_preserve_human_edits(self):
        snapshot = self.snapshot()
        state, target = self.durable / 'document-state', self.durable / 'reviewed.md'

        def render_proposal(snapshot, name, **kwargs):
            return self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                            '--out', self.durable / name, '--document-state', state,
                            '--target', target, '--document-owner', 'owner', **kwargs)

        def promote(proposal, operation, *extra, expected=0):
            return self.cli('promote', '--state', state, '--target', target,
                            '--proposal', proposal['proposal_id'], '--operation-id', operation,
                            '--expect-target', proposal['observed_target']['sha256'],
                            '--expect-draft', proposal['new_generated'], '--single-writer',
                            *extra, expected=expected, script=GUARD_SCRIPT)

        first = render_proposal(snapshot, 'first-render')
        self.assertFalse(target.exists())
        proposal = first['proposal']
        metadata = json.loads(Path(first['render']).read_bytes())
        self.assertEqual(snapshot.sha256, metadata['snapshot_sha256'])
        self.assertEqual({'schema': 'pstack-generated-source/1',
                          'generator': {'id': 'task-evidence-renderer', 'version': '1',
                                        'sha256': evidence.digest(SCRIPT.read_bytes())},
                          'inputs': [{'id': 'snapshot', 'sha256': snapshot.sha256}],
                          'render_id': evidence.digest(Path(first['render']).read_bytes())},
                         proposal['source'])
        self.assertEqual(first['render_sha256'], proposal['source']['render_id'])
        draft = Path(proposal['proposal_dir']) / 'draft.md'
        self.assertEqual(metadata['files']['summary'], evidence.digest(draft.read_bytes()))
        self.assertEqual('new', proposal['classification'])
        immutable = self.render(snapshot, name='default-render')
        self.assertNotIn('proposal', immutable)
        for name in ('render.json', 'summary.md', 'cases.md'):
            self.assertEqual((self.durable / 'first-render' / name).read_bytes(),
                             (self.durable / 'default-render' / name).read_bytes())
        self.assertEqual('committed', promote(proposal, 'first', '--decision', 'replace')['outcome'])
        target.chmod(0o640)
        human = target.read_bytes() + b'\nHuman review: keep this explanation.\n'
        target.write_bytes(human)
        self.request['cases'][0]['scenario'] = 'public-followup'
        next_snapshot = self.snapshot()
        before = target.stat()
        second = render_proposal(next_snapshot, 'second-render')
        next_proposal = second['proposal']
        self.assertEqual(human, target.read_bytes())
        self.assertEqual((before.st_ino, before.st_mtime_ns),
                         (target.stat().st_ino, target.stat().st_mtime_ns))
        self.assertEqual('reviewed_change', next_proposal['classification'])
        self.assertEqual([{'id': 'snapshot', 'sha256': next_snapshot.sha256}], next_proposal['source']['inputs'])
        retained = Path(next_proposal['proposal_dir'])
        self.assertEqual(human, (retained / 'target-before.md').read_bytes())
        self.assertEqual(draft.read_bytes(), (retained / 'generated-before.md').read_bytes())
        self.assertIn(b'-Human review: keep this explanation.', (retained / 'target.diff').read_bytes())
        merged = self.durable / 'manual-merge.md'
        merged.write_bytes((retained / 'draft.md').read_bytes() + b'\nHuman review: keep this explanation.\n')
        merge_args = ('--decision', 'merge', '--merged', merged, '--expect-merged', evidence.digest(merged.read_bytes()))
        promote(next_proposal, 'wrong-merge', '--decision', 'merge', '--merged', merged,
                '--expect-merged', '0' * 64, expected=1)
        self.assertEqual(human, target.read_bytes())
        self.assertEqual('committed', promote(next_proposal, 'manual-merge', *merge_args)['outcome'])
        self.assertEqual(merged.read_bytes(), target.read_bytes())
        self.assertEqual(expected_mode(0o640), target.stat().st_mode & 0o777)
        later = target.read_bytes() + b'\nLater human correction.\n'
        target.write_bytes(later)
        before = target.stat()
        merged.unlink()
        for old, operation, args in ((proposal, 'first', ('--decision', 'replace')),
                                     (next_proposal, 'manual-merge', merge_args)):
            self.assertEqual('already_committed', promote(old, operation, *args)['outcome'])
            self.assertEqual(later, target.read_bytes())
            self.assertEqual((before.st_ino, before.st_mtime_ns),
                             (target.stat().st_ino, target.stat().st_mtime_ns))

    def test_guarded_render_leaves_installed_plugin_tree_unchanged(self):
        snapshot = self.snapshot()
        scripts = self.source / 'plugin/skills/poteto-mode/scripts'
        scripts.mkdir(parents=True)
        for script in (SCRIPT, GUARD_SCRIPT, FS_SCRIPT):
            shutil.copyfile(script, scripts / script.name)
        target = self.durable / 'reviewed.md'
        target.write_text('Previously reviewed text\n')
        result = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                          '--out', self.durable / 'render', '--document-state', self.durable / 'state',
                          '--target', target, '--document-owner', 'owner', script=scripts / SCRIPT.name,
                          env={'PYTHONDONTWRITEBYTECODE': '', 'PYTHONPYCACHEPREFIX': ''})
        self.assertIn('proposal', result)
        self.assertEqual('Previously reviewed text\n', target.read_text(encoding='utf-8'))
        self.assertEqual({SCRIPT.name, GUARD_SCRIPT.name, FS_SCRIPT.name}, {path.name for path in scripts.iterdir()})

    def test_guarded_render_rejects_targets_and_state_in_plugin_roots(self):
        snapshot = self.snapshot()
        plugin = self.durable / 'plugin'
        scripts = plugin / 'skills/poteto-mode/scripts'
        scripts.mkdir(parents=True)
        for script in (SCRIPT, GUARD_SCRIPT, FS_SCRIPT):
            shutil.copyfile(script, scripts / script.name)
        other = self.durable / 'profile/config/plugins/t3-pstack'
        marker = Path('.antigravity-plugin/plugin.json')
        (other / marker).parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT.parents[3] / marker, other / marker)
        for label, state, target in (
            ('target', self.durable / 'state', plugin / 'reviewed.md'),
            ('state', other / 'state', self.durable / 'reviewed.md'),
        ):
            with self.subTest(location=label):
                result = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                                  '--out', self.durable / f'render-{label}', '--document-state', state,
                                  '--target', target, '--document-owner', 'owner',
                                  script=scripts / SCRIPT.name, expected=1)
                self.assertIn('document_guard_error', self.codes(result))
                self.assertFalse(state.exists())
                self.assertFalse(target.with_name(target.name + '.pstack-guard.lock').exists())

    def test_cli_partial_document_options_fail_before_render_or_guard_side_effects(self):
        snapshot = self.snapshot()
        options = [('--document-state', self.durable / 'state'),
                   ('--target', self.durable / 'reviewed.md'), ('--document-owner', 'owner')]
        for mask in range(1, 7):
            output = self.durable / ('partial-' + str(mask))
            args = [part for index, pair in enumerate(options) if mask & (1 << index) for part in pair]
            self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                     '--out', output, *args, expected=2, syntax_error=True)
            self.assertFalse(output.exists())
            self.assertFalse((self.durable / 'state').exists())
            self.assertFalse((self.durable / 'reviewed.md.pstack-guard.lock').exists())
        with self.assertRaises(evidence.EvidenceError):
            evidence.render(snapshot, self.durable / 'api-partial', document_state=self.durable / 'state')
        self.assertFalse((self.durable / 'api-partial').exists())
        self.assertFalse((self.durable / 'state').exists())

    def test_cli_render_rejects_wrong_snapshot_and_document_bindings(self):
        snapshot = self.snapshot()
        state, target = self.durable / 'state', self.durable / 'reviewed.md'
        target.write_bytes(b'Human text\n')

        def render(name, sha=None, **changes):
            options = {'document-state': state, 'target': target, 'document-owner': 'owner', **changes}
            return self.cli('render', '--snapshot', snapshot.path, '--sha256', sha or snapshot.sha256,
                            '--out', self.durable / name,
                            *[part for key, value in options.items() for part in ('--' + key, value)], expected=1)

        self.assertIn('hash_mismatch', self.codes(render('wrong-snapshot', '0' * 64)))
        self.assertFalse((self.durable / 'wrong-snapshot').exists())
        self.assertFalse(state.exists())
        render('empty-owner', **{'document-owner': ' '})
        self.assertFalse((self.durable / 'empty-owner').exists())
        self.assertIn('document_options', self.codes(render('overlap', target=self.durable / 'overlap' / 'summary.md')))
        self.assertFalse((self.durable / 'overlap').exists())
        self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                 '--out', self.durable / 'bound', '--document-state', state,
                 '--target', target, '--document-owner', 'owner')
        before = target.stat()
        for name, changes in [('wrong-owner', {'document-owner': 'another-owner'}),
                              ('wrong-target', {'target': self.durable / 'other.md'}),
                              ('wrong-state', {'document-state': self.durable / 'other-state'})]:
            result = render(name, **changes)
            self.assertEqual('invalid', result['status'])
            self.assertEqual(b'Human text\n', target.read_bytes())
            self.assertEqual((before.st_ino, before.st_mtime_ns),
                             (target.stat().st_ino, target.stat().st_mtime_ns))
        self.assertFalse((self.durable / 'other.md').exists())
        self.assertFalse((self.durable / 'other-state').exists())

    def test_render_api_proposes_without_target_write(self):
        snapshot = self.snapshot()
        target = self.durable / 'reviewed.md'
        target.write_bytes(b'Human text\n')
        rendered = evidence.render(snapshot, self.durable / 'api-render',
                                   document_state=self.durable / 'api-state',
                                   target=target, document_owner='owner')
        self.assertEqual('untracked', rendered['proposal']['classification'])
        self.assertEqual(b'Human text\n', target.read_bytes())
        self.assertEqual(snapshot.sha256, rendered['snapshot_sha256'])

    def test_repair_g1_render_lock_reservations_and_subsequent_correct_use(self):
        snapshot = self.snapshot()
        for guarded in (False, True):
            for descendant in (False, True):
                target = self.durable / ('lock-' + str(guarded) + str(descendant) + '.md')
                state = self.durable / (target.stem + '-state')
                lock = target.with_name(target.name + '.pstack-guard.lock')
                output = lock / 'child' if descendant else lock
                options = ['--document-state', state, '--target', target, '--document-owner', 'owner'] if guarded else []
                with self.subTest(guarded=guarded, descendant=descendant):
                    self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                             '--out', output, *options, expected=1)
                    self.assertFalse(lock.exists())
                    self.assertFalse(state.exists())
                    result = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                                      '--out', self.durable / (target.stem + '-good'), '--document-state', state,
                                      '--target', target, '--document-owner', 'owner')
                    self.assertEqual('proposed', result['proposal']['outcome'])
        state, target = self.durable / 'bound-state', self.durable / 'bound.md'
        self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                 '--out', self.durable / 'bound-render', '--document-state', state,
                 '--target', target, '--document-owner', 'owner')
        other = self.durable / 'other.md'
        result = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                          '--out', self.durable / 'rebind', '--document-state', state,
                          '--target', other, '--document-owner', 'owner', expected=1)
        self.assertIn('document_guard_error', self.codes(result))
        self.assertEqual('proposed', self.cli(
            'render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
            '--out', self.durable / 'correct-other', '--document-state', self.durable / 'other-state',
            '--target', other, '--document-owner', 'owner')['proposal']['outcome'])


    def test_residual_h2_surrogate_output_api_rejects_without_side_effects(self):
        snapshot = self.snapshot()
        for guarded in (False, True):
            for suffix in ('plain', 'reserved', 'ancestor'):
                with self.subTest(guarded=guarded, suffix=suffix):
                    name = '\udcff-output-' + str(guarded) + '-' + suffix + ('.pstack-guard.lock' if suffix != 'plain' else '')
                    output = self.durable / name
                    if suffix == 'ancestor':
                        output /= 'child'
                    options = dict(document_state=self.durable / 'state', target=self.durable / 'target.md',
                                   document_owner='owner') if guarded else {}
                    before = sorted(str(p) for p in self.durable.rglob('*'))
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.render(snapshot, output, **options)
                    self.assertEqual(before, sorted(str(p) for p in self.durable.rglob('*')))

    def test_residual_h2_raw_c_locale_output_errors_are_json_without_writes(self):
        snapshot = self.snapshot()
        for guarded in (False, True):
            for suffix in ('plain', 'reserved', 'ancestor'):
                with self.subTest(guarded=guarded, suffix=suffix):
                    name = '\udcff-output-' + str(guarded) + '-' + suffix + ('.pstack-guard.lock' if suffix != 'plain' else '')
                    output = self.durable / name
                    if suffix == 'ancestor':
                        output /= 'child'
                    args = [sys.executable, '-B', '-P', str(SCRIPT), 'render', '--snapshot', str(snapshot.path),
                            '--sha256', snapshot.sha256, '--out', str(output)]
                    if guarded:
                        args += ['--document-state', str(self.durable / 'state'), '--target',
                                 str(self.durable / 'target.md'), '--document-owner', 'owner']
                    before = sorted(str(p) for p in self.durable.rglob('*'))
                    native_args = args if WINDOWS else [a.encode('utf-8', 'surrogateescape') for a in args]
                    process = subprocess.run(native_args, capture_output=True,
                                             env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
                                                  'LC_ALL': 'C', 'LANG': 'C', 'PYTHONUTF8': '1',
                                                  'PYTHONSAFEPATH': '1'}, timeout=20)
                    self.assertEqual(1, process.returncode)
                    self.assertEqual(b'', process.stderr)
                    self.assertEqual('invalid', json.loads(process.stdout)['status'])
                    self.assertEqual(before, sorted(str(p) for p in self.durable.rglob('*')))

    def test_residual_h2_valid_unicode_output_still_renders(self):
        snapshot = self.snapshot()
        rendered = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                            '--out', self.durable / '渲染輸出 with spaces',
                            env={'LC_ALL': 'C', 'LANG': 'C', 'PYTHONUTF8': '1'})
        self.assertTrue(Path(rendered['render']).is_file())
        for guarded in (False, True):
            options = dict(document_state=self.durable / '狀態', target=self.durable / '審閱.md',
                           document_owner='擁有者') if guarded else {}
            result = evidence.render(snapshot, self.durable / ('輸出-' + str(guarded)), **options)
            self.assertTrue(Path(result['render']).is_file())
            if guarded:
                self.assertEqual('proposed', result['proposal']['outcome'])

    def test_repair_h1_cli_safe_path_and_cached_explicit_sibling(self):
        snapshot = self.snapshot()
        for name, flags, extra_env in (('env', [], {'PYTHONSAFEPATH': '1'}), ('flag', ['-P'], {})):
            argv = [sys.executable, *flags, str(SCRIPT), 'render', '--snapshot', str(snapshot.path),
                    '--sha256', snapshot.sha256, '--out', str(self.durable / (name + '-render')),
                    '--document-state', str(self.durable / (name + '-state')),
                    '--target', str(self.durable / (name + '.md')), '--document-owner', 'owner']
            process = subprocess.run(argv, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', **extra_env},
                                     capture_output=True, encoding='utf-8')
            self.assertEqual(0, process.returncode, process.stdout + process.stderr)
            self.assertEqual('proposed', json.loads(process.stdout)['proposal']['outcome'])
        before = list(sys.path)
        guard = evidence._document_guard()
        self.assertEqual(GUARD_SCRIPT.resolve(), Path(guard.__file__).resolve())
        self.assertIs(guard, evidence._document_guard())
        self.assertEqual(before, sys.path)

    def test_repair_g3_renderer_serializes_malformed_intent_and_owner_as_domain_errors(self):
        snapshot = self.snapshot()
        state, target = self.durable / 'guard-state', self.durable / 'reviewed.md'

        def render(name, owner='owner', expected=0):
            return self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                            '--out', self.durable / name, '--document-state', state,
                            '--target', target, '--document-owner', owner, expected=expected)

        render('initial')
        with self.subTest(record='owner'):
            self.assertIn('document_guard_error', self.codes(render('wrong-owner', 'wrong', 1)))
        operation = state / 'operations' / evidence.digest(b'malformed')
        operation.mkdir()
        (operation / 'intent.json').write_bytes(b'{}')
        (operation / 'request.json').write_bytes(b'{}')
        with self.subTest(record='intent'):
            self.assertIn('document_guard_error', self.codes(render('malformed', expected=1)))
        self.assertFalse(target.exists())

    def test_repair_guarded_invalid_outputs_preserve_preflight_and_allow_correct_use(self):
        snapshot = self.snapshot()
        real = self.durable / 'real-parent'
        real.mkdir()
        alias = self.durable / 'alias-parent'
        link_directory(alias, real)
        dangling = self.durable / 'dangling'
        link_file(self, dangling, self.durable / 'missing')
        existing = self.durable / 'existing'
        existing.mkdir()
        ordinary_file = self.durable / 'ordinary-file'
        ordinary_file.write_bytes(b'Human data')
        before_file = ordinary_file.stat()
        for number, output in enumerate((alias / 'nested/out', dangling, existing, ordinary_file / 'out', Path('relative-output'))):
            with self.subTest(output=str(output)):
                state, target = self.durable / ('state-' + str(number)), self.durable / ('target-' + str(number) + '.md')
                before = sorted(str(p.relative_to(self.durable)) for p in self.durable.rglob('*'))
                self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256, '--out', output,
                         '--document-state', state, '--target', target, '--document-owner', 'owner', expected=1)
                self.assertEqual(before, sorted(str(p.relative_to(self.durable)) for p in self.durable.rglob('*')))
                self.assertEqual('proposed', self.cli(
                    'render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                    '--out', self.durable / ('good-render-' + str(number)), '--document-state', state,
                    '--target', target, '--document-owner', 'owner')['proposal']['outcome'])
        self.assertEqual(b'Human data', ordinary_file.read_bytes())
        self.assertEqual((before_file.st_ino, before_file.st_mode), (ordinary_file.stat().st_ino, ordinary_file.stat().st_mode))

    def test_repair_guarded_historical_render_and_no_link_publication(self):
        self.historical()
        snapshot = self.snapshot()
        result = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256,
                          '--out', self.durable / 'guarded-historical', '--document-state', self.durable / 'state',
                          '--target', self.durable / 'reviewed.md', '--document-owner', 'owner')
        self.assertEqual('proposed', result['proposal']['outcome'])
        publication = self.cli('publication', '--render', result['render'], '--sha256', result['render_sha256'])
        self.assertEqual('checked_no_links', publication['links'])
        self.assertEqual('valid', publication['status'])
        self.assertIn('Archive consistency: valid', Path(result['render']).with_name('summary.md').read_text(encoding='utf-8'))

    def test_cli_retains_cross_directory_bytes_after_only_originals_removed(self):
        expected = {a['id']: Path(a['source']['path']).read_bytes() for a in self.request['artifacts']}
        snapshot = self.snapshot()
        shutil.rmtree(self.source)
        result = self.check_cli(snapshot)
        self.assertEqual('valid', result['archive_integrity'])
        self.assertEqual('unknown', result['reuse'])
        self.assertIn('original_removed', self.codes(result))
        for ident, data in expected.items():
            self.assertEqual(data, snapshot.artifact_bytes(ident))
        stored = snapshot.data['records'][0]
        self.assertEqual(self.request['records'][0]['command'], stored['command'])
        self.assertEqual(self.request['records'][0]['harness'], stored['harness'])
        self.assertEqual(self.request['records'][0]['producer'], stored['producer'])
        rendered = self.render(snapshot)
        published = self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'])
        self.assertEqual('checked_no_links', published['links'])
        self.assertFalse(self.sentinel.exists())

    def test_hash_source_and_preserved_loss_are_distinct(self):
        path = Path(self.request['artifacts'][0]['source']['path'])
        path.unlink()
        self.assertIn('missing_source', self.codes(self.preserve(expected=1)))
        path.write_bytes(b'changed bytes')
        self.assertIn('hash_mismatch', self.codes(self.preserve(expected=1)))
        path.write_bytes(b'{"scope":"public","rows":[1,2]}\n')
        snapshot = self.snapshot()
        (snapshot.path.parents[2] / 'objects' / evidence.digest(path.read_bytes())).unlink()
        result = self.check_cli(snapshot, expected=1)
        self.assertIn('missing_preserved', self.codes(result))
        self.assertNotIn('missing_original', self.codes(result))

    def test_expected_snapshot_hash_is_mandatory_and_rechecked(self):
        snapshot = self.snapshot()
        with self.assertRaises(evidence.EvidenceError):
            evidence.Snapshot(snapshot.path, snapshot.sha256, b'forged cached bytes')
        changed_view = snapshot.data
        changed_view['candidates'][0]['sha256'] = 'f' * 64
        self.assertEqual(self.candidate_sha, snapshot.data['candidates'][0]['sha256'])
        self.cli('check', '--snapshot', snapshot.path, '--sha256', 'f' * 64, expected=1)
        snapshot.path.write_bytes(snapshot.path.read_bytes() + b' ')
        with self.assertRaises(evidence.EvidenceError):
            evidence.check(snapshot)

    def test_production_rejects_temp_installed_and_escape_roots(self):
        for root in (self.source, SCRIPT.parents[3], self.durable / 'declared-only'):
            with self.subTest(root=root):
                self.request['retention']['durable_root'] = str(root)
                result = self.preserve(expected=1)
                self.assertIn('retention_invalid', self.codes(result))
        self.request['retention']['durable_root'] = str(self.source)
        path = self.durable / 'import.json'
        path.write_text(json.dumps(self.request))
        result = self.cli('preserve', '--input', path, '--store', self.source / 'store', expected=1)
        self.assertIn('retention_invalid', self.codes(result))
        self.request['retention']['durable_root'] = str(self.durable)
        link_directory((self.durable / 'archive'), self.source)
        self.assertIn('retention_invalid', self.codes(self.preserve(expected=1)))
        project_skill = self.durable / 'project/.agents/skills/demo'
        project_skill.mkdir(parents=True)
        (project_skill / 'SKILL.md').write_text('---\nname: demo\n---\n')
        path = self.durable / 'import.json'
        for skill_root in (project_skill, project_skill / 'evidence'):
            with self.subTest(skill_root=skill_root):
                self.request['retention']['durable_root'] = str(skill_root)
                path.write_text(json.dumps(self.request))
                result = self.cli('preserve', '--input', path, '--store', skill_root / 'store', expected=1)
                self.assertIn('retention_invalid', self.codes(result))

    def test_rejects_t3_installations_and_configured_skill_roots(self):
        bundle = SCRIPT.parents[3]
        runtime_copy = self.durable / 'runtime-copy'
        script_copy = runtime_copy / SCRIPT.relative_to(bundle)
        script_copy.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, script_copy)
        shutil.copyfile(FS_SCRIPT, script_copy.with_name(FS_SCRIPT.name))
        codex_home = self.durable / 'codex-home'
        claude_home = self.durable / 'claude-home'
        kiro_home = self.durable / 'kiro-home'
        config = {'CODEX_HOME': str(codex_home), 'CLAUDE_CONFIG_DIR': str(claude_home),
                  'KIRO_HOME': str(kiro_home)}
        linked_skills = self.durable / 'linked-skills'
        linked_skills.mkdir()
        codex_home.mkdir()
        link_directory((codex_home / 'skills'), linked_skills)
        installations = {
            'codex': codex_home / 'plugins/cache/t3-pstack/t3-pstack/2.6.2-explore.3',
            'claude': claude_home / 'plugins/cache/t3-pstack/t3-pstack/2.6.2-explore.3',
            'antigravity': self.durable / '.t3/userdata/providers/antigravity/profile/config/plugins/t3-pstack',
        }
        for host, root in [*installations.items(), ('claude', kiro_home / 't3-pstack')]:
            marker = Path(f'.{host}-plugin/plugin.json')
            (root / marker).parent.mkdir(parents=True)
            shutil.copyfile(bundle / marker, root / marker)

        request = self.durable / 'import.json'
        for root in (runtime_copy, *installations.values(), kiro_home / 't3-pstack',
                     linked_skills, claude_home / 'skills', kiro_home / 'skills'):
            with self.subTest(root=root):
                root.mkdir(parents=True, exist_ok=True)
                self.request['retention']['durable_root'] = str(root)
                request.write_text(json.dumps(self.request))
                store = root / 'archive'
                result = self.cli('preserve', '--input', request, '--store', store,
                                  expected=1, script=script_copy, env=config)
                self.assertIn('retention_invalid', self.codes(result))
                self.assertFalse(store.exists())

        root = self.durable / 'project/config/plugins/archive-data'
        root.mkdir(parents=True)
        self.request['retention']['durable_root'] = str(root)
        request.write_text(json.dumps(self.request))
        result = self.cli('preserve', '--input', request, '--store', root / 'archive',
                          script=script_copy, env=config)
        self.assertEqual('preserved', result['status'])

    def test_no_note_alias_by_path_or_inode(self):
        raw = Path(self.request['artifacts'][0]['source']['path'])
        alias = self.source / 'mutable-note'
        os.link(raw, alias)
        for note in (str(raw), str(alias)):
            self.request['notes'] = [note]
            self.assertIn('note_alias', self.codes(self.preserve(expected=1)))

    def test_remote_and_nonregular_sources_never_fall_back(self):
        self.request['artifacts'][0]['source']['host'] = 'other-host'
        self.assertIn('remote_source_unavailable', self.codes(self.preserve(expected=1)))
        self.request['artifacts'][0]['source']['host'] = 'local'
        raw = Path(self.request['artifacts'][0]['source']['path'])
        raw.unlink()
        if WINDOWS:
            raw.mkdir()
        else:
            os.mkfifo(raw)
        self.assertIn('unsupported_file', self.codes(self.preserve(expected=1)))

    def test_snapshot_is_stable_idempotent_and_store_owner_is_fixed(self):
        first = self.preserve()
        self.request['artifacts'].reverse()
        second = self.preserve()
        self.assertEqual(first['snapshot_sha256'], second['snapshot_sha256'])
        self.request['task_id'] = 'another-task'
        self.assertIn('owner_mismatch', self.codes(self.preserve(expected=1)))

    def test_current_independent_observation_is_hash_bound(self):
        snapshot = self.snapshot()
        context, _, path = self.context()
        result = self.check_cli(snapshot, context)
        self.assertEqual('valid', result['reuse'])
        self.assertEqual('declarations_only', result['execution'])
        path.write_bytes(path.read_bytes() + b' ')
        self.assertIn('hash_mismatch', self.codes(self.check_cli(snapshot, context, expected=1)))

    def test_current_capture_missing_or_changed_is_invalid(self):
        snapshot = self.snapshot()
        context, observation, _ = self.context()
        Path(observation['raw']['path']).write_bytes(b'wrong')
        self.assertIn('hash_mismatch', self.codes(self.check_cli(snapshot, context, expected=1)))
        Path(observation['raw']['path']).unlink()
        self.assertIn('missing_source', self.codes(self.check_cli(snapshot, context, expected=1)))

    def test_wrong_candidate_owner_generation_and_expiry_remain_distinct(self):
        snapshot = self.snapshot()
        for field, value, expected in [('owner', 'author', 'owner_mismatch'), ('generation', 'restart-2', 'environment_stale'),
                                       ('environment', 'env-2', 'environment_stale'), ('expires_at', '2026-11-17T01:00:00.5Z', 'expired')]:
            with self.subTest(field=field):
                context, observation, path = self.context()
                observation['resource'][field] = value
                self.change_observation(context, observation, path)
                self.assertIn(expected, self.codes(self.check_cli(snapshot, context, expected=1)))
        context, _, _ = self.context()
        context['candidate']['sha256'] = 'c' * 64
        self.assertIn('candidate_mismatch', self.codes(self.check_cli(snapshot, context, expected=1)))
        context, _, _ = self.context()
        context['checked_at'] = '2026-11-18T01:00:00Z'
        self.assertIn('expired', self.codes(self.check_cli(snapshot, context, expected=1)))

    def test_record_owner_and_generation_are_checked_per_record(self):
        self.request['records'][0]['resource_owner'] = 'author'
        self.request['records'][0]['resource_generation'] = 'old-start'
        snapshot = self.snapshot()
        context, _, _ = self.context()
        result = self.check_cli(snapshot, context, expected=1)
        self.assertTrue({'owner_mismatch', 'environment_stale'} <= self.codes(result))

    def test_old_environment_and_same_observer_do_not_establish_recheck(self):
        snapshot = self.snapshot()
        context, observation, path = self.context(False)
        context['purpose'] = 'behavior'
        self.assertIn('independence_unverified', self.codes(self.check_cli(snapshot, context, expected=1)))
        context['purpose'] = 'navigation'
        observation['observed_at'] = '2026-11-17T00:00:03Z'
        observation['resource']['observed_at'] = observation['observed_at']
        self.change_observation(context, observation, path)
        self.assertIn('environment_unknown', self.codes(self.check_cli(snapshot, context, expected=1)))
        context, observation, path = self.context()
        context['observer'] = observation['observer'] = 'author'
        self.change_observation(context, observation, path)
        self.assertIn('independence_unverified', self.codes(self.check_cli(snapshot, context, expected=1)))

    def historical(self):
        self.artifact('secondary', 'report', b'Historical report: original raw unavailable; database substituted.')
        self.request['artifacts'][0] = {k: v for k, v in self.request['artifacts'][0].items() if k != 'media_type'}
        self.request['artifacts'][0].update(state='missing', missing_reason='Original temp directory was cleaned')
        record = self.request['records'][0]
        record.update(evidence_type='historical_secondary', limitation='Original raw missing; narrative retained; database substitution reported')
        record['artifacts'].append('secondary')
        record['command']['execution_id'] = None
        self.request['cases'][0]['actual'] = {'kind': 'unverified', 'reason': 'Historical report only; original raw is missing'}

    def test_historical_report_retained_without_claiming_new_execution(self):
        self.historical()
        snapshot = self.snapshot()
        result = self.check_cli(snapshot)
        self.assertEqual('valid', result['archive_integrity'])
        self.assertIn('missing_original', self.codes(result))
        context, _, _ = self.context()
        self.assertIn('historical_only', self.codes(self.check_cli(snapshot, context, expected=1)))
        rendered = self.render(snapshot)
        text = (Path(rendered['render']).parent / 'summary.md').read_text(encoding='utf-8')
        self.assertIn('historical', text)
        self.assertIn('unverified', text)
        report = next(a for a in snapshot.data['artifacts'] if a['id'] == 'secondary')
        (snapshot.path.parents[2] / 'objects' / report['sha256']).unlink()
        result = self.check_cli(snapshot, expected=1)
        self.assertTrue({'missing_original', 'missing_preserved'} <= self.codes(result))

    def test_historical_cannot_supply_measured_actual_or_new_execution(self):
        self.historical()
        self.request['records'][0]['command']['execution_id'] = 'invented-new-run'
        self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))
        self.request['records'][0]['command']['execution_id'] = None
        self.request['cases'][0]['actual'] = {'kind': 'artifact', 'artifact': 'secondary', 'format': 'utf8'}
        self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))

    def test_environment_snapshot_is_never_behavior_proof(self):
        record = self.request['records'][0]
        record.update(evidence_type='environment_snapshot', declared_outcome='unknown')
        record['artifacts'] = ['environment']
        record['producer']['artifact'] = None
        self.request['cases'][0]['actual'] = {'kind': 'unverified', 'reason': 'Only environment navigation collected'}
        snapshot = self.snapshot()
        context, _, _ = self.context()
        self.assertIn('behavior_unverified', self.codes(self.check_cli(snapshot, context, expected=1)))

    def test_independent_archived_recheck_requires_new_identity_and_capture(self):
        record = copy.deepcopy(self.request['records'][0])
        record.update(id='recheck', observer='verifier', evidence_type='independent_recheck', rechecks='run-1')
        record['command']['execution_id'] = 'verifier-run'
        self.request['records'].append(record)
        self.assertIn('independence_unverified', self.codes(self.preserve(expected=1)))
        self.artifact('rechecked-raw', 'raw', b'{"rows":[1,2],"scope":"public"}\n')
        record['artifacts'] = ['rechecked-raw', 'environment']
        record['producer']['artifact'] = None
        self.preserve()

    def test_missing_review_fields_inventory_and_subject_are_rejected(self):
        for field in ('reason', 'evidence', 'subject_sha256'):
            with self.subTest(field=field):
                original = self.request['reviews'][0].pop(field)
                self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))
                self.request['reviews'][0][field] = original
        for field in ('candidate_sha256', 'subject_sha256', 'inventory_sha256'):
            with self.subTest(field=field):
                original = self.request['reviews'][0][field]
                self.request['reviews'][0][field] = 'f' * 64
                self.assertIn('review_subject_mismatch', self.codes(self.check_cli(self.snapshot(), expected=1)))
                self.request['reviews'][0][field] = original
        self.request['reviews'] = []
        self.assertIn('review_missing', self.codes(self.check_cli(self.snapshot(), expected=1)))

    def test_review_evidence_and_disposition_cannot_be_resolved_by_wellformedness(self):
        self.request['reviews'][0]['evidence'] = []
        self.assertIn('review_evidence_missing', self.codes(self.check_cli(self.snapshot(), expected=1)))
        self.request['reviews'][0]['evidence'] = ['diff']
        for disposition in ('defer', 'change', 'reject'):
            self.request['reviews'][0]['disposition'] = disposition
            self.assertIn('review_unresolved', self.codes(self.check_cli(self.snapshot(), expected=1)))

    def test_multilingual_verdict_lint_has_no_minimum_length(self):
        for reason in ('PASS', ' Ｐ Ａ Ｓ Ｓ。 ', 'P\u200bASS', '[PASS!]', '**retain**', 'ok', 'lgtm',
                       '通過', '「通過。」', '（保留）', '合格', '承認', '好', '沒問題', '没问题', '', '\u200b'):
            with self.subTest(reason=reason):
                self.request['reviews'][0]['reason'] = reason
                self.assertIn('review_reason_invalid', self.codes(self.check_cli(self.snapshot(), expected=1)))
        for reason in ('路徑先綁定再查詢', '空输入返回空表', '境界で型検証済み', '경계값 검증 완료', 'No raw URL', 'Route binds first.'):
            with self.subTest(reason=reason):
                self.request['reviews'][0]['reason'] = reason
                self.assertEqual('valid', self.check_cli(self.snapshot())['review_readiness'])

    def test_inventory_revision_cannot_inherit_previous_review(self):
        self.request['review_inventory']['revision'] = 'r2'
        self.request['review_inventory']['items'].append({'id': 'new-obligation', 'candidate': 'fixed', 'subject': 'diff', 'description': 'New requirement'})
        result = self.check_cli(self.snapshot(), expected=1)
        self.assertTrue({'review_missing', 'review_subject_mismatch'} <= self.codes(result))

    def test_schema_unknown_duplicate_and_malformed_types_fail_cli(self):
        for key, value in [('schema', 'future/99'), ('cases', []), ('candidates', self.request['candidates'] * 2)]:
            with self.subTest(key=key):
                original = self.request[key]
                self.request[key] = value
                self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))
                self.request[key] = original
        self.request['records'][0]['command']['exit_code'] = True
        self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))
        self.request['records'][0]['command']['exit_code'] = 0
        path = self.durable / 'duplicate.json'
        path.write_text('{"schema":"a","schema":"b"}')
        self.assertIn('schema_invalid', self.codes(self.cli('preserve', '--input', path, '--store', self.durable / 'archive', expected=1)))
        self.request['covered'] = True
        self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))

    def test_render_is_same_source_deterministic_safe_and_fresh(self):
        self.request['cases'][0]['entry'] = '[bad](file:///home/author/raw) <script>x</script> https://private.invalid/raw\n| inject'
        snapshot = self.snapshot()
        first = self.render(snapshot)
        second = self.render(snapshot, name='render-again')
        self.assertEqual(first['render_sha256'], second['render_sha256'])
        directory = Path(first['render']).parent
        for name in ('summary', 'cases'):
            raw = (directory / (name + '.md')).read_text(encoding='utf-8')
            self.assertNotIn('<script>', raw)
            self.assertNotIn('file://', raw)
            self.assertNotIn('https://private', raw)
            self.assertNotIn('\n| inject', raw)
            self.assertIn('fixed', raw)
            self.assertIn('persistence unverified', raw)
        self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256, '--out', directory, expected=1)
        self.assertFalse(self.sentinel.exists())

    def test_render_preserves_a_competing_file(self):
        snapshot = self.snapshot()
        output = self.durable / 'contested-render'
        owner, method = (evidence._fs, 'ensure_directory') if WINDOWS else (Path, 'mkdir')
        mkdir = getattr(owner, method)

        def competing_file(path, *args, **kwargs):
            mkdir(path, *args, **kwargs)
            if path == output:
                (output / 'summary.md').write_bytes(b'other writer')

        with patch.object(owner, method, competing_file):
            with self.assertRaises(evidence.EvidenceError):
                evidence.render(snapshot, output)
        self.assertEqual((output / 'summary.md').read_bytes(), b'other writer')
        self.assertFalse((output / 'render.json').exists())

    def test_publication_rechecks_both_exact_rendered_files(self):
        snapshot = self.snapshot()
        for name in ('summary', 'cases'):
            rendered = self.render(snapshot, name='render-' + name)
            (Path(rendered['render']).parent / (name + '.md')).write_text('Changed [raw](file:///tmp/raw)')
            self.assertIn('hash_mismatch', self.codes(self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'], expected=1)))

    def test_read_only_archive_checks_owner_without_requiring_a_writable_volume(self):
        snapshot = self.snapshot()
        rendered = self.render(snapshot)
        fs = evidence._fs
        good_check = evidence.check(snapshot)
        native_owned_directory = fs.owned_directory
        dacl = 2

        def get_security(_handle, _kind, _flags, owner, _group, acl, _sacl, descriptor):
            owner._obj.value = 1
            acl._obj.value = dacl
            descriptor._obj.value = 3
            return 0

        def volume(_handle, _label, _length, _serial, _component, flags, name, _name_length):
            flags._obj.value = 8 | 0x80000
            name.value = 'NTFS'
            return True

        def owned_directory(path):
            if WINDOWS:
                return native_owned_directory(path)
            # Model a readable Windows directory while exercising real archive reads on this host.
            api = SimpleNamespace(get_security=get_security, equal_sid=lambda owner, user: owner.value == user,
                                  free=lambda _: None, DWORD=C.c_uint32, volume=volume)
            with patch.object(fs, 'WINDOWS', True), patch.object(fs, '_win', return_value=api), patch.object(
                    fs, '_handle', return_value=nullcontext(42)), patch.object(fs, '_win_info'), patch.object(
                    fs, '_token_sid', return_value=nullcontext(1)):
                return native_owned_directory(path)

        volume_probe = patch.object(fs._win(), 'volume', volume) if WINDOWS else nullcontext()
        with patch.object(fs, 'owned_directory', owned_directory), volume_probe:
            self.assertEqual(evidence.check(snapshot), good_check)
            self.assertEqual(evidence.publication(rendered['render'], rendered['render_sha256'])['status'], 'valid')
            if WINDOWS:
                with self.assertRaises(fs.CapabilityError):
                    evidence.preserve(self.request, snapshot.path.parents[2])
            else:
                dacl = None
                with self.assertRaises(evidence.EvidenceError):
                    evidence.check(snapshot)

    def link(self, item='raw', url=None, audience='public-anonymous'):
        return {'schema': 'pstack-links/1', 'audience': audience,
                'links': [{'item': item, 'url': url or 'https://raw.githubusercontent.com/owner/repo/' + '1' * 40 + '/raw.json'}]}

    def test_publication_offline_status_and_expected_remote_content(self):
        snapshot = self.snapshot()
        rendered = self.render(snapshot, self.link())
        for payload, expected in [(snapshot.artifact_bytes('raw'), 'valid'), (b'arbitrary other web bytes', 'invalid')]:
            with patch.object(evidence, '_anonymous_fetch', return_value=payload):
                result = evidence.publication(rendered['render'], rendered['render_sha256'])
            self.assertEqual(expected, result['status'])
        for status in (301, 302, 303, 307, 308, 401, 403, 404, 410, 429, 503):
            with self.subTest(status=status):
                with patch.object(evidence, '_anonymous_fetch', side_effect=urllib.error.HTTPError('url', status, 'error', {}, None)):
                    result = evidence.publication(rendered['render'], rendered['render_sha256'])
                self.assertEqual('unknown' if status in {429, 503} else 'invalid', result['status'])
        with patch.object(evidence, '_anonymous_fetch', side_effect=TimeoutError('timeout')):
            self.assertEqual('unknown', evidence.publication(rendered['render'], rendered['render_sha256'])['status'])
        (snapshot.path.parents[2] / 'objects' / evidence.digest(snapshot.artifact_bytes('raw'))).unlink()
        with patch.object(evidence, '_anonymous_fetch', return_value=b'irrelevant'):
            with self.assertRaises(evidence.EvidenceError):
                evidence.publication(rendered['render'], rendered['render_sha256'])

    def test_report_url_is_bound_to_exact_outgoing_bytes(self):
        snapshot = self.snapshot()
        rendered = self.render(snapshot, self.link('summary'))
        summary = (Path(rendered['render']).parent / 'summary.md').read_bytes()
        with patch.object(evidence, '_anonymous_fetch', return_value=summary):
            self.assertEqual('links_verified', evidence.publication(rendered['render'], rendered['render_sha256'])['links'])
        with patch.object(evidence, '_anonymous_fetch', return_value=snapshot.artifact_bytes('raw')):
            self.assertIn('publication_hash_mismatch', self.codes(evidence.publication(rendered['render'], rendered['render_sha256'])))

    def test_publication_strict_url_parser_and_audience_unknown(self):
        snapshot = self.snapshot()
        urls = [
            ('file:///tmp/raw', 'invalid'), ('/home/author/raw', 'invalid'),
            ('https://example.com/raw', 'unknown'),
            ('https://raw.githubusercontent.com/o/r/main/raw', 'invalid'),
            ('https://raw.githubusercontent.com/o/r/' + '1' * 40 + '/%2e%2e/raw', 'invalid'),
            ('https://raw.githubusercontent.com/o/r/' + '1' * 40 + '/raw?token=x', 'invalid'),
            ('https://raw.githubusercontent.com:443/o/r/' + '1' * 40 + '/raw', 'invalid'),
            ('https://user@raw.githubusercontent.com/o/r/' + '1' * 40 + '/raw', 'invalid'),
        ]
        for number, (url, expected) in enumerate(urls):
            with self.subTest(url=url):
                rendered = self.render(snapshot, self.link(url=url), name='url-' + str(number))
                result = self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'], expected=1)
                self.assertEqual(expected, result['status'])
        rendered = self.render(snapshot, self.link(audience='private-repo-readers'), name='private')
        result = self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'], expected=1)
        self.assertEqual('unknown', result['status'])

    def test_link_map_rejects_injected_markdown_and_missing_artifacts(self):
        snapshot = self.snapshot()
        for intent in (self.link(url='https://example.com/a)\n<img src=x>'), self.link('absent')):
            with self.assertRaises(evidence.EvidenceError):
                evidence.render(snapshot, self.durable / 'unsafe-render', intent)


    def test_binary_and_c_locale_preservation(self):
        self.artifact('binary', 'raw', bytes.fromhex('ff00fe0a72617700'))
        self.request['records'][0]['artifacts'].append('binary')
        self.request['reviews'][0]['reason'] = '境界で型検証済み'
        with patch.dict(os.environ, {'LC_ALL': 'C', 'LANG': 'C', 'PYTHONUTF8': '0'}):
            snapshot = self.snapshot()
            rendered = self.render(snapshot)
            self.check_cli(snapshot)
        self.assertEqual(bytes.fromhex('ff00fe0a72617700'), snapshot.artifact_bytes('binary'))
        self.assertIn('境界で型検証済み', (Path(rendered['render']).parent / 'summary.md').read_text(encoding='utf-8'))

    def test_archival_original_and_secondary_remain_separate(self):
        self.historical()
        self.artifact('other-original', 'raw', b'Original stderr that did survive')
        self.request['records'][0]['artifacts'].append('other-original')
        snapshot = self.snapshot()
        self.assertEqual(b'Original stderr that did survive', snapshot.artifact_bytes('other-original'))
        self.assertIn(b'Historical report', snapshot.artifact_bytes('secondary'))

    def test_corrupt_existing_objects_are_not_overwritten_and_old_snapshots_stay_pinned(self):
        first = self.snapshot()
        self.request['reviews'][0]['reason'] = 'Scope is a path value.'
        second = self.snapshot()
        self.assertNotEqual(first.sha256, second.sha256)
        self.check_cli(first)
        self.render(first)
        self.assertEqual('The route binds scope before querying.', first.data['reviews'][0]['reason'])
        artifact = next(a for a in first.data['artifacts'] if a['id'] == 'raw')
        path = first.path.parents[2] / 'objects' / artifact['sha256']
        path.write_bytes(b'corruption')
        self.assertIn('hash_mismatch', self.codes(self.preserve(expected=1)))
        self.assertEqual(b'corruption', path.read_bytes())

    def test_symlink_loop_directory_and_store_object_escape(self):
        raw = Path(self.request['artifacts'][0]['source']['path'])
        raw.unlink()
        link_file(self, raw, raw.name)
        self.assertTrue({'io_error', 'unsupported_file'} & self.codes(self.preserve(expected=1)))
        raw.unlink()
        raw.mkdir()
        self.assertIn('unsupported_file', self.codes(self.preserve(expected=1)))
        raw.rmdir()
        raw.write_bytes(b'{"scope":"public","rows":[1,2]}\n')
        archive = self.durable / 'escape-archive'
        archive.mkdir()
        link_directory((archive / 'objects'), self.source)
        result = self.cli('preserve', '--input', self.durable / 'import.json', '--store', archive, expected=1)
        self.assertIn('retention_invalid', self.codes(result))

    def test_interrupt_before_manifest_install_is_retryable_without_partial_snapshot(self):
        clean = self.snapshot()
        input_path = self.durable / 'import.json'
        archive = self.durable / 'interrupted'
        code = """
import importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location('task_evidence', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
linux = sys.platform.startswith('linux')
original = os.link if linux else module._fs.publish_new
def interrupt(source, destination, *args, **kwargs):
    if pathlib.Path(destination).name == 'manifest.json':
        os._exit(73)
    return original(source, destination, *args, **kwargs)
if linux:
    os.link = interrupt
else:
    module._fs.publish_new = interrupt
raise SystemExit(module.main(sys.argv[2:]))
"""
        result = subprocess.run([sys.executable, '-B', '-c', code, str(SCRIPT), 'preserve', '--input', str(input_path), '--store', str(archive)],
                                capture_output=True, encoding='utf-8')
        self.assertEqual(73, result.returncode)
        self.assertEqual([], list(archive.glob('snapshots/*/manifest.json')))
        retried = self.cli('preserve', '--input', input_path, '--store', archive)
        self.assertEqual(clean.sha256, retried['snapshot_sha256'])
        snapshot = evidence.Snapshot.read(retried['snapshot'], retried['snapshot_sha256'])
        self.check_cli(snapshot)

    def test_interrupt_during_render_never_publishes_complete_render(self):
        snapshot = self.snapshot()
        original = evidence._fs.publish_new
        def interrupted(source, destination):
            if isinstance(source, Path) and source.name == 'cases.md':
                raise OSError('simulated interrupted pair')
            return original(source, destination)
        with patch.object(evidence._fs, 'publish_new', side_effect=interrupted):
            with self.assertRaises(OSError):
                evidence.render(snapshot, self.durable / 'partial-render')
        self.assertFalse((self.durable / 'partial-render/render.json').exists())
        self.render(snapshot, name='retry-render')

    def test_all_conflicting_reuse_findings_are_retained(self):
        snapshot = self.snapshot()
        context, observation, path = self.context()
        context['candidate'] = {**context['candidate'], 'sha256': 'f' * 64}
        observation['resource'].update(owner='author', generation='restarted')
        context['checked_at'] = '2026-11-19T00:00:00Z'
        self.change_observation(context, observation, path)
        result = self.check_cli(snapshot, context, expected=1)
        self.assertEqual('valid', result['archive_integrity'])
        self.assertTrue({'candidate_mismatch', 'owner_mismatch', 'environment_stale', 'expired'} <= self.codes(result))

    def test_candidate_bytes_and_review_subject_cannot_change_behind_an_id(self):
        artifact = next(a for a in self.request['artifacts'] if a['id'] == 'candidate-source')
        self.request['candidates'][0]['sha256'] = 'f' * 64
        self.assertIn('candidate_mismatch', self.codes(self.preserve(expected=1)))
        Path(artifact['source']['path']).write_bytes(b'new candidate source')
        artifact['sha256'] = evidence.digest(b'new candidate source')
        self.request['candidates'][0]['sha256'] = artifact['sha256']
        result = self.check_cli(self.snapshot(), expected=1)
        self.assertIn('review_subject_mismatch', self.codes(result))

    def test_exact_json_values_do_not_equate_nested_boolean_and_integer(self):
        self.request['cases'][0]['expected']['value']['rows'] = [True, 2]
        rendered = self.render(self.snapshot())
        self.assertIn('expectation mismatched', (Path(rendered['render']).parent / 'summary.md').read_text(encoding='utf-8'))

    def test_transport_is_anonymous_redirect_free_and_bounded(self):
        import io
        class Response:
            status = 200
            def __init__(self, data):
                self.body = io.BytesIO(data)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read1(self, size):
                return self.body.read(size)
        class Opener:
            def __init__(self, data):
                self.data = data
                self.request = None
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response(self.data)
        snapshot = self.snapshot()
        rendered = self.render(snapshot, self.link())
        opener = Opener(snapshot.artifact_bytes('raw'))
        captured = []
        def factory(*handlers):
            captured.extend(handlers)
            return opener
        with patch.dict(os.environ, {'GH_TOKEN': 'not-for-http', 'GITHUB_TOKEN': 'not-for-http', 'HTTPS_PROXY': 'http://author-proxy.invalid'}):
            with patch.object(evidence.urllib.request, 'build_opener', side_effect=factory):
                self.assertEqual('valid', evidence.publication(rendered['render'], rendered['render_sha256'])['status'])
        self.assertFalse(any(key.casefold() in {'authorization', 'cookie'} for key in opener.request.headers))
        self.assertEqual(10, opener.timeout)
        proxy = next(h for h in captured if isinstance(h, evidence.urllib.request.ProxyHandler))
        self.assertEqual({}, proxy.proxies)
        redirect = next(h for h in captured if isinstance(h, evidence.urllib.request.HTTPRedirectHandler))
        for status in (301, 302, 303, 307, 308):
            self.assertIsNone(redirect.redirect_request(opener.request, None, status, 'redirect', {}, 'https://elsewhere.invalid'))
        oversized = Opener(b'x' * (evidence.MAX_BYTES + 1))
        with patch.object(evidence.urllib.request, 'build_opener', return_value=oversized):
            self.assertIn('size_limit', self.codes(evidence.publication(rendered['render'], rendered['render_sha256'])))


    def test_source_environment_and_report_cannot_supply_measured_actual(self):
        self.artifact('narrative', 'report', b'Claimed output with no raw capture')
        self.request['records'][0]['artifacts'].extend(['candidate-source', 'narrative'])
        for artifact in ('environment', 'diff', 'candidate-source', 'narrative'):
            with self.subTest(artifact=artifact):
                self.request['cases'][0]['actual']['artifact'] = artifact
                self.assertIn('schema_invalid', self.codes(self.preserve(expected=1)))
        self.request['cases'][0]['actual']['artifact'] = 'raw'
        self.preserve()

    def test_identical_new_capture_bytes_can_be_independent(self):
        snapshot = self.snapshot()
        context, observation, path = self.context()
        raw = Path(observation['raw']['path'])
        raw.write_bytes(snapshot.artifact_bytes('raw'))
        observation['raw']['sha256'] = evidence.digest(raw.read_bytes())
        self.change_observation(context, observation, path)
        self.assertEqual('valid', self.check_cli(snapshot, context)['reuse'])
        original = Path(next(a for a in self.request['artifacts'] if a['id'] == 'raw')['source']['path'])
        alias = self.source / 'worker-b/current-alias'
        os.link(original, alias)
        observation['raw']['path'] = str(alias)
        self.change_observation(context, observation, path)
        self.assertIn('independence_unverified', self.codes(self.check_cli(snapshot, context, expected=1)))

    def test_changing_original_during_copy_fails_without_blessing_new_bytes(self):
        raw = Path(next(a for a in self.request['artifacts'] if a['id'] == 'raw')['source']['path'])
        original_bytes = raw.read_bytes()
        identity = evidence._fs.identity(raw)
        fdopen = os.fdopen
        class ChangingStream:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def fileno(self):
                return self.stream.fileno()
            def read(self, count):
                data = self.stream.read(count)
                raw.write_bytes(b'changed concurrently')
                return data
        def open_stream(fd, *args, **kwargs):
            stream = fdopen(fd, *args, **kwargs)
            if WINDOWS:
                import msvcrt
                opened = evidence._fs._win_identity(msvcrt.get_osfhandle(fd), raw)
            else:
                info = os.fstat(fd)
                opened = (info.st_dev, info.st_ino)
            return ChangingStream(stream) if opened == identity else stream
        with patch.object(os, 'fdopen', side_effect=open_stream):
            with self.assertRaises(evidence.EvidenceError) as error:
                evidence.preserve(self.request, self.durable / 'archive')
        self.assertEqual('source_changed', error.exception.finding['code'])
        self.assertEqual([], list((self.durable / 'archive').glob('snapshots/*/manifest.json')))
        raw.write_bytes(original_bytes)
        self.preserve()


    def test_repair_d1_review_requires_available_hash_valid_candidate_subject_and_support(self):
        self.artifact('support', 'report', b'Separate review supporting bytes')
        self.request['reviews'][0]['evidence'] = ['support']
        base = copy.deepcopy(self.request)
        for ident in ('candidate-source', 'diff', 'support'):
            for damage in ('declared-missing', 'deleted', 'corrupt'):
                with self.subTest(item=ident, damage=damage):
                    self.request = copy.deepcopy(base)
                    artifact = next(a for a in self.request['artifacts'] if a['id'] == ident)
                    if damage == 'declared-missing':
                        artifact.pop('media_type')
                        artifact.update(state='missing', missing_reason='Unavailable original')
                        # A historical/environment package may retain a candidate digest
                        # or diff locator even though it cannot support a ready review.
                        record = self.request['records'][0]
                        record.update(evidence_type='environment_snapshot', declared_outcome='unknown',
                                      artifacts=['environment'], producer={'name': 'preflight', 'artifact': None})
                        self.request['cases'][0]['actual'] = {'kind': 'unverified', 'reason': 'Navigation only'}
                    snapshot = self.snapshot()
                    blob = snapshot.path.parents[2] / 'objects' / artifact['sha256']
                    original = blob.read_bytes() if blob.exists() else None
                    if damage == 'deleted':
                        blob.unlink()
                    elif damage == 'corrupt':
                        blob.write_bytes(b'corrupt preserved bytes')
                    try:
                        result = evidence.check(snapshot)
                        self.assertEqual('invalid', result['review_readiness'])
                        self.check_cli(snapshot, expected=1)
                        self.assertEqual('valid' if damage == 'declared-missing' else 'invalid', result['archive_integrity'])
                        if damage == 'declared-missing':
                            rendered = self.render(snapshot, name='missing-' + ident)
                            self.assertIn('Review readiness: invalid.', (Path(rendered['render']).parent / 'summary.md').read_text(encoding='utf-8'))
                    finally:
                        if original is not None:
                            blob.write_bytes(original)

    def test_repair_d2_historical_publication_keeps_loss_informational_but_retained_report_required(self):
        self.historical()
        snapshot = self.snapshot()
        rendered = self.render(snapshot)
        result = self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'])
        self.assertEqual('valid', result['status'])
        self.assertEqual('checked_no_links', result['links'])
        self.assertIn('missing_original', self.codes(result))
        self.assertIn('Original temp directory was cleaned', (Path(rendered['render']).parent / 'summary.md').read_text(encoding='utf-8'))
        linked = self.render(snapshot, self.link('secondary'), name='secondary-linked')
        with patch.object(evidence, '_anonymous_fetch', return_value=snapshot.artifact_bytes('secondary')):
            self.assertEqual('links_verified', evidence.publication(linked['render'], linked['render_sha256'])['links'])
        blob = snapshot.path.parents[2] / 'objects' / evidence.digest(snapshot.artifact_bytes('secondary'))
        original = blob.read_bytes()
        for damage in ('deleted', 'corrupt'):
            with self.subTest(damage=damage):
                if damage == 'deleted':
                    blob.unlink()
                else:
                    blob.write_bytes(b'corrupt report')
                result = self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'], expected=1)
                self.assertEqual('invalid', result['status'])
                blob.write_bytes(original)

    def shared_resource_records(self):
        self.artifact('raw-two', 'raw', b'Second execution output')
        second = copy.deepcopy(self.request['records'][0])
        second.update(id='run-2', artifacts=['raw-two', 'environment'], producer={'name': 'second', 'artifact': None})
        second['command']['execution_id'] = 'execution-2'
        self.request['records'].append(second)
        self.request['cases'][0]['records'].append('run-2')
        self.request['actors'].append({'id': 'verifier-two', 'role': 'verifier'})
        self.artifact('raw-rechecked', 'raw', b'Archived independent output')
        recheck = copy.deepcopy(second)
        recheck.update(id='recheck-1', observer='verifier-two', evidence_type='independent_recheck',
                       rechecks='run-1', observed_at='2026-11-17T00:00:04Z', artifacts=['raw-rechecked', 'environment'])
        recheck['command']['execution_id'] = 'archived-verifier-run'
        self.request['records'].append(recheck)
        self.request['cases'][0]['records'].append('recheck-1')
        auxiliary = copy.deepcopy(second)
        auxiliary.update(id='preflight', evidence_type='environment_snapshot', declared_outcome='unknown', artifacts=['environment'])
        auxiliary['command']['execution_id'] = None
        self.request['records'].append(auxiliary)
        self.artifact('old-missing', 'raw', b'Lost old output')
        missing = self.request['artifacts'][-1]
        missing.pop('media_type')
        missing.update(state='missing', missing_reason='Old source cleaned')
        self.artifact('old-secondary', 'report', b'Old narrative, explicitly historical')
        historical = copy.deepcopy(auxiliary)
        historical.update(id='old-run', evidence_type='historical_secondary', artifacts=['old-missing', 'old-secondary'],
                          limitation='Original cleaned; secondary retained')
        self.request['records'].append(historical)
        # Auxiliary records linked to a behavior case remain context, too.
        self.request['cases'][0]['records'] += ['preflight', 'old-run']
        self.artifact('unlinked-raw', 'raw', b'Unlinked behavioral context')
        unlinked = copy.deepcopy(second)
        unlinked.update(id='unlinked-run', artifacts=['unlinked-raw', 'environment'])
        unlinked['command']['execution_id'] = 'unlinked-execution'
        self.request['records'].append(unlinked)

    def add_current_observation(self, context, template, ident, number):
        observation = copy.deepcopy(template)
        observation.update(rechecks=ident, execution_id='current-execution-' + str(number))
        raw = self.durable / ('fresh-' + str(number) + '.raw')
        raw.write_bytes(('Fresh output ' + str(number)).encode())
        observation['raw'] = {'path': str(raw), 'sha256': evidence.digest(raw.read_bytes())}
        path = self.durable / ('observation-' + str(number) + '.json')
        path.write_bytes(evidence.canonical(observation))
        context['observations'].append({'path': str(path), 'sha256': evidence.digest(path.read_bytes())})
        return observation, path

    def test_repair_d3_shared_resource_behavior_obligations_and_auxiliary_context(self):
        self.shared_resource_records()
        snapshot = self.snapshot()
        context, observation, _ = self.context()
        for number, ident in enumerate(('run-2', 'recheck-1'), 2):
            self.add_current_observation(context, observation, ident, number)
        result = self.check_cli(snapshot, context)
        self.assertEqual('valid', result['reuse'])
        self.assertTrue({'preflight', 'old-run', 'unlinked-run'} <= {f['subject'] for f in result['findings'] if f['status'] == 'info'})
        context['observations'].pop()
        self.assertEqual('unknown', self.check_cli(snapshot, context, expected=1)['reuse'])

    def test_repair_d3_auxiliary_only_case_remains_unverified(self):
        self.shared_resource_records()
        context, observation, _ = self.context()
        for number, ident in enumerate(('run-2', 'recheck-1'), 2):
            self.add_current_observation(context, observation, ident, number)
        auxiliary_case = copy.deepcopy(self.request['cases'][0])
        auxiliary_case.update(id='auxiliary-case', scenario='auxiliary', records=['preflight', 'old-run'],
                              actual={'kind': 'unverified', 'reason': 'Auxiliary evidence only'})
        self.request['cases'].append(auxiliary_case)
        result = self.check_cli(self.snapshot(), context, expected=1)
        self.assertIn('behavior_unverified', {f['code'] for f in result['findings'] if f['subject'] == 'auxiliary-case'})

    def test_repair_d3_candidate_without_cases_cannot_pass_vacuously(self):
        self.request['candidates'].append({**self.request['candidates'][0], 'id': 'other'})
        record = copy.deepcopy(self.request['records'][0])
        record.update(id='other-run', candidate='other')
        record['command']['execution_id'] = 'other-execution'
        self.request['records'].append(record)
        self.request['cases'][0].update(candidate='other', records=['other-run'])
        context, _, _ = self.context()
        result = self.check_cli(self.snapshot(), context, expected=1)
        self.assertEqual('unknown', result['reuse'])
        self.assertIn('behavior_unverified', self.codes(result))

    def test_repair_d3_conflicting_observations_and_reused_independence_identities_fail(self):
        self.shared_resource_records()
        snapshot = self.snapshot()
        for damage in ('duplicate-binding', 'execution-id', 'capture-path', 'capture-inode', 'archived-execution', 'archived-capture'):
            with self.subTest(damage=damage):
                context, first, _ = self.context()
                second, path = self.add_current_observation(context, first, 'run-2', 2)
                self.add_current_observation(context, first, 'recheck-1', 3)
                if damage == 'duplicate-binding':
                    second['rechecks'] = 'run-1'
                    second['resource']['generation'] = 'contradictory'
                elif damage == 'execution-id':
                    second['execution_id'] = first['execution_id']
                elif damage == 'archived-execution':
                    second['execution_id'] = 'execution-1'
                elif damage == 'archived-capture':
                    source = next(a['source']['path'] for a in self.request['artifacts'] if a['id'] == 'raw')
                    second['raw'] = {'path': source, 'sha256': evidence.digest(Path(source).read_bytes())}
                else:
                    if damage == 'capture-path':
                        second['raw'] = first['raw']
                    else:
                        alias = self.durable / 'hardlinked-current'
                        os.link(first['raw']['path'], alias)
                        second['raw'] = {**first['raw'], 'path': str(alias)}
                path.write_bytes(evidence.canonical(second))
                context['observations'][1]['sha256'] = evidence.digest(path.read_bytes())
                result = self.check_cli(snapshot, context, expected=1)
                self.assertEqual('invalid', result['reuse'])

    def test_repair_d4_archival_consistency_reports_all_candidates_without_context(self):
        self.request['candidates'].append({**self.request['candidates'][0], 'id': 'other'})
        other = copy.deepcopy(self.request['records'][0])
        other.update(id='other-run', candidate='other', resource_owner='author', resource_generation='wrong',
                     environment='wrong-env', observed_at='2026-11-19T00:00:00Z', expires_at='2026-11-18T00:00:00Z')
        other['command']['started_at'] = '2026-11-19T00:00:02Z'
        other['command']['finished_at'] = '2026-11-19T00:00:01Z'
        self.request['records'].append(other)
        snapshot = self.snapshot()
        for context in (None, self.context()[0]):
            result = self.check_cli(snapshot, context, expected=1)
            self.assertEqual('valid', result['archive_integrity'])
            self.assertEqual('invalid', result['archive_consistency'])
            findings = [f for f in result['findings'] if f['subject'] == 'other-run']
            self.assertTrue({'owner_mismatch', 'environment_stale', 'expired', 'time_order_invalid'} <= {f['code'] for f in findings})
            self.assertTrue(any('generation' in f['reason'] for f in findings))
            self.assertTrue(any('environment' in f['reason'] for f in findings))
            self.assertEqual(4, sum(f['code'] == 'time_order_invalid' for f in findings))
        rendered = self.render(snapshot)
        self.assertIn('Archive consistency: invalid.', (Path(rendered['render']).parent / 'summary.md').read_text(encoding='utf-8'))

    def test_repair_d4_current_observation_newer_than_record_and_resource(self):
        self.request['resources'][0]['observed_at'] = '2026-11-17T02:00:00Z'
        snapshot = self.snapshot()
        context, observation, path = self.context()
        result = self.check_cli(snapshot, context, expected=1)
        self.assertIn('environment_unknown', self.codes(result))
        observation['observed_at'] = observation['resource']['observed_at'] = '2026-11-17T03:00:00Z'
        context['checked_at'] = '2026-11-17T03:00:01Z'
        self.change_observation(context, observation, path)
        self.assertEqual('valid', self.check_cli(snapshot, context)['reuse'])

    def test_repair_d4_current_time_errors_do_not_mask_owner_environment_or_expiry(self):
        snapshot = self.snapshot()
        context, observation, path = self.context()
        observation['resource'].update(owner='author', generation='wrong', environment='wrong', expires_at='2026-11-17T00:00:00Z')
        self.change_observation(context, observation, path)
        result = self.check_cli(snapshot, context, expected=1)
        self.assertTrue({'owner_mismatch', 'environment_stale', 'time_order_invalid', 'expired'} <= self.codes(result))

    def test_repair_d5_invalid_render_destinations_have_no_side_effects(self):
        snapshot = self.snapshot()
        real = self.durable / 'real-parent'
        real.mkdir()
        symlink = self.durable / 'symlink-parent'
        link_directory(symlink, real)
        dangling = self.durable / 'dangling-output'
        link_file(self, dangling, self.durable / 'absent')
        existing = self.durable / 'existing'
        existing.mkdir()
        ordinary_file = self.durable / 'file'
        ordinary_file.write_text('Do not change')
        cases = [(symlink / 'nested/out', 'retention_invalid'), (dangling, 'output_exists'),
                 (existing, 'output_exists'), (ordinary_file / 'out', 'retention_invalid'),
                 (Path('relative-output'), 'schema_invalid')]
        for output, code in cases:
            with self.subTest(output=str(output)):
                before = sorted(str(p.relative_to(self.durable)) for p in self.durable.rglob('*'))
                result = self.cli('render', '--snapshot', snapshot.path, '--sha256', snapshot.sha256, '--out', output, expected=1)
                self.assertIn(code, self.codes(result))
                self.assertEqual(before, sorted(str(p.relative_to(self.durable)) for p in self.durable.rglob('*')))

    def test_repair_d5_local_links_invalid_for_every_audience(self):
        snapshot = self.snapshot()
        for audience in ('public-anonymous', 'private-repo-readers'):
            for number, url in enumerate(('file:///tmp/raw', '/home/author/raw', 'raw.txt', 'http://localhost/raw', 'http://127.0.0.1/raw')):
                with self.subTest(audience=audience, url=url):
                    rendered = self.render(snapshot, self.link(url=url, audience=audience), name=audience + str(number))
                    result = self.cli('publication', '--render', rendered['render'], '--sha256', rendered['render_sha256'], expected=1)
                    self.assertEqual('invalid', result['status'])
                    self.assertIn('publication_url_invalid', self.codes(result))


    def test_repair_d3_archived_recheck_cannot_reuse_another_execution_identity_or_capture(self):
        self.shared_resource_records()
        original = copy.deepcopy(self.request)
        for damage in ('execution-id', 'capture-path', 'capture-inode'):
            with self.subTest(damage=damage):
                self.request = copy.deepcopy(original)
                recheck = next(r for r in self.request['records'] if r['id'] == 'recheck-1')
                if damage == 'execution-id':
                    recheck['command']['execution_id'] = 'execution-2'
                elif damage == 'capture-path':
                    recheck['artifacts'] = ['raw-two', 'environment']
                else:
                    raw = next(a for a in self.request['artifacts'] if a['id'] == 'raw-two')
                    alias = self.source / 'worker-b/archived-alias'
                    os.link(raw['source']['path'], alias)
                    artifact = next(a for a in self.request['artifacts'] if a['id'] == 'raw-rechecked')
                    artifact['source']['path'], artifact['sha256'] = str(alias), raw['sha256']
                self.assertIn('independence_unverified', self.codes(self.preserve(expected=1)))

    def test_repair_d4_validly_ordered_archival_contradictions_are_reported_without_context(self):
        record = self.request['records'][0]
        record.update(resource_owner='author', resource_generation='wrong-generation', environment='wrong-environment',
                      observed_at='2026-11-17T05:00:00Z')
        self.request['resources'][0]['expires_at'] = '2026-11-17T03:00:00Z'
        result = self.check_cli(self.snapshot(), expected=1)
        self.assertEqual('valid', result['archive_integrity'])
        self.assertEqual('invalid', result['archive_consistency'])
        self.assertTrue({'owner_mismatch', 'environment_stale', 'expired'} <= self.codes(result))

    def test_repair_d4_resource_order_error_does_not_mask_record_contradictions(self):
        self.request['resources'][0]['expires_at'] = '2026-11-16T23:00:00Z'
        self.request['records'][0].update(resource_owner='author', resource_generation='wrong', environment='wrong')
        result = self.check_cli(self.snapshot(), expected=1)
        self.assertEqual('valid', result['archive_integrity'])
        self.assertTrue({'owner_mismatch', 'environment_stale', 'time_order_invalid', 'expired'} <= self.codes(result))

    def test_real_transport_observes_anonymous_requests_errors_redirect_refusal_and_body_limit(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                requests.append((self.path, dict(self.headers)))
                if self.path.startswith('/status/'):
                    self.send_response(int(self.path.rsplit('/', 1)[1]))
                    self.send_header('Location', '/must-not-follow')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    try:
                        self.wfile.write(b'x' * (evidence.MAX_BYTES + 1) if self.path == '/oversized' else b'actual transport bytes')
                    except (BrokenPipeError, ConnectionResetError):
                        pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:' + str(server.server_port)
            with patch.dict(os.environ, {'GH_TOKEN': 'not-for-http', 'GITHUB_TOKEN': 'not-for-http',
                                         'HTTP_PROXY': 'http://proxy.invalid', 'HTTPS_PROXY': 'http://proxy.invalid'}):
                self.assertEqual(b'actual transport bytes', evidence._anonymous_fetch(base + '/okay'))
                for status in (301, 302, 303, 307, 308, 401, 403, 404, 410, 429, 503):
                    with self.subTest(status=status):
                        with self.assertRaises(urllib.error.HTTPError) as error:
                            evidence._anonymous_fetch(base + '/status/' + str(status))
                        self.assertEqual(status, error.exception.code)
                        error.exception.close()
                with self.assertRaises(evidence.EvidenceError) as error:
                    evidence._anonymous_fetch(base + '/oversized')
                self.assertEqual('size_limit', error.exception.finding['code'])
            self.assertNotIn('/must-not-follow', [p for p, headers in requests])
            self.assertEqual(13, len(requests))
            for path, headers in requests:
                self.assertFalse({'authorization', 'cookie'} & {key.casefold() for key in headers})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
