#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evidence_test_support import WINDOWS, expected_mode, link_directory, link_file, writable_tree

SCRIPT = Path(__file__).resolve().parents[1] / 'plugins/pstack/skills/poteto-mode/scripts/guarded_document.py'
SPEC = importlib.util.spec_from_file_location('guarded_document', SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)


def sha(data):
    return hashlib.sha256(data).hexdigest()


FAULT_RUNNER = r"""
from contextlib import contextmanager
import os, pathlib, runpy, sys, time
script, phase, action, marker, target = sys.argv[1:6]
arguments = sys.argv[6:]
marker, target = pathlib.Path(marker), pathlib.Path(target)
module = runpy.run_path(script, run_name='guard_fault_child')
scope = module['promote'].__globals__
fs = scope['_fs']
def trip():
    marker.write_text(phase, encoding='utf-8')
    if action == 'fail':
        raise OSError('injected filesystem failure at ' + phase)
    release = marker.with_suffix('.release')
    while not release.exists():
        time.sleep(0.01)
write_once = scope['_write_once']
def write(path, data):
    if phase == 'before_intent' and path.name == 'intent.json':
        trip()
    if phase == 'before_receipt' and path.name == 'receipt.json':
        trip()
    write_once(path, data)
    if phase == 'prepared' and path.name == 'intent.json':
        trip()
    if phase == 'receipt' and path.name == 'receipt.json':
        trip()
scope['_write_once'] = write
replace = fs.replace_existing
def replace_target(source, destination):
    replace(source, destination)
    if phase == 'replaced' and destination == target:
        trip()
fs.replace_existing = replace_target
stage = fs.stage
@contextmanager
def stage_file(parent, data, **options):
    with stage(parent, data, **options) as staged:
        if phase == 'staged' and options.get('prefix', '').startswith('.' + target.name + '.pstack-'):
            trip()
        yield staged
fs.stage = stage_file
install = scope['_rename_noreplace']
def no_clobber(source, destination):
    if phase == 'absent_race' and destination == target:
        trip()
    install(source, destination)
scope['_rename_noreplace'] = no_clobber
sync = fs.sync_directory
def sync_directory(path):
    sync(path)
    if (phase in ('intent', 'request') and path.parent.name == 'operations'
            and (path / 'request.json').is_file()
            and (path / 'intent.json').is_file() == (phase == 'intent')):
        trip()
fs.sync_directory = sync_directory
sys.exit(module['_main'](arguments))
"""


class GuardedDocumentTests(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ.get('PSTACK_GUARD_TEST_ROOT',
                                     Path.home() / '.local/state/pstack-guard-tests')).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='owned-', dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(writable_tree, self.root)
        self.state = self.root / 'state'
        self.target = self.root / 'reviewed.md'
        self.generated = self.put('generated.md', b'new generated\n')
        self.source = GUARD.GeneratedSource('test-renderer', '1', sha(b'renderer'),
                                            (('snapshot', sha(b'snapshot')),), sha(b'render-pair'))
        self.source_path = self.put('source.json', json.dumps(self.source.as_dict()).encode())
        self.env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}

    def put(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def cli(self, *args, ok=True):
        process = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                                 capture_output=True, encoding='utf-8', env=self.env, timeout=15)
        if ok:
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        else:
            self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
        return json.loads(process.stdout)

    def proposal(self):
        return self.cli('propose', '--state', self.state, '--target', self.target,
                        '--generated', self.generated, '--source', self.source_path,
                        '--owner', 'owned-test')

    def test_repair_g1_rejections_leave_target_available_for_correct_state(self):
        self.proposal()
        for case in ('rebind', 'state-file', 'before-propose', 'owner', 'generated', 'source'):
            with self.subTest(case=case):
                target = self.root / ('rejected-' + case + '.md')
                state = self.root / (case + '-state')
                lock = target.with_name(target.name + '.pstack-guard.lock')
                bad_state = self.state if case == 'rebind' else self.root / (case + '-bad-state')
                if case == 'state-file':
                    bad_state.write_bytes(b'unrelated state file')
                if case == 'before-propose':
                    with self.assertRaises(GUARD.GuardError):
                        GUARD.promote(bad_state, target, '0' * 64, operation_id='early',
                                      expect_target='absent', expect_draft='0' * 64, single_writer=True)
                else:
                    with self.assertRaises((GUARD.GuardError, OSError)):
                        GUARD.propose(bad_state, target,
                                      target if case == 'generated' else self.generated,
                                      object() if case == 'source' else self.source,
                                      owner='\udcff' if case == 'owner' else 'owned-test')
                self.assertFalse(lock.exists() and lock.read_bytes())
                good = GUARD.propose(state, target, self.generated, self.source, owner='owned-test')
                self.assertEqual('proposed', good['outcome'])
                self.assertFalse(target.exists())

    def test_repair_g1_lock_namespace_is_reserved_for_all_inputs(self):
        for role in ('state', 'generated', 'merged'):
            for descendant in (False, True):
                with self.subTest(role=role, descendant=descendant):
                    target = self.root / (role + str(descendant) + '.md')
                    state = self.root / (role + str(descendant) + '-state')
                    lock = target.with_name(target.name + '.pstack-guard.lock')
                    reserved = lock / 'child' if descendant else lock
                    if role == 'merged':
                        proposal = GUARD.propose(state, target, self.generated, self.source, owner='owner')
                        before = lock.read_bytes()
                        with self.assertRaises(GUARD.GuardError):
                            GUARD.promote(state, target, proposal['proposal_id'], operation_id='bad',
                                          expect_target='absent', expect_draft=proposal['new_generated'],
                                          decision='merge', merged=reserved, expect_merged='0' * 64, single_writer=True)
                        self.assertEqual(before, lock.read_bytes())
                        self.assertEqual('committed', GUARD.promote(
                            state, target, proposal['proposal_id'], operation_id='good',
                            expect_target='absent', expect_draft=proposal['new_generated'], single_writer=True)['outcome'])
                    else:
                        with self.assertRaises(GUARD.GuardError):
                            GUARD.propose(reserved if role == 'state' else state, target,
                                          reserved if role == 'generated' else self.generated,
                                          self.source, owner='owner')
                        self.assertFalse(lock.exists())
                        self.assertFalse(state.exists())
                        self.assertEqual('proposed', GUARD.propose(
                            state, target, self.generated, self.source, owner='owner')['outcome'])

    def test_repair_g1_concurrent_state_binding_leaves_losing_target_usable(self):
        targets = [self.root / 'first.md', self.root / 'second.md']
        processes = [subprocess.Popen(
            [sys.executable, str(SCRIPT), 'propose', '--state', str(self.state), '--target', str(target),
             '--generated', str(self.generated), '--source', str(self.source_path), '--owner', 'owned-test'],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for target in targets]
        results = []
        for target, process in zip(targets, processes):
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(b'', stderr)
            results.append((target, process.returncode, json.loads(stdout)))
        self.assertEqual([0, 1], sorted(row[1] for row in results))
        loser = next(target for target, code, _ in results if code)
        self.assertFalse(loser.with_name(loser.name + '.pstack-guard.lock').read_bytes())
        self.assertEqual('proposed', GUARD.propose(
            self.root / 'loser-state', loser, self.generated, self.source, owner='owned-test')['outcome'])

    def test_existing_unrelated_lock_bytes_are_never_replaced(self):
        lock = self.target.with_name(self.target.name + '.pstack-guard.lock')
        lock.write_bytes(b'Unrelated retained bytes\n')
        lock.chmod(0o640)
        before = lock.stat()
        with self.assertRaises(GUARD.GuardError):
            GUARD.propose(self.state, self.target, self.generated, self.source, owner='owned-test')
        self.assertEqual(b'Unrelated retained bytes\n', lock.read_bytes())
        self.assertEqual((before.st_ino, before.st_mode), (lock.stat().st_ino, lock.stat().st_mode))
        self.assertFalse(self.state.exists())

    def test_repair_g2_surrogates_in_source_path_and_operation_reject_before_writes(self):
        for case in ('source', 'path'):
            with self.subTest(case=case):
                state, target = self.root / (case + '-state'), self.root / (case + '-target.md')
                source = self.source_path
                if case == 'source':
                    value = self.source.as_dict()
                    value['generator']['id'] = '\udcff'
                    source = self.put('surrogate-source.json', json.dumps(value).encode('ascii'))
                else:
                    state = self.root / '\udcff'
                result = self.cli('propose', '--state', state, '--target', target, '--generated', self.generated,
                                  '--source', source, '--owner', 'owner', ok=False)
                self.assertEqual('error', result['outcome'])
                self.assertFalse(state.exists())
                self.assertFalse(target.with_name(target.name + '.pstack-guard.lock').exists())
                self.assertEqual('proposed', GUARD.propose(
                    self.root / (case + '-good-state'), target, self.generated, self.source, owner='owner')['outcome'])
        proposal = self.proposal()
        with self.assertRaises(GUARD.GuardError):
            GUARD.promote(self.state, self.target, proposal['proposal_id'], operation_id='\udcff',
                          expect_target='absent', expect_draft=proposal['new_generated'], single_writer=True)
        self.assertEqual([], list((self.state / 'operations').iterdir()))
        self.assertEqual('committed', self.cli(*self.promote_args(proposal))['outcome'])

    def test_repair_g2_c_locale_full_cli_and_surrogate_rejection_before_effects(self):
        self.env.update(LC_ALL='C', LANG='C', PYTHONUTF8='1')
        source = self.source.as_dict()
        source['generator']['id'] = '摘要生成器'
        self.source_path.write_bytes(json.dumps(source, ensure_ascii=False).encode('utf-8'))
        proposal = self.proposal()
        self.assertEqual('摘要生成器', proposal['source']['generator']['id'])
        receipt = self.cli(*self.promote_args(proposal))
        self.assertEqual('committed', receipt['outcome'])
        self.assertEqual('already_committed', self.cli(
            'recover', '--state', self.state, '--target', self.target, '--operation-id', 'op-1')['outcome'])
        target = self.root / 'surrogate.md'
        state = self.root / 'surrogate-state'
        args = [sys.executable, str(SCRIPT), 'propose', '--state', str(state), '--target', str(target),
                '--generated', str(self.generated), '--source', str(self.source_path), '--owner', '\udcff']
        native_args = args if WINDOWS else [arg.encode('utf-8', 'surrogateescape') for arg in args]
        process = subprocess.run(native_args, env=self.env, capture_output=True, timeout=15)
        self.assertEqual(1, process.returncode)
        self.assertEqual(b'', process.stderr)
        self.assertEqual('error', json.loads(process.stdout)['outcome'])
        self.assertFalse(state.exists())
        self.assertFalse(target.with_name(target.name + '.pstack-guard.lock').exists())
        self.assertEqual('proposed', GUARD.propose(state, target, self.generated, self.source, owner='owner')['outcome'])

    def test_repair_g3_malformed_persisted_records_raise_domain_error(self):
        proposal = self.proposal()
        self.cli(*self.promote_args(proposal))
        directory = self.state / 'operations' / sha(b'op-1')
        for name in ('intent.json', 'request.json', 'receipt.json'):
            path = directory / name
            original = path.read_bytes()
            valid = json.loads(original)
            malformed_values = [{}, {'schema': []}, {'request': []}]
            if name == 'intent.json':
                malformed_values.extend({**valid, field: []} for field in
                                        ('request', 'prior_target', 'prior_receipt', 'desired_mode', 'operation_id'))
            for malformed in malformed_values:
                with self.subTest(name=name, malformed=malformed):
                    path.chmod(0o600)
                    path.write_text(json.dumps(malformed))
                    for call in (lambda: GUARD.propose(self.state, self.target, self.generated, self.source, owner='owned-test'),
                                 lambda: GUARD.promote(self.state, self.target, proposal['proposal_id'], operation_id='op-1',
                                                      expect_target='absent', expect_draft=proposal['new_generated'], single_writer=True),
                                 lambda: GUARD.recover(self.state, self.target, 'op-1')):
                        with self.assertRaises(GUARD.GuardError):
                            call()
            path.write_bytes(original)
            path.chmod(0o444)
        self.assertEqual('already_committed', GUARD.recover(self.state, self.target, 'op-1')['outcome'])

    def test_committed_merge_history_does_not_resolve_external_input_again(self):
        proposal = self.proposal()
        merged = self.put('merged.md', b'Generated text and human review\n')
        self.cli(*self.promote_args(proposal, **{'--decision': 'merge', '--merged': merged,
                                               '--expect-merged': sha(merged.read_bytes())}))
        merged.unlink()
        link_file(self, merged, self.generated)
        before = self.target.stat()
        self.assertEqual('already_committed', GUARD.recover(self.state, self.target, 'op-1')['outcome'])
        self.assertEqual('reviewed_change', self.proposal()['classification'])
        self.assertEqual(b'Generated text and human review\n', self.target.read_bytes())
        self.assertEqual((before.st_ino, before.st_mode), (self.target.stat().st_ino, self.target.stat().st_mode))

    def promote_args(self, proposal, operation='op-1', **overrides):
        values = {'--state': self.state, '--target': self.target,
                  '--proposal': proposal['proposal_id'], '--operation-id': operation,
                  '--decision': 'replace', '--expect-target': proposal['observed_target']['sha256'],
                  '--expect-draft': proposal['new_generated']}
        values.update(overrides)
        return ['promote', '--single-writer', *(str(item) for pair in values.items() for item in pair)]

    def recover(self, operation='op-1', ok=True):
        return self.cli('recover', '--state', self.state, '--target', self.target,
                        '--operation-id', operation, ok=ok)

    def fault(self, args, phase, action='stop'):
        marker = self.root / ('marker-' + phase)
        child = subprocess.Popen([sys.executable, '-c', FAULT_RUNNER, str(SCRIPT), phase,
                                  action, str(marker), str(self.target), *args],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.addCleanup(lambda: self.stop(child))
        deadline = time.monotonic() + 10
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not marker.exists():
            self.stop(child)
            out, err = child.communicate()
            self.fail('Fault point was not reached: ' + out + err)
        child.release_path = marker.with_suffix('.release')
        return child

    @staticmethod
    def stop(child):
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)

    def test_cli_preserves_existing_review_and_diffs_actual_target(self):
        self.target.write_bytes(b'reviewed by human\n')
        self.target.chmod(0o640)
        proposal = self.proposal()
        self.assertEqual(proposal['classification'], 'untracked')
        self.assertEqual(self.target.read_bytes(), b'reviewed by human\n')
        directory = Path(proposal['proposal_dir'])
        self.assertEqual((directory / 'target-before.md').read_bytes(), b'reviewed by human\n')
        self.assertEqual((directory / 'target.diff').read_bytes(),
                         b'--- target-before\n+++ draft\n@@ -1 +1 @@\n-reviewed by human\n+new generated\n')
        self.assertEqual(self.proposal()['proposal_id'], proposal['proposal_id'])
        self.assertEqual(len(list((self.state / 'proposals').iterdir())), 1)
        self.cli(*self.promote_args(proposal))
        self.assertEqual(self.target.read_bytes(), b'new generated\n')
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), expected_mode(0o640))
        replay = self.cli(*self.promote_args(proposal))
        self.assertEqual(replay['outcome'], 'already_committed')

    def test_manual_merge_retains_generated_baseline_separately(self):
        initial = self.proposal()
        self.cli(*self.promote_args(initial))
        self.target.write_bytes(b'new generated\nhuman review\n')
        self.generated.write_bytes(b'regenerated\n')
        stale = self.cli(*self.promote_args(initial, 'stale'), ok=False)
        self.assertEqual(stale['outcome'], 'error')
        proposal = self.proposal()
        self.assertEqual(proposal['classification'], 'reviewed_change')
        directory = Path(proposal['proposal_dir'])
        self.assertEqual((directory / 'generated-before.md').read_bytes(), b'new generated\n')
        self.assertIn(b'-human review\n', (directory / 'target.diff').read_bytes())
        self.assertNotIn(b'human review', (directory / 'generated.diff').read_bytes())
        merged = self.put('merged.md', b'regenerated\nhuman review\n')
        args = self.promote_args(proposal, 'merge', **{'--decision': 'merge', '--merged': merged,
                                                     '--expect-merged': sha(merged.read_bytes())})
        receipt = self.cli(*args)
        self.assertEqual(receipt['generated_baseline'], sha(b'regenerated\n'))
        self.assertEqual(receipt['desired_target'], sha(b'regenerated\nhuman review\n'))
        merged.unlink()
        self.target.write_bytes(b'later edit\n')
        replay = self.cli(*args)
        self.assertEqual(replay['outcome'], 'already_committed')
        self.assertEqual(self.target.read_bytes(), b'later edit\n')
        next_proposal = self.proposal()
        self.assertEqual(next_proposal['previous_generated'], sha(b'regenerated\n'))
        self.assertEqual((Path(next_proposal['proposal_dir']) / 'generated-before.md').read_bytes(), b'regenerated\n')

    def test_generator_only_change_has_distinct_identity_without_target_write(self):
        proposal = self.proposal()
        self.cli(*self.promote_args(proposal))
        before = self.target.stat()
        source = self.source.as_dict()
        source['generator']['sha256'] = sha(b'new renderer')
        self.source_path.write_text(json.dumps(source))
        changed = self.proposal()
        self.assertEqual(changed['classification'], 'unchanged')
        self.assertNotEqual(changed['proposal_id'], self.proposal_from_old_source())
        self.assertEqual(self.target.stat().st_ino, before.st_ino)
        self.cli(*self.promote_args(changed, 'provenance-only'))
        self.assertEqual(self.target.stat().st_ino, before.st_ino)
        self.assertEqual(self.target.stat().st_mtime_ns, before.st_mtime_ns)

    def proposal_from_old_source(self):
        saved = self.source_path.read_bytes()
        self.source_path.write_text(json.dumps(self.source.as_dict()))
        try:
            return self.proposal()['proposal_id']
        finally:
            self.source_path.write_bytes(saved)

    def test_bad_hashes_changed_operation_inputs_and_manual_edits_are_rejected(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        for key in ('--expect-target', '--expect-draft'):
            with self.subTest(key=key):
                self.cli(*self.promote_args(proposal, **{key: '0' * 64}), ok=False)
                self.assertEqual(self.target.read_bytes(), b'old\n')
        merged = self.put('merge.md', b'merged\n')
        self.cli(*self.promote_args(proposal, **{'--decision': 'merge', '--merged': merged,
                                               '--expect-merged': '0' * 64}), ok=False)
        self.cli(*self.promote_args(proposal))
        self.target.write_bytes(b'later manual edit\n')
        self.cli(*self.promote_args(proposal, **{'--expect-target': sha(b'later manual edit\n')}), ok=False)
        self.cli(*self.promote_args(proposal, 'new-id'), ok=False)
        self.assertEqual(self.cli(*self.promote_args(proposal))['outcome'], 'already_committed')
        self.assertEqual(self.target.read_bytes(), b'later manual edit\n')

    def test_mode_changes_and_deleted_targets_invalidate_proposals(self):
        self.target.write_bytes(b'old\n')
        self.target.chmod(0o444 if WINDOWS else 0o600)
        proposal = self.proposal()
        self.target.chmod(0o644)
        self.cli(*self.promote_args(proposal), ok=False)
        self.target.unlink()
        self.cli(*self.promote_args(proposal), ok=False)
        fresh = self.proposal()
        self.cli(*self.promote_args(fresh))
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), expected_mode(0o644))

    def test_untracked_same_bytes_and_semantically_bad_text_still_need_promotion(self):
        self.target.write_bytes(self.generated.read_bytes())
        proposal = self.proposal()
        self.assertEqual(proposal['classification'], 'unchanged')
        self.assertEqual(list((self.state / 'operations').iterdir()), [])
        self.generated.write_bytes(b'Invented claim: every user approved this.\n')
        bad = self.proposal()
        self.assertEqual(bad['outcome'], 'proposed')
        self.assertEqual(self.target.read_bytes(), b'new generated\n')

    def test_copies_are_independent_and_tampering_is_detected(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        draft = Path(proposal['proposal_dir']) / 'draft.md'
        obj = self.state / 'objects' / proposal['new_generated']
        self.assertNotEqual(draft.stat().st_ino, obj.stat().st_ino)
        self.assertEqual(draft.stat().st_nlink, 1)
        self.assertEqual(obj.stat().st_nlink, 1)
        self.generated.write_bytes(b'changed input\n')
        self.assertEqual(draft.read_bytes(), b'new generated\n')
        draft.chmod(0o644)
        draft.write_bytes(b'changed retained copy\n')
        self.assertEqual(obj.read_bytes(), b'new generated\n')
        self.cli(*self.promote_args(proposal), ok=False)
        self.assertEqual(self.target.read_bytes(), b'old\n')

    def test_corrupt_object_fails_instead_of_overwriting(self):
        proposal = self.proposal()
        obj = self.state / 'objects' / proposal['new_generated']
        obj.chmod(0o644)
        obj.write_bytes(b'corrupt\n')
        self.cli(*self.promote_args(proposal), ok=False)
        self.assertFalse(self.target.exists())
        self.cli('propose', '--state', self.state, '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        self.assertEqual(obj.read_bytes(), b'corrupt\n')

    def test_aliases_nonregular_files_skill_outputs_and_rebinding_are_rejected(self):
        real = self.put('real.md', b'real\n')
        if WINDOWS:
            link_directory(self.target, self.root)
        else:
            self.target.symlink_to(real)
        self.cli('propose', '--state', self.state, '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        if WINDOWS:
            self.target.rmdir()
        else:
            self.target.unlink()
        os.link(real, self.target)
        self.cli('propose', '--state', self.state, '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        self.target.unlink()
        if WINDOWS:
            self.target.mkdir()
        else:
            os.mkfifo(self.target)
        self.cli('propose', '--state', self.state, '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        if WINDOWS:
            self.target.rmdir()
        else:
            self.target.unlink()
        proposal = self.proposal()
        self.cli('propose', '--state', self.root / 'other-state', '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        self.cli('propose', '--state', self.state, '--target', self.root / 'other.md',
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        self.cli('propose', '--state', SCRIPT.parent / 'forbidden-state', '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        self.cli('propose', '--state', self.root / 'fresh-state', '--target', SCRIPT.parent / 'forbidden.md',
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        self.assertFalse((SCRIPT.parent / 'forbidden-state').exists())
        self.assertFalse((SCRIPT.parent / 'forbidden.md.pstack-guard.lock').exists())
        installed_skill = self.root / 'project/.agents/skills/herdr-demo'
        installed_skill.mkdir(parents=True)
        (installed_skill / 'SKILL.md').write_text('---\nname: herdr-demo\n---\n')
        for bad_state, bad_target in (
                (installed_skill / 'state', self.target),
                (self.root / 'fresh-state-2', installed_skill / 'reviewed.md'),
        ):
            result = self.cli('propose', '--state', bad_state, '--target', bad_target,
                              '--generated', self.generated, '--source', self.source_path,
                              '--owner', 'owned-test', ok=False)
            self.assertIn('skill trees', result['reason'])
        herdr_checkout = self.root / 'herdr-checkout'
        (herdr_checkout / '.agents/skills').mkdir(parents=True)
        (herdr_checkout / 'upstream/pstack').mkdir(parents=True)
        result = self.cli('propose', '--state', self.root / 'fresh-state-3',
                          '--target', herdr_checkout / 'reviewed.md',
                          '--generated', self.generated, '--source', self.source_path,
                          '--owner', 'owned-test', ok=False)
        self.assertIn('skill trees', result['reason'])
        self.cli(*self.promote_args(proposal))

    def test_target_directory_and_symlink_parent_are_rejected(self):
        self.target.mkdir()
        self.cli('propose', '--state', self.state, '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)
        alias = self.root / 'alias'
        link_directory(alias, self.root)
        self.cli('propose', '--state', self.state, '--target', alias / 'doc.md',
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)

    def test_case_variant_stays_bound_to_uncreated_target_on_case_insensitive_filesystem(self):
        parent = self.root / 'Mixed Case'
        parent.mkdir()
        alternate_parent = self.root / 'MIXED CASE'
        if not alternate_parent.exists():
            self.skipTest('fixture volume is case-sensitive')
        self.assertTrue(alternate_parent.samefile(parent))
        self.target = parent / 'Input Review.md'
        proposed = self.proposal()
        alternate = alternate_parent / 'Input REVIEW.md'
        receipt = self.cli(*self.promote_args(proposed, **{'--target': alternate}))
        self.assertEqual('committed', receipt['outcome'])
        self.assertEqual(self.generated.read_bytes(), self.target.read_bytes())
        self.assertEqual('already_committed', self.cli(
            'recover', '--state', self.state, '--target', alternate, '--operation-id', 'op-1')['outcome'])
        self.assertEqual([self.target.name + '.pstack-guard.lock'],
                         [candidate.name for candidate in parent.glob('*.pstack-guard.lock')])
        excluded = self.root / 'Excluded Root'
        alternate_root = self.root / 'EXCLUDED ROOT'
        next_target = parent / 'other.md'
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(excluded)}):
            with self.assertRaisesRegex(GUARD.GuardError, 'outside temporary and system directories'):
                GUARD.propose(alternate_root, next_target, self.generated, self.source, owner='owned-test')
        self.assertFalse(alternate_root.exists())
        self.assertFalse(next_target.with_name(next_target.name + '.pstack-guard.lock').exists())

    @unittest.skipIf(WINDOWS, 'Darwin POSIX path observation fixture')
    def test_darwin_absent_target_recovers_case_from_existing_sidecar(self):
        self.target = self.root / 'Mixed Case.md'
        self.proposal()
        alternate = self.root / 'MIXED CASE.md'
        lock = self.target.with_name(self.target.name + '.pstack-guard.lock')
        alternate_lock = alternate.with_name(alternate.name + '.pstack-guard.lock')
        lstat = Path.lstat

        def lookup(path):
            return lock if path == alternate_lock else path

        fs = GUARD._fs
        with patch.object(fs, 'DARWIN', True), patch.object(
                fs, '_darwin_realpath', lambda path: lookup(path).resolve(strict=True), create=True), patch.object(
                Path, 'lstat', lambda path, *args, **kwargs: lstat(lookup(path), *args, **kwargs)):
            self.assertEqual(self.target, GUARD._target_path(alternate))
            excluded = self.root / 'Excluded Root'
            alternative = self.root / 'EXCLUDED ROOT'
            with patch.object(fs, '_darwin_case_sensitive', return_value=False), patch.object(
                    fs, 'excluded_roots', return_value={excluded}):
                with self.assertRaisesRegex(GUARD.GuardError, 'outside temporary and system directories'):
                    with GUARD._locked(alternative, self.root / 'other.md', owner='owned-test'):
                        self.fail('entered the excluded root')
            with patch.object(fs, '_darwin_case_sensitive', return_value=True):
                self.assertFalse(fs.contains_path(alternative, excluded))
            self.assertFalse(alternative.exists())

    @unittest.skipUnless(WINDOWS, 'Windows short path names')
    def test_windows_short_temp_alias_is_excluded(self):
        import ctypes as C
        from ctypes import wintypes as W

        fs = GUARD._fs
        directory = self.root / 'Temporary directory with long name'
        directory.mkdir()
        short_name = C.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
        short_name.argtypes = [W.LPCWSTR, W.LPWSTR, W.DWORD]
        short_name.restype = W.DWORD
        buffer = C.create_unicode_buffer(32768)
        self.assertTrue(0 < short_name(str(directory), buffer, len(buffer)) < len(buffer),
                        f'GetShortPathNameW failed (WinError {C.get_last_error()})')
        short = Path(buffer.value)
        if short.name == directory.name:
            self.skipTest('fixture directory has no NTFS 8.3 alias')
        self.assertEqual(directory, fs.canonical_path(short))
        target = directory / 'review.md'
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(short)}):
            with self.assertRaisesRegex(GUARD.GuardError, 'outside temporary and system directories'):
                GUARD.propose(self.state, target, self.generated, self.source, owner='owned-test')
        self.assertFalse(self.state.exists())
        self.assertEqual([], list(directory.iterdir()))

    @unittest.skipUnless(WINDOWS, 'Windows file sharing')
    def test_windows_target_reader_denying_delete_retains_intent_for_retry(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        fs = GUARD._fs
        with fs._handle(self.target, fs._READ, share=3):
            failure = self.cli(*self.promote_args(proposal), ok=False)
            self.assertEqual('error', failure['outcome'])
            self.assertEqual(b'old\n', self.target.read_bytes())
            self.assertEqual('prepared', self.recover()['outcome'])
            self.assertFalse(list((self.state / 'operations').glob('*/receipt.json')))
        self.assertEqual('committed', self.cli(*self.promote_args(proposal))['outcome'])
        self.assertEqual('already_committed', self.recover()['outcome'])
        self.assertEqual(self.generated.read_bytes(), self.target.read_bytes())

    def test_public_api_and_source_boundary(self):
        proposal = GUARD.propose(self.state, self.target, self.generated, self.source, owner='owned-test')
        with self.assertRaises(GUARD.GuardError):
            GUARD.promote(self.state, self.target, proposal['proposal_id'], operation_id='api',
                          expect_target='absent', expect_draft=proposal['new_generated'])
        receipt = GUARD.promote(self.state, self.target, proposal['proposal_id'], operation_id='api',
                                expect_target='absent', expect_draft=proposal['new_generated'], single_writer=True)
        self.assertEqual(receipt['outcome'], 'committed')
        self.assertEqual(GUARD.recover(self.state, self.target, 'api')['outcome'], 'already_committed')
        malformed = self.source.as_dict()
        malformed['inputs'] = []
        self.source_path.write_text(json.dumps(malformed))
        self.cli('propose', '--state', self.state, '--target', self.target,
                 '--generated', self.generated, '--source', self.source_path,
                 '--owner', 'owned-test', ok=False)

    def test_missing_final_newline_has_a_valid_patch(self):
        self.target.write_bytes(b'old')
        self.generated.write_bytes(b'new')
        proposal = self.proposal()
        patch = Path(proposal['proposal_dir']) / 'target.diff'
        self.assertEqual(patch.read_bytes(),
                         b'--- target-before\n+++ draft\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n')
        copy = self.put('draft', b'old')
        result = subprocess.run(['git', '-c', 'core.autocrlf=false', 'apply', '--unsafe-paths', str(patch)], capture_output=True, text=True, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(copy.read_bytes(), b'new')

    def test_crlf_and_non_utf8_diffs_preserve_exact_bytes(self):
        self.target.write_bytes(b'unchanged\r\nold\xff\r\n')
        self.generated.write_bytes(b'unchanged\r\nnew\xfe\r\n')
        proposal = self.proposal()
        patch = Path(proposal['proposal_dir']) / 'target.diff'
        self.assertEqual(patch.read_bytes(),
                         b'--- target-before\n+++ draft\n@@ -1,2 +1,2 @@\n unchanged\r\n-old\xff\r\n+new\xfe\r\n')
        copy = self.put('draft', self.target.read_bytes())
        result = subprocess.run(['git', '-c', 'core.autocrlf=false', 'apply', '--unsafe-paths', str(patch)], capture_output=True, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(copy.read_bytes(), self.generated.read_bytes())

    def test_two_concurrent_same_id_promotions_commit_once(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        args = self.promote_args(proposal)
        first = self.fault(args, 'staged')
        second = subprocess.Popen([sys.executable, str(SCRIPT), *args],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.addCleanup(lambda: self.stop(second))
        if WINDOWS:
            lock = self.target.with_name(self.target.name + '.pstack-guard.lock')
            with self.assertRaises(PermissionError):
                lock.unlink()
        first.release_path.touch()
        first_out, first_err = first.communicate(timeout=10)
        second_out, second_err = second.communicate(timeout=10)
        self.assertEqual(first.returncode, 0, first_out + first_err)
        self.assertEqual(second.returncode, 0, second_out + second_err)
        self.assertEqual(json.loads(first_out)['outcome'], 'committed')
        self.assertEqual(json.loads(second_out)['outcome'], 'already_committed')
        self.assertEqual(len(list((self.state / 'operations').glob('*/receipt.json'))), 1)
        self.assertEqual(self.target.read_bytes(), b'new generated\n')

    def test_two_cooperative_subprocesses_serialize_and_release_after_kill(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        first = self.fault(self.promote_args(proposal), 'staged')
        args = self.promote_args(proposal, 'op-2', **{'--lock-timeout': '0.15'})
        self.assertEqual(self.cli(*args, ok=False)['outcome'], 'error')
        self.assertEqual(self.target.read_bytes(), b'old\n')
        self.stop(first)
        self.assertEqual(self.recover()['outcome'], 'prepared')
        self.cli(*self.promote_args(proposal))
        self.cli(*self.promote_args(proposal, 'op-2'), ok=False)
        self.assertEqual(self.target.read_bytes(), b'new generated\n')

    def test_final_recheck_occurs_after_staging_fsync(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        child = self.fault(self.promote_args(proposal), 'staged')
        self.target.write_bytes(b'edit during staging\n')
        child.release_path.touch()
        out, err = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 1, out + err)
        self.assertEqual(self.target.read_bytes(), b'edit during staging\n')
        self.assertEqual(self.recover(ok=False)['outcome'], 'conflict')

    def test_absent_creation_race_is_genuinely_no_clobber(self):
        proposal = self.proposal()
        child = self.fault(self.promote_args(proposal), 'absent_race')
        self.target.write_bytes(b'uncooperative creator won\n')
        child.release_path.touch()
        out, err = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 1, out + err)
        self.assertEqual(self.target.read_bytes(), b'uncooperative creator won\n')
        self.assertEqual(self.recover(ok=False)['outcome'], 'conflict')

    def test_prepared_fences_new_operations_and_altered_id_inputs(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        child = self.fault(self.promote_args(proposal), 'prepared', 'fail')
        out, err = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 1, out + err)
        self.cli(*self.promote_args(proposal, 'op-2'), ok=False)
        merged = self.put('merge.md', b'other\n')
        self.cli(*self.promote_args(proposal, **{'--decision': 'merge', '--merged': merged,
                                               '--expect-merged': sha(merged.read_bytes())}), ok=False)
        self.assertEqual(self.recover()['outcome'], 'prepared')
        self.cli(*self.promote_args(proposal))

    def test_killed_preintent_prepared_replaced_and_receipt_stages_recover(self):
        for phase in ('before_intent', 'prepared', 'replaced', 'receipt'):
            with self.subTest(phase=phase):
                directory = self.root / phase
                directory.mkdir()
                self.state = directory / 'state'
                self.target = directory / 'reviewed.md'
                self.target.write_bytes(b'old complete bytes\n')
                self.target.chmod(0o604)
                proposal = self.proposal()
                child = self.fault(self.promote_args(proposal), phase)
                self.stop(child)
                if phase == 'before_intent':
                    self.recover(ok=False)
                    self.assertEqual(self.target.read_bytes(), b'old complete bytes\n')
                    self.cli(*self.promote_args(proposal))
                elif phase == 'prepared':
                    self.assertEqual(self.recover()['outcome'], 'prepared')
                    self.assertEqual(self.target.read_bytes(), b'old complete bytes\n')
                    self.cli(*self.promote_args(proposal))
                else:
                    self.assertEqual(self.target.read_bytes(), b'new generated\n')
                    self.assertEqual(self.recover()['outcome'],
                                     'committed' if phase == 'replaced' else 'already_committed')
                self.assertEqual(self.target.read_bytes(), b'new generated\n')
                self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), expected_mode(0o604))
                self.target.write_bytes(b'edit after crash recovery\n')
                self.assertEqual(self.cli(*self.promote_args(proposal))['outcome'], 'already_committed')
                self.assertEqual(self.target.read_bytes(), b'edit after crash recovery\n')
                for file in self.state.rglob('*'):
                    if file.is_file():
                        self.assertEqual(file.stat().st_nlink, 1, str(file))

    def test_failing_replace_preserves_prior_bytes_and_can_resume(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        child = self.fault(self.promote_args(proposal), 'staged', 'fail')
        out, err = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 1, out + err)
        self.assertEqual(self.target.read_bytes(), b'old\n')
        self.assertEqual(self.recover()['outcome'], 'prepared')
        self.cli(*self.promote_args(proposal))

    def test_receipt_failure_after_replace_recovers_without_rewriting_target(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        child = self.fault(self.promote_args(proposal), 'before_receipt', 'fail')
        out, err = child.communicate(timeout=10)
        self.assertEqual(child.returncode, 1, out + err)
        self.assertEqual(self.target.read_bytes(), b'new generated\n')
        installed = self.target.stat()
        self.assertEqual(self.recover()['outcome'], 'committed')
        self.assertEqual(self.target.stat().st_ino, installed.st_ino)
        self.assertEqual(self.target.stat().st_mtime_ns, installed.st_mtime_ns)


    def merge_fixture(self, name):
        base = self.root / name
        base.mkdir()
        target, state, merged = base / 'target.md', base / 'state', base / 'merged.md'
        target.write_bytes(b'prior review\n')
        target.chmod(0o640)
        merged.write_bytes(b'accepted merge\n')
        proposal = self.cli('propose', '--state', state, '--target', target,
                            '--generated', self.generated, '--source', self.source_path, '--owner', 'owner')
        args = self.promote_args(proposal, **{'--state': state, '--target': target,
                                            '--decision': 'merge', '--merged': merged,
                                            '--expect-merged': sha(b'accepted merge\n')})
        return target, state, merged, args

    def interrupt_merge_syscall(self, args, base, phase):
        marker = base / 'paused'
        target = args[args.index('--target') + 1]
        child = subprocess.Popen([sys.executable, '-B', '-c', FAULT_RUNNER, str(SCRIPT),
                                  phase, 'stop', str(marker), target, *args],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.addCleanup(lambda: self.stop(child))
        deadline = time.monotonic() + 10
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not marker.exists():
            self.stop(child)
            self.fail('Durable syscall boundary not reached: ' + repr(child.communicate()))
        self.stop(child)
        self.assertNotEqual(0, child.returncode)

    def alter_merge(self, merged, change):
        merged.unlink()
        if change == 'changed':
            merged.write_bytes(b'obsolete changed bytes\n')
        elif change in ('symlink', 'dangling'):
            other = merged.with_name('other.md')
            if change == 'symlink':
                other.write_bytes(b'unrelated bytes\n')
            link_file(self, merged, other)

    def test_residual_g4_committed_promote_replay_ignores_historical_merge(self):
        target, state, merged, args = self.merge_fixture('committed')
        self.assertEqual('committed', self.cli(*args)['outcome'])
        target.write_bytes(b'later human edit\n')
        target.chmod(0o600)
        def observation():
            info = target.stat()
            return target.read_bytes(), info.st_ino, info.st_mode, info.st_mtime_ns
        before = observation()
        for change in ('changed', 'deleted', 'symlink', 'dangling'):
            with self.subTest(change=change):
                if not os.path.lexists(merged):
                    merged.write_bytes(b'temporary')
                self.alter_merge(merged, change)
                self.assertEqual('already_committed', self.cli(*args)['outcome'])
                self.assertEqual(before, observation())
                for flag, value in (('--merged', str(merged.parent / 'other.md')),
                                    ('--expect-merged', '0' * 64), ('--expect-draft', '0' * 64),
                                    ('--merged', str(merged.parent) + '/unused/../merged.md')):
                    altered = list(args)
                    altered[altered.index(flag) + 1] = value
                    self.assertEqual('error', self.cli(*altered, ok=False)['outcome'])
                    self.assertEqual(before, observation())

    def test_residual_g4_prepared_promote_resumes_retained_merge_after_syscall_kill(self):
        for change in ('changed', 'deleted', 'symlink', 'dangling'):
            with self.subTest(change=change):
                target, state, merged, args = self.merge_fixture('prepared-' + change)
                self.interrupt_merge_syscall(args, merged.parent, 'intent')
                before = target.stat()
                self.alter_merge(merged, change)
                self.assertEqual('prepared', self.cli('recover', '--state', state, '--target', target,
                                                     '--operation-id', 'op-1')['outcome'])
                altered = list(args)
                altered[altered.index('--expect-merged') + 1] = '0' * 64
                self.cli(*altered, ok=False)
                new_id = list(args)
                new_id[new_id.index('--operation-id') + 1] = 'another'
                self.cli(*new_id, ok=False)
                self.assertEqual(b'prior review\n', target.read_bytes())
                self.assertEqual((before.st_ino, before.st_mode, before.st_mtime_ns),
                                 (target.stat().st_ino, target.stat().st_mode, target.stat().st_mtime_ns))
                receipt = self.cli(*args)
                self.assertEqual('committed', receipt['outcome'])
                self.assertEqual(sha(b'accepted merge\n'), receipt['desired_target'])
                self.assertEqual(b'accepted merge\n', target.read_bytes())
                self.assertEqual(expected_mode(0o640), stat.S_IMODE(target.stat().st_mode))

    def test_residual_g4_request_only_requires_live_merge_input(self):
        for change in ('changed', 'deleted', 'symlink', 'dangling'):
            with self.subTest(change=change):
                target, state, merged, args = self.merge_fixture('request-' + change)
                self.interrupt_merge_syscall(args, merged.parent, 'request')
                operation = state / 'operations' / sha(b'op-1')
                self.assertTrue((operation / 'request.json').is_file())
                self.assertFalse((operation / 'intent.json').exists())
                self.alter_merge(merged, change)
                self.cli(*args, ok=False)
                self.assertFalse((operation / 'intent.json').exists())
                self.assertEqual(b'prior review\n', target.read_bytes())
                if os.path.lexists(merged):
                    merged.unlink()
                merged.write_bytes(b'accepted merge\n')
                self.assertEqual('committed', self.cli(*args)['outcome'])

    def test_residual_g4_fresh_aliases_and_prepared_target_edits_remain_rejected(self):
        target, state, merged, args = self.merge_fixture('protected')
        alias = merged.with_name('alias.md')
        link_file(self, alias, merged)
        aliased = list(args)
        aliased[aliased.index('--merged') + 1] = str(alias)
        self.cli(*aliased, ok=False)
        self.assertEqual([], list((state / 'operations').iterdir()))
        self.interrupt_merge_syscall(args, merged.parent, 'intent')
        self.alter_merge(merged, 'symlink')
        target.write_bytes(b'human edited while prepared\n')
        before = target.stat()
        self.cli(*args, ok=False)
        self.assertEqual(b'human edited while prepared\n', target.read_bytes())
        self.assertEqual((before.st_ino, before.st_mode, before.st_mtime_ns),
                         (target.stat().st_ino, target.stat().st_mode, target.stat().st_mtime_ns))

    def test_prepared_merge_resumes_from_retained_bytes_after_inputs_disappear(self):
        self.target.write_bytes(b'old reviewed\n')
        proposal = self.proposal()
        merged = self.put('merge.md', b'new generated\nhuman addition\n')
        args = self.promote_args(proposal, **{'--decision': 'merge', '--merged': merged,
                                            '--expect-merged': sha(merged.read_bytes())})
        child = self.fault(args, 'prepared')
        self.stop(child)
        merged.unlink()
        self.generated.unlink()
        self.source_path.unlink()
        self.assertEqual(self.recover()['outcome'], 'prepared')
        receipt = self.cli(*args)
        self.assertEqual(self.target.read_bytes(), b'new generated\nhuman addition\n')
        self.assertEqual(receipt['generated_baseline'], sha(b'new generated\n'))
        self.assertEqual(receipt['desired_target'], sha(b'new generated\nhuman addition\n'))

    def test_unknown_third_content_and_unreadable_recovery_preserve_everything(self):
        self.target.write_bytes(b'old\n')
        proposal = self.proposal()
        child = self.fault(self.promote_args(proposal), 'prepared')
        self.stop(child)
        original = {str(p.relative_to(self.state)): p.read_bytes()
                    for p in self.state.rglob('*') if p.is_file()}
        self.target.write_bytes(b'third-party bytes\n')
        self.assertEqual(self.recover(ok=False)['outcome'], 'conflict')
        self.assertEqual(self.target.read_bytes(), b'third-party bytes\n')
        self.target.unlink()
        link_file(self, self.target, self.generated)
        self.assertEqual(self.recover(ok=False)['outcome'], 'error')
        self.target.unlink()
        self.target.mkdir()
        self.assertEqual(self.recover(ok=False)['outcome'], 'uncertain')
        for relative, data in original.items():
            self.assertEqual((self.state / relative).read_bytes(), data)
        self.assertTrue(self.target.is_dir())


if __name__ == '__main__':
    unittest.main()
