"""Exercise evidence commands from a staged copy of the installed plugin."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from evidence_test_support import assert_darwin_identity, remove_tree


PLUGIN = Path(__file__).resolve().parents[1] / 'plugins/pstack'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def inventory(plugin):
    return {p.relative_to(plugin).as_posix(): sha(p.read_bytes()) for p in plugin.rglob('*') if p.is_file()}


def load(path):
    spec = importlib.util.spec_from_file_location('evidence_smoke', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def prepare(root):
    plugin = root / 'staged plugin'
    shutil.copytree(PLUGIN, plugin)
    (root / 'plugin-inventory.json').write_bytes(json_bytes(inventory(plugin)))
    # Retain Unicode/spaces on every host. The snapshot path also crosses
    # MAX_PATH on Windows, including the content-addressed directory name.
    evidence = root / '証拠 with spaces'
    if sys.platform == 'win32':
        evidence = evidence / ('long directory ' + 'a' * 100) / ('nested ' + 'b' * 90)
    evidence.mkdir(parents=True)
    scripts = plugin / 'skills/poteto-mode/scripts'
    request, candidate = evidence / 'request.json', evidence / 'candidate file.py'
    candidate.write_bytes(b'pass\n')
    raw, diff = evidence / 'result.dat', evidence / 'change.diff'
    raw.write_bytes(b'{"working":true}\n')
    diff.write_bytes(b'+ preserve bytes\n')
    environment = evidence / 'environment.txt'
    environment.write_bytes(b'Python local smoke fixture\n')
    artifacts = [{'id': name, 'kind': kind, 'state': 'available', 'source': {'path': str(path), 'host': 'local'},
                  'sha256': sha(path.read_bytes()), 'media_type': 'application/octet-stream'}
                 for name, kind, path in [('candidate', 'source', candidate), ('raw', 'raw', raw),
                                           ('diff', 'diff', diff), ('environment', 'environment', environment)]]
    review = {'owner': 'owner', 'revision': 'r1', 'items': [
        {'id': 'inspect', 'candidate': 'fixed', 'subject': 'diff', 'description': 'Inspect captured bytes'}]}
    observed, expiry = '2026-11-17T00:00:03Z', '2026-11-18T00:00:00Z'
    request.write_bytes(json_bytes({
        'schema': 'pstack-evidence/1', 'task_id': 'smoke', 'owner': 'owner',
        'retention': {'owner': 'owner', 'durable_root': str(evidence), 'cleanup_after': None},
        'actors': [{'id': name, 'role': name} for name in ('owner', 'author', 'reviewer')],
        'candidates': [{'id': 'fixed', 'sha256': artifacts[0]['sha256'], 'author': 'author', 'artifact': 'candidate'}],
        'resources': [{'id': 'runtime', 'owner': 'owner', 'generation': 'start-1', 'environment': 'local',
                       'observed_at': '2026-11-17T00:00:00Z', 'expires_at': expiry}],
        'artifacts': artifacts, 'notes': [],
        'records': [{'id': 'run-1', 'candidate': 'fixed', 'observer': 'author', 'observed_at': observed,
                     'resource': 'runtime', 'resource_owner': 'owner', 'resource_generation': 'start-1',
                     'environment': 'local', 'expires_at': expiry, 'evidence_type': 'executed',
                     'declared_outcome': 'pass', 'rechecks': None, 'limitation': None, 'artifacts': ['raw', 'environment'],
                     'producer': {'name': 'smoke', 'artifact': None},
                     'command': {'argv': ['never-executed'], 'cwd': str(evidence), 'exit_code': 0,
                                 'started_at': '2026-11-17T00:00:01Z', 'finished_at': '2026-11-17T00:00:02Z',
                                 'execution_id': 'run-1'},
                     'harness': {'description': 'Local fixture', 'substitutions': [], 'boundaries': ['Captured JSON']}}],
        'cases': [{'id': 'check', 'candidate': 'fixed', 'scenario': 'local', 'scenario_sha256': 'a' * 64,
                   'entry': 'read captured JSON', 'expected': {'kind': 'json_equal', 'value': {'working': True}},
                   'actual': {'kind': 'artifact', 'artifact': 'raw', 'format': 'json'}, 'records': ['run-1']}],
        'review_inventory': review,
        'reviews': [{'item': 'inspect', 'reviewer': 'reviewer', 'candidate_sha256': artifacts[0]['sha256'],
                     'subject_sha256': artifacts[2]['sha256'], 'inventory_sha256': sha(json_bytes(review)),
                     'disposition': 'accept', 'reason': 'The recorded output matches the expected JSON.',
                     'evidence': ['diff'], 'limitation': None}],
    }))
    (evidence / 'bad.json').write_bytes(b'{')
    (evidence / 'bom.json').write_bytes(b'\xef\xbb\xbf' + request.read_bytes())
    return {name: str(path) for name, path in {
        'task': scripts / 'task_evidence.py', 'guard': scripts / 'guarded_document.py',
        'validation': scripts / 'validation-evidence.py', 'request': request, 'candidate': candidate,
        'archive': evidence / 'archive', 'render': evidence / 'render pair', 'target': evidence / '審査 notes.md',
        'state': evidence / 'document state', 'bad': evidence / 'bad.json', 'bom': evidence / 'bom.json',
        'preflight': evidence / 'preflight.json',
    }.items()}


def verify_plugin(root):
    plugin = root / 'staged plugin'
    assert not list(plugin.rglob('__pycache__'))
    assert inventory(plugin) == json.loads((root / 'plugin-inventory.json').read_bytes())


def smoke(paths):
    def cli(tool, *args, exit_code=0):
        completed = subprocess.run([sys.executable, paths[tool], *args], capture_output=True,
                                   encoding='utf-8', timeout=45)
        assert completed.returncode == exit_code and not completed.stderr, completed
        return json.loads(completed.stdout)

    snapshot = cli('task', 'preserve', '--input', paths['request'], '--store', paths['archive'])
    pin = ('--snapshot', snapshot['snapshot'], '--sha256', snapshot['snapshot_sha256'])
    assert cli('task', 'check', *pin)['archive_integrity'] == 'valid'
    binding = ('--state', paths['state'], '--target', paths['target'])
    rendered = cli('task', 'render', *pin, '--out', paths['render'],
                   '--document-state', paths['state'], '--target', paths['target'],
                   '--document-owner', 'owner')
    proposal = rendered['proposal']
    target = Path(paths['target'])
    assert proposal['outcome'] == 'proposed' and not target.exists()
    assert cli('guard', 'promote', *binding, '--operation-id', 'smoke', '--decision', 'replace',
               '--proposal', proposal['proposal_id'], '--expect-target', 'absent',
               '--expect-draft', proposal['new_generated'], '--single-writer')['outcome'] == 'committed'
    assert target.read_bytes() == (Path(paths['render']) / 'summary.md').read_bytes()
    assert cli('guard', 'recover', *binding, '--operation-id', 'smoke')['outcome'] == 'already_committed'
    assert cli('task', 'publication', '--render', rendered['render'], '--sha256',
               rendered['render_sha256'])['status'] == 'valid'
    assert cli('task', 'preserve', '--input', paths['bad'], '--store', paths['archive'],
               exit_code=1)['status'] == 'invalid'
    assert cli('task', 'preserve', '--input', paths['bom'], '--store', paths['archive'],
               exit_code=1)['findings'][0]['code'] == 'schema_invalid'
    assert cli('validation', 'preflight', paths['bad'], exit_code=1)['outcome'] == 'invalid'
    assert cli('guard', 'recover', *binding, '--operation-id', 'absent', exit_code=1)['outcome'] == 'error'

    argv = [sys.executable, '-c', 'import sys; print("ready", flush=True); sys.stdin.read()',
            '証拠 with spaces', '']
    earliest = time.time_ns()
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
        try:
            latest = time.time_ns()
            assert child.stdout.readline().rstrip() == b'ready'
            process = load(Path(paths['validation'])).read_local_process(child.pid)
            if sys.platform == 'darwin':
                assert process['argv'] == argv, process
                assert_darwin_identity(process, earliest, latest)
            candidate = paths['candidate']
            preflight = {'candidate': 'fixed', 'source_mode': 'local',
                         'files': [{'host': candidate, 'visible': candidate, 'sha256': sha(Path(candidate).read_bytes())}],
                         'process': process}
            Path(paths['preflight']).write_bytes(json_bytes(preflight))
            checked = cli('validation', 'preflight', paths['preflight'], exit_code=1)
            assert (checked['source_status'], checked['process_status'], checked['loaded_candidate']) == (
                'verified', 'verified', 'unknown'), checked
        finally:
            child.kill()
    checked = cli('validation', 'preflight', paths['preflight'], exit_code=1)
    assert checked['process_status'] == 'unknown', checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--prepare', action='store_true', help='print a new fixture for PowerShell')
    group.add_argument('--verify-and-remove', type=Path, metavar='ROOT', help='verify and remove a prepared fixture')
    args = parser.parse_args()
    parent = (Path.home() / '.local/state/pstack-evidence-smoke').resolve()
    parent.mkdir(parents=True, exist_ok=True)
    if args.verify_and_remove:
        root = args.verify_and_remove.resolve()
        if root.parent != parent or not root.name.startswith('smoke-'):
            parser.error('expected a prepared smoke fixture')
        try:
            verify_plugin(root)
        finally:
            remove_tree(root)
        return
    root = Path(tempfile.mkdtemp(prefix='smoke-', dir=parent))
    try:
        paths = prepare(root)
        if args.prepare:
            print(json.dumps({'root': str(root), **paths}, ensure_ascii=True))
            return
        smoke(paths)
        verify_plugin(root)
        print(f'Staged evidence CLI smoke passed on {sys.platform}')
    finally:
        if not args.prepare:
            remove_tree(root)


if __name__ == '__main__':
    main()
