#!/usr/bin/env python3
"""Preserve, inspect and render task evidence without executing recorded commands."""

import argparse
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import socket
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone


# Load the installed sibling without creating bytecode or searching sys.path.
def _load_filesystem():
    path = Path(__file__).resolve().with_name('evidence_fs.py')
    spec = importlib.util.spec_from_file_location('_pstack_evidence_fs', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


_fs = _load_filesystem()


SCHEMA = 'pstack-evidence/1'
KINDS = {'raw', 'command', 'environment', 'report', 'trace', 'diff', 'blame', 'recorder', 'source'}
TYPES = {'executed', 'independent_recheck', 'historical_secondary', 'environment_snapshot'}
MAX_BYTES = 16 * 1024 * 1024
PLUGIN_ROOT = Path(__file__).resolve().parents[3]


class EvidenceError(ValueError):
    def __init__(self, code, subject, reason):
        self.finding = {'code': code, 'subject': str(subject), 'reason': reason}
        super().__init__(reason)


def _fail(code, subject, reason):
    raise EvidenceError(code, subject, reason)


def _require(condition, subject, reason, code='schema_invalid'):
    if not condition:
        _fail(code, subject, reason)


def _document_guard():
    path = Path(__file__).resolve().with_name('guarded_document.py')
    name = '_pstack_guarded_document_' + hashlib.sha256(os.fsencode(path)).hexdigest()
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            # The installed plugin must stay byte-for-byte unchanged.
            exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        except BaseException:
            del sys.modules[name]
            raise
    return sys.modules[name]


def canonical(value):
    """Canonical UTF-8 JSON used by snapshot, inventory and render identities."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, key, 'duplicate JSON key')
        result[key] = value
    return result


def _decode(data):
    def finite(value):
        number = float(value)
        _require(math.isfinite(number), value, 'nonfinite JSON number')
        return number

    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_float=finite,
                          parse_constant=lambda value: _fail('schema_invalid', value, 'nonfinite JSON number'))
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        _fail('schema_invalid', 'JSON', str(exc))


def _regular(path, expected=None, *, anchor=None):
    path = Path(path)
    try:
        data, _ = _fs.read_regular(path, max_bytes=MAX_BYTES, anchor=anchor)
    except FileNotFoundError:
        _fail('missing_source', path, 'file does not exist')
    except _fs.UnsupportedFile as exc:
        _fail('unsupported_file', path, str(exc))
    except _fs.SourceChanged as exc:
        _fail('source_changed', path, str(exc))
    except _fs.SizeLimit:
        _fail('size_limit', path, 'file exceeds 16 MiB limit')
    except _fs.CapabilityError as exc:
        _fail('unsupported_capability', path, str(exc))
    except (ValueError, OSError) as exc:
        _fail('io_error', path, str(exc))
    if expected is not None:
        _require(digest(data) == expected, path, 'bytes differ from expected SHA-256', 'hash_mismatch')
    return data


def read_json(path, expected=None):
    return _decode(_regular(path, expected))


def _fields(value, required, optional=''):
    _require(type(value) is dict, 'object', 'expected JSON object')
    required, optional = set(required.split()), set(optional.split())
    _require(required <= value.keys(), 'object', 'missing fields: ' + ', '.join(sorted(required - value.keys())))
    _require(value.keys() <= required | optional, 'object', 'unknown fields: ' + ', '.join(sorted(value.keys() - required - optional)))
    return value


def _text(value, subject='text'):
    _require(isinstance(value, str) and bool(value.strip()), subject, 'expected nonempty string')
    return value


def _id(value):
    _text(value, 'id')
    _require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]*', value) is not None, value, 'invalid identifier')
    return value


def _ref(value, index, subject):
    _id(value)
    _require(value in index, subject, 'unknown reference: ' + value)


def _sha(value):
    _require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None,
             'sha256', 'expected lowercase SHA-256')
    return value


def _time(value):
    _text(value, 'timestamp')
    _require(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z', value) is not None,
             value, 'expected RFC3339 UTC timestamp ending in Z')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        _fail('schema_invalid', value, str(exc))


def _path(value):
    _text(value, 'path')
    _require(Path(value).is_absolute(), value, 'expected absolute path')
    try:
        _fs.validate_path(value)
    except ValueError as exc:
        _fail('schema_invalid', value, str(exc))
    return Path(value)


def _list(value, subject='array', nonempty=False):
    _require(type(value) is list and (not nonempty or bool(value)), subject, 'expected ' + ('nonempty ' if nonempty else '') + 'array')
    return value


def _index(items, key='id', nonempty=False):
    result = {}
    for item in _list(items, key, nonempty):
        _require(type(item) is dict and key in item, key, 'missing identity')
        ident = _id(item[key])
        _require(ident not in result, ident, 'duplicate identity')
        result[ident] = item
    return result


def _refs(values, index, subject, nonempty=False):
    _list(values, subject, nonempty)
    _require(all(isinstance(v, str) for v in values), subject, 'references must be strings')
    _require(len(set(values)) == len(values), subject, 'duplicate references')
    for value in values:
        _require(value in index, subject, 'unknown reference: ' + value)


def _alias(first, second):
    first, second = Path(first), Path(second)
    return _fs.canonical_path(first) == _fs.canonical_path(second) or (first.exists() and second.exists() and _fs.identity(first) == _fs.identity(second))


def _resource(resource, actors):
    _fields(resource, 'id owner generation environment observed_at expires_at')
    for key in ('id', 'owner', 'generation', 'environment'):
        _id(resource[key])
    _require(resource['owner'] in actors, resource['id'], 'unknown resource owner')
    _time(resource['observed_at'])
    _time(resource['expires_at'])


def _result(value, actual=False):
    if actual:
        _fields(value, 'kind', 'artifact format reason')
        _text(value['kind'])
        _require(value['kind'] in {'artifact', 'unverified'}, 'actual', 'unsupported actual type')
        if value['kind'] == 'artifact':
            _fields(value, 'kind artifact format')
            _id(value['artifact'])
            _text(value['format'])
            _require(value['format'] in {'json', 'utf8'}, 'actual', 'unsupported format')
        else:
            _fields(value, 'kind reason')
            _text(value['reason'])
    else:
        _fields(value, 'kind value')
        _text(value['kind'])
        _require(value['kind'] in {'json_equal', 'text_equal'}, 'expected', 'unsupported expectation')
        if value['kind'] == 'text_equal':
            _require(isinstance(value['value'], str), 'expected', 'text expectation must be string')
        canonical(value['value'])


def inventory_digest(inventory):
    value = copy.deepcopy(inventory)
    value['items'] = sorted(value['items'], key=lambda item: item['id'])
    return digest(canonical(value))


def _manifest(value, preserved=False):
    try:
        value = _decode(canonical(value))
    except (TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        _fail('schema_invalid', 'manifest', str(exc))
    _fields(value, 'schema task_id owner retention actors candidates resources artifacts records cases review_inventory reviews notes')
    _require(value['schema'] == SCHEMA, 'schema', 'unsupported schema version')
    _id(value['task_id'])
    actors = _index(value['actors'], nonempty=True)
    for actor in actors.values():
        _fields(actor, 'id role')
        _text(actor['role'])
        _require(actor['role'] in {'owner', 'author', 'verifier', 'reviewer'}, actor['id'], 'unknown actor role')
    _ref(value['owner'], actors, 'owner')
    _require(actors[value['owner']]['role'] == 'owner', 'owner', 'expected declared owner actor')
    retention = _fields(value['retention'], 'owner durable_root cleanup_after')
    _require(retention['owner'] == value['owner'], 'retention', 'retention owner mismatch', 'owner_mismatch')
    _path(retention['durable_root'])
    if retention['cleanup_after'] is not None:
        _time(retention['cleanup_after'])
    candidates = _index(value['candidates'], nonempty=True)
    for candidate in candidates.values():
        _fields(candidate, 'id sha256 author artifact')
        _sha(candidate['sha256'])
        _id(candidate['artifact'])
        _ref(candidate['author'], actors, candidate['id'])
    resources = _index(value['resources'])
    for resource in resources.values():
        _resource(resource, actors)
    artifacts = _index(value['artifacts'], nonempty=True)
    for artifact in artifacts.values():
        _fields(artifact, 'id kind source state', 'sha256 media_type size missing_reason')
        _require(artifact['id'] not in {'summary', 'cases'}, artifact['id'], 'artifact ID is reserved for rendered reports')
        _text(artifact['kind'])
        _require(artifact['kind'] in KINDS, artifact['id'], 'unknown artifact kind')
        _fields(artifact['source'], 'path host')
        _path(artifact['source']['path'])
        _text(artifact['source']['host'])
        if artifact['state'] == 'missing':
            _fields(artifact, 'id kind source state missing_reason sha256')
            _text(artifact['missing_reason'])
            if artifact['sha256'] is not None:
                _sha(artifact['sha256'])
        else:
            fields = 'id kind source state sha256 media_type' + (' size' if preserved else '')
            _fields(artifact, fields)
            _require(artifact['state'] == ('preserved' if preserved else 'available'), artifact['id'], 'invalid artifact state')
            _sha(artifact['sha256'])
            _text(artifact['media_type'])
            if preserved:
                _require(type(artifact['size']) is int and 0 <= artifact['size'] <= MAX_BYTES, artifact['id'], 'invalid size')
    for candidate in candidates.values():
        _ref(candidate['artifact'], artifacts, candidate['id'])
        _require(candidate['sha256'] == artifacts[candidate['artifact']]['sha256'], candidate['id'],
                 'candidate content identity differs from candidate artifact', 'candidate_mismatch')
    for note in _list(value['notes']):
        _path(note)
    records = _index(value['records'])
    for record in records.values():
        _fields(record, 'id candidate observer observed_at evidence_type resource resource_owner resource_generation environment expires_at command harness artifacts declared_outcome rechecks limitation producer')
        ident = record['id']
        _ref(record['candidate'], candidates, ident)
        _ref(record['observer'], actors, ident)
        _text(record['evidence_type'])
        _require(record['evidence_type'] in TYPES, ident, 'unknown evidence type')
        _ref(record['resource'], resources, ident)
        for key in ('resource_owner', 'resource_generation', 'environment'):
            _id(record[key])
        _require(record['resource_owner'] in actors, ident, 'unknown resource owner')
        _time(record['observed_at'])
        _time(record['expires_at'])
        _text(record['declared_outcome'])
        _require(record['declared_outcome'] in {'pass', 'fail', 'unknown'}, ident, 'invalid declared outcome')
        if record['limitation'] is not None:
            _text(record['limitation'])
        _fields(record['harness'], 'description substitutions boundaries')
        _text(record['harness']['description'])
        for substitution in _list(record['harness']['substitutions']):
            _fields(substitution, 'component replacement impact')
            for text in substitution.values():
                _text(text)
        for boundary in _list(record['harness']['boundaries']):
            _text(boundary)
        _refs(record['artifacts'], artifacts, ident, True)
        command = _fields(record['command'], 'argv cwd exit_code started_at finished_at execution_id')
        for argument in _list(command['argv']):
            _require(isinstance(argument, str), ident, 'argv entries must be strings')
        _path(command['cwd'])
        _require(command['exit_code'] is None or type(command['exit_code']) is int, ident, 'exit code must be integer or null')
        for key in ('started_at', 'finished_at'):
            if command[key] is not None:
                _time(command[key])
        if command['execution_id'] is not None:
            _id(command['execution_id'])
        producer = _fields(record['producer'], 'name artifact')
        _text(producer['name'])
        if producer['artifact'] is not None:
            _id(producer['artifact'])
            _require(producer['artifact'] in record['artifacts'], ident, 'producer artifact must be included')
        available = [artifacts[a] for a in record['artifacts'] if artifacts[a]['state'] != 'missing']
        kinds = {a['kind'] for a in available}
        if record['evidence_type'] in {'executed', 'independent_recheck'}:
            _require(artifacts[candidates[record['candidate']]['artifact']]['state'] != 'missing', ident,
                     'execution requires preserved candidate content')
            _require(bool(command['argv']) and command['exit_code'] is not None and command['execution_id'] is not None,
                     ident, 'execution requires argv, exit code and execution ID')
            _require(command['started_at'] is not None and command['finished_at'] is not None, ident, 'execution requires times')
            _require(bool(kinds & {'raw', 'trace'}) and 'environment' in kinds, ident, 'execution requires original raw/trace and environment bytes')
            _require(all(artifacts[a]['state'] != 'missing' for a in record['artifacts']), ident, 'execution cannot claim missing evidence')
        elif record['evidence_type'] == 'historical_secondary':
            _require('report' in kinds and record['limitation'] is not None, ident, 'historical secondary requires retained report and missing-original limitation')
            _require(any(artifacts[a]['state'] == 'missing' for a in record['artifacts']), ident, 'historical secondary must identify missing originals')
            _require(command['execution_id'] is None, ident, 'historical report cannot declare new execution identity')
        else:
            _require('environment' in kinds and record['declared_outcome'] == 'unknown', ident, 'environment snapshot cannot declare behavioral outcome')
        if record['evidence_type'] != 'independent_recheck':
            _require(record['rechecks'] is None, ident, 'only independent recheck references an original run')
    for record in records.values():
        if record['evidence_type'] != 'independent_recheck':
            continue
        ident = record['id']
        _id(record['rechecks'])
        _require(record['rechecks'] in records and record['rechecks'] != ident, ident, 'missing original execution')
        original = records[record['rechecks']]
        _require(original['evidence_type'] == 'executed' and original['candidate'] == record['candidate'], ident, 'recheck requires same-candidate original execution')
        _require(record['observer'] not in {candidates[record['candidate']]['author'], original['observer']}, ident, 'recheck observer is not independent', 'independence_unverified')
        _require(actors[record['observer']]['role'] == 'verifier', ident, 'recheck requires verifier role')
        peers = [r for r in records.values() if r['id'] != ident and r['evidence_type'] in {'executed', 'independent_recheck'}]
        _require(all(record['command']['execution_id'] != r['command']['execution_id'] for r in peers),
                 ident, 'recheck reused an execution ID', 'independence_unverified')
        peer_captures = [artifacts[a]['source']['path'] for r in peers for a in r['artifacts']
                         if artifacts[a]['kind'] in {'raw', 'trace'}]
        same_capture = (lambda first, second: os.path.normpath(first) == os.path.normpath(second)) if preserved else _alias
        _require(not any(same_capture(artifacts[a]['source']['path'], path) for a in record['artifacts']
                         if artifacts[a]['kind'] in {'raw', 'trace'} for path in peer_captures),
                 ident, 'recheck reused an execution capture', 'independence_unverified')
    cases = _index(value['cases'], nonempty=True)
    scoped = set()
    for case in cases.values():
        _fields(case, 'id candidate scenario scenario_sha256 entry expected actual records')
        _ref(case['candidate'], candidates, case['id'])
        _id(case['scenario'])
        _sha(case['scenario_sha256'])
        _text(case['entry'])
        scope = (case['candidate'], case['scenario'])
        _require(scope not in scoped, case['id'], 'duplicate candidate/scenario case')
        scoped.add(scope)
        _result(case['expected'])
        _result(case['actual'], True)
        _refs(case['records'], records, case['id'], True)
        _require(all(records[r]['candidate'] == case['candidate'] for r in case['records']), case['id'], 'record candidate differs from case', 'candidate_mismatch')
        if case['actual']['kind'] == 'artifact':
            artifact = case['actual']['artifact']
            _require(artifact in artifacts and artifacts[artifact]['state'] != 'missing', case['id'], 'actual result must have available bytes')
            _require(artifacts[artifact]['kind'] in {'raw', 'trace'}, case['id'], 'measured actual requires raw or trace output')
            _require(any(artifact in records[r]['artifacts'] for r in case['records']), case['id'], 'actual result is not in a case record')
            _require(any(records[r]['evidence_type'] in {'executed', 'independent_recheck'} and artifact in records[r]['artifacts'] for r in case['records']), case['id'], 'historical/environment evidence cannot supply measured actual')
            _require(case['actual']['format'] == ('json' if case['expected']['kind'] == 'json_equal' else 'utf8'), case['id'], 'actual format differs from expectation kind')
    inventory = _fields(value['review_inventory'], 'owner revision items')
    _require(inventory['owner'] == value['owner'], 'review_inventory', 'only package owner declares inventory', 'owner_mismatch')
    _id(inventory['revision'])
    requirements = _index(inventory['items'], nonempty=True)
    for requirement in requirements.values():
        _fields(requirement, 'id candidate subject description')
        _ref(requirement['candidate'], candidates, requirement['id'])
        _ref(requirement['subject'], artifacts, requirement['id'])
        _text(requirement['description'])
    reviews = _index(value['reviews'], 'item')
    for review in reviews.values():
        _fields(review, 'item reviewer candidate_sha256 subject_sha256 inventory_sha256 disposition reason evidence limitation')
        _require(review['item'] in requirements, review['item'], 'review outside required inventory')
        _ref(review['reviewer'], actors, review['item'])
        _require(actors[review['reviewer']]['role'] == 'reviewer', review['item'], 'expected reviewer role')
        for key in ('candidate_sha256', 'subject_sha256', 'inventory_sha256'):
            _sha(review[key])
        _text(review['disposition'])
        _require(review['disposition'] in {'accept', 'change', 'defer', 'reject'}, review['item'], 'unknown disposition')
        _require(isinstance(review['reason'], str), review['item'], 'reason must be string')
        _refs(review['evidence'], artifacts, review['item'])
        if review['limitation'] is not None:
            _text(review['limitation'])
    for key in ('actors', 'candidates', 'resources', 'artifacts', 'records', 'cases'):
        value[key].sort(key=lambda item: item['id'])
    value['reviews'].sort(key=lambda item: item['item'])
    value['review_inventory']['items'].sort(key=lambda item: item['id'])
    return value


@dataclass(frozen=True)
class Snapshot:
    """Pinned canonical manifest; each data access returns an independent value."""
    path: Path
    sha256: str
    _bytes: bytes

    def __post_init__(self):
        _sha(self.sha256)
        _require(type(self._bytes) is bytes and digest(self._bytes) == self.sha256,
                 str(self.path), 'snapshot bytes differ from pinned identity', 'hash_mismatch')

    @property
    def data(self):
        return _decode(self._bytes)

    @classmethod
    def read(cls, path, expected_sha256):
        _sha(expected_sha256)
        declared = _path(str(path))
        path = _fs.canonical_path(declared)
        if _fs.WINDOWS:
            _require(path == declared, declared, 'snapshot path has a reparse alias', 'retention_invalid')
        data = _regular(path, expected_sha256, anchor=path.parent)
        manifest = _manifest(_decode(data), preserved=True)
        _require(canonical(manifest) == data, path, 'snapshot must be normalized canonical JSON')
        _require(path.name == 'manifest.json' and path.parent.name == expected_sha256 and path.parent.parent.name == 'snapshots', path, 'invalid snapshot layout')
        return cls(path, expected_sha256, data)

    def artifact_bytes(self, artifact_id):
        artifacts = {a['id']: a for a in self.data['artifacts']}
        _require(artifact_id in artifacts, artifact_id, 'unknown artifact')
        artifact = artifacts[artifact_id]
        _require(artifact['state'] == 'preserved', artifact_id, 'original evidence is missing', 'missing_original')
        store = self.path.parents[2]
        path = store / 'objects' / artifact['sha256']
        _require(_fs.canonical_path(path.parent) == store / 'objects', artifact_id, 'object directory is a symlink escape', 'retention_invalid')
        try:
            data = _regular(path, artifact['sha256'], anchor=store)
        except EvidenceError as exc:
            if exc.finding['code'] == 'missing_source':
                _fail('missing_preserved', artifact_id, 'preserved object does not exist')
            raise
        _require(len(data) == artifact['size'], artifact_id, 'preserved size mismatch', 'hash_mismatch')
        return data


def _skill_roots(path):
    roots = [_fs.canonical_path(PLUGIN_ROOT)]
    home = Path.home()
    configs = {home / relative for relative in (
        '.codex', '.claude', '.kiro', '.agents', '.gemini/config', '.cursor',
    )}
    for variable in ('CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'KIRO_HOME'):
        if os.environ.get(variable):
            configs.add(Path(os.environ[variable]).expanduser())
    for config in configs:
        base = config / 'skills'
        roots.append(_fs.canonical_path(base))
        if base.is_dir():
            roots.extend(_fs.canonical_path(child) for child in base.iterdir()
                         if (child / 'SKILL.md').is_file())
    for parent in (path, *path.parents):
        if any((parent / f'.{host}-plugin/plugin.json').is_file()
               for host in ('codex', 'claude', 'antigravity')) or (
                (parent / 'SKILL.md').is_file() and (parent / 'library/skills').is_dir()) or (
                (parent / '.agents/skills').is_dir() and (parent / 'upstream/pstack').is_dir()) or (
                (parent / 'SKILL.md').is_file() and parent.parent.name == 'skills'
                and len(parent.parents) >= 2 and parent.parents[1].name == '.agents'):
            roots.append(parent)
    return roots


def _durable(store, retention):
    store = _path(str(store))
    declared_root = _path(retention['durable_root'])
    resolve = _fs.unaliased_path if _fs.WINDOWS or _fs.DARWIN else _fs.canonical_path
    try:
        root, resolved_store = resolve(declared_root), resolve(store)
    except _fs.UnsupportedFile as exc:
        _fail('retention_invalid', store, str(exc))
    _require(root != root.parent, root, 'filesystem roots cannot hold retention', 'retention_invalid')
    _require(_fs.contains_path(resolved_store, root), store, 'store lies outside declared durable root', 'retention_invalid')
    excluded = _fs.excluded_roots()
    for path in (resolved_store, root):
        _require(not any(_fs.contains_path(path, p) for p in excluded)
                 and not any(_fs.contains_path(path, r) for r in _skill_roots(path)), path,
                 'retention must be outside installed skill and ephemeral roots', 'retention_invalid')
    try:
        _fs.owned_directory(declared_root)
    except _fs.CapabilityError:
        raise
    except OSError as exc:
        _fail('retention_invalid', root, str(exc))
    return resolved_store, root


def _install(path, data, conflict_code='hash_mismatch'):
    _require(_fs.canonical_path(path.parent) == path.parent, path,
             'immutable destination has symlink parents', 'retention_invalid')
    _fs.ensure_directory(path.parent, parents=True)
    with _fs.stage(path.parent, data) as staged:
        try:
            if sys.platform.startswith('linux'):
                os.link(staged.path, path)
            else:
                _fs.publish_new(staged, path)
        except FileExistsError:
            _require(_regular(path, anchor=path.parent) == data, path,
                     'existing immutable bytes differ', conflict_code)
        _fs.sync_directory(path.parent)


def preserve(request, store):
    """Copy local inputs after validating their expected hashes. Never run argv."""
    manifest = _manifest(request)
    store, root = _durable(store, manifest['retention'])
    owner = {'schema': 'pstack-retention/1', 'task_id': manifest['task_id'],
             'owner': manifest['owner'], 'durable_root': str(root),
             'cleanup_after': manifest['retention']['cleanup_after']}
    _fs.ensure_directory(store, parents=True)
    _fs.require_same_volume(store, root)
    _fs.sync_directory(store.parent)
    _install(store / 'owner.json', canonical(owner), 'owner_mismatch')
    notes = [_fs.canonical_path(p) for p in manifest['notes']]
    for artifact in manifest['artifacts']:
        if artifact['state'] == 'missing':
            continue
        source = artifact['source']
        _require(source['host'] == 'local', artifact['id'], 'transfer remote evidence separately and verify bytes', 'remote_source_unavailable')
        path = Path(source['path'])
        _require(_fs.canonical_path(path) not in notes and not any(note.exists() and path.exists() and _fs.identity(path) == _fs.identity(note) for note in notes), artifact['id'], 'raw evidence aliases a mutable note', 'note_alias')
        data = _regular(path, artifact['sha256'])
        _install(store / 'objects' / artifact['sha256'], data)
        artifact['state'], artifact['size'] = 'preserved', len(data)
    manifest = _manifest(manifest, preserved=True)
    data = canonical(manifest)
    identity = digest(data)
    destination = store / 'snapshots' / identity / 'manifest.json'
    _install(destination, data)
    _fs.sync_directory(destination.parent.parent)
    _fs.sync_directory(store)
    if store != root:
        for parent in store.parents:
            _fs.sync_directory(parent)
            if parent == root:
                break
    return Snapshot.read(destination, identity)


_BARE = {'pass', 'passed', 'fail', 'failed', 'retain', 'retained', 'accept', 'accepted',
         'reject', 'rejected', 'ok', 'okay', 'lgtm', 'approve', 'approved', 'change', 'defer',
         '通過', '通过', '保留', '合格', '不合格', '承認', '承认', '維持', '维持', '可', '不可',
         '好', '沒問題', '没问题'}


def reason_is_substantive(reason):
    """Bounded structural lint, not a semantic or language quality judgment."""
    normalized = unicodedata.normalize('NFKC', reason).casefold()
    normalized = ''.join(ch for ch in normalized if not ch.isspace() and unicodedata.category(ch)[0] not in {'P', 'Z', 'C'})
    return bool(normalized) and normalized not in _BARE


def _finding(code, subject, reason, status='invalid'):
    return {'code': code, 'subject': subject, 'reason': reason, 'status': status}


def _status(findings):
    if any(f['status'] == 'invalid' for f in findings):
        return 'invalid'
    return 'unknown' if any(f['status'] == 'unknown' for f in findings) else 'valid'


def _reviews(snapshot):
    manifest = snapshot.data
    findings = []
    reviews = {r['item']: r for r in manifest['reviews']}
    candidates = {c['id']: c for c in manifest['candidates']}
    artifacts = {a['id']: a for a in manifest['artifacts']}
    inventory = inventory_digest(manifest['review_inventory'])
    for item in manifest['review_inventory']['items']:
        review = reviews.get(item['id'])
        if review is None:
            findings.append(_finding('review_missing', item['id'], 'required review is missing'))
            continue
        if (review['candidate_sha256'] != candidates[item['candidate']]['sha256'] or
                review['subject_sha256'] != artifacts[item['subject']]['sha256'] or
                review['inventory_sha256'] != inventory):
            findings.append(_finding('review_subject_mismatch', item['id'], 'candidate, subject or inventory changed'))
        if not reason_is_substantive(review['reason']):
            findings.append(_finding('review_reason_invalid', item['id'], 'empty or verdict-only reason'))
        required = [(candidates[item['candidate']]['artifact'], 'review_candidate_missing'),
                    (item['subject'], 'review_subject_missing')]
        required.extend((a, 'review_evidence_missing') for a in review['evidence'])
        if not review['evidence']:
            findings.append(_finding('review_evidence_missing', item['id'], 'review needs preserved supporting evidence'))
        for artifact_id, code in required:
            try:
                snapshot.artifact_bytes(artifact_id)
            except EvidenceError as exc:
                findings.append(_finding(code, item['id'], artifact_id + ': ' + exc.finding['code'] + '; ' + exc.finding['reason']))
        if review['disposition'] != 'accept' or review['limitation'] is not None:
            findings.append(_finding('review_unresolved', item['id'], 'disposition or limitation remains unresolved', 'unknown'))
    return findings


def _integrity(snapshot):
    findings = []
    Snapshot.read(snapshot.path, snapshot.sha256)
    manifest = snapshot.data
    store, root = _durable(snapshot.path.parents[2], manifest['retention'])
    expected_owner = {'schema': 'pstack-retention/1', 'task_id': manifest['task_id'],
                      'owner': manifest['owner'], 'durable_root': str(root),
                      'cleanup_after': manifest['retention']['cleanup_after']}
    _require(read_json(store / 'owner.json') == expected_owner, store, 'retention declaration differs from store owner', 'owner_mismatch')
    for artifact in manifest['artifacts']:
        if artifact['state'] == 'missing':
            findings.append(_finding('missing_original', artifact['id'], artifact['missing_reason'], 'info'))
            continue
        try:
            snapshot.artifact_bytes(artifact['id'])
        except EvidenceError as exc:
            findings.append({**exc.finding, 'status': 'invalid'})
            continue
        if artifact['source']['host'] == 'local' and not Path(artifact['source']['path']).exists():
            findings.append(_finding('original_removed', artifact['id'], 'original path is gone; preserved bytes remain', 'info'))
    return findings


def _resource_times(resource, subject):
    if _time(resource['observed_at']) >= _time(resource['expires_at']):
        return [_finding('time_order_invalid', subject, 'resource expiry must follow its observation')]
    return []


def _consistency(manifest):
    findings = []
    resources = {r['id']: r for r in manifest['resources']}
    records = {r['id']: r for r in manifest['records']}
    for resource in resources.values():
        findings.extend(_resource_times(resource, resource['id']))
    for record in records.values():
        ident, resource = record['id'], resources[record['resource']]
        if record['resource_owner'] != resource['owner']:
            findings.append(_finding('owner_mismatch', ident, 'record owner differs from declared resource owner'))
        for field, key in (('resource_generation', 'generation'), ('environment', 'environment')):
            if record[field] != resource[key]:
                findings.append(_finding('environment_stale', ident, 'record ' + key + ' differs from declared resource'))
        if _time(record['observed_at']) >= _time(resource['expires_at']):
            findings.append(_finding('expired', ident, 'record was observed after resource expiry'))
        if _time(record['expires_at']) <= _time(record['observed_at']):
            findings.append(_finding('time_order_invalid', ident, 'record expiry must follow its observation'))
        command = record['command']
        start, finish = command['started_at'], command['finished_at']
        if start is not None and finish is not None and _time(start) > _time(finish):
            findings.append(_finding('time_order_invalid', ident, 'command start follows finish'))
        for field in ('started_at', 'finished_at'):
            if command[field] is not None and _time(command[field]) > _time(record['observed_at']):
                findings.append(_finding('time_order_invalid', ident, 'command ' + field + ' follows record observation'))
        if record['evidence_type'] == 'independent_recheck' and _time(record['observed_at']) <= _time(records[record['rechecks']]['observed_at']):
            findings.append(_finding('time_order_invalid', ident, 'independent recheck must follow original observation'))
    return findings


@dataclass(frozen=True)
class ReuseContext:
    _bytes: bytes

    @property
    def data(self):
        return _decode(self._bytes)

    @classmethod
    def parse(cls, value):
        _fields(value, 'schema candidate observer purpose checked_at inventory_sha256 observations')
        _require(value['schema'] == 'pstack-reuse/1', 'schema', 'unsupported reuse schema')
        _fields(value['candidate'], 'id sha256')
        _id(value['candidate']['id'])
        _sha(value['candidate']['sha256'])
        _id(value['observer'])
        _text(value['purpose'])
        _require(value['purpose'] in {'navigation', 'behavior', 'independent_behavior'}, 'purpose', 'unsupported reuse purpose')
        _time(value['checked_at'])
        _sha(value['inventory_sha256'])
        seen = set()
        for observation in _list(value['observations']):
            _fields(observation, 'path sha256')
            path = _fs.canonical_path(_path(observation['path']))
            _sha(observation['sha256'])
            _require(path not in seen, path, 'duplicate observation reference')
            seen.add(path)
        return cls(canonical(value))


def _observations(context, manifest):
    observations, findings = {}, []
    actors = {a['id']: a for a in manifest['actors']}
    records = {r['id']: r for r in manifest['records']}
    for reference in context['observations']:
        try:
            observation = read_json(reference['path'], reference['sha256'])
            _fields(observation, 'schema candidate observer observed_at resource evidence_type execution_id rechecks raw producer limitations')
            _require(observation['schema'] == 'pstack-current-observation/1', 'schema', 'unsupported current observation schema')
            _fields(observation['candidate'], 'id sha256')
            _id(observation['candidate']['id'])
            _sha(observation['candidate']['sha256'])
            _id(observation['observer'])
            _require(observation['observer'] == context['observer'] and observation['observer'] in actors, reference['path'], 'current observation observer mismatch', 'owner_mismatch')
            _resource(observation['resource'], actors)
            _time(observation['observed_at'])
            _text(observation['evidence_type'])
            _require(observation['evidence_type'] in {'environment_snapshot', 'independent_recheck'}, reference['path'], 'unsupported current evidence type')
            if observation['execution_id'] is not None:
                _id(observation['execution_id'])
            if observation['rechecks'] is not None:
                _id(observation['rechecks'])
            _text(observation['producer'])
            for limitation in _list(observation['limitations']):
                _text(limitation)
            _fields(observation['raw'], 'path sha256')
            _path(observation['raw']['path'])
            _sha(observation['raw']['sha256'])
            _regular(observation['raw']['path'], observation['raw']['sha256'])
            ident = observation['resource']['id']
            if observation['rechecks'] is not None:
                _ref(observation['rechecks'], records, reference['path'])
                record = records[observation['rechecks']]
                _require(record['resource'] == ident and record['candidate'] == observation['candidate']['id'],
                         reference['path'], 'observation record/resource/candidate binding differs', 'candidate_mismatch')
            key = (ident, observation['rechecks'])
            _require(key not in observations, ident, 'duplicate current record/resource observation')
            observations[key] = observation
        except EvidenceError as exc:
            findings.append({**exc.finding, 'status': 'invalid'})
    return observations, findings


def check(snapshot, context=None):
    """Report archive, review and live-reuse scopes separately; no execution occurs."""
    manifest = snapshot.data
    integrity = _integrity(snapshot)
    reviews = _reviews(snapshot)
    consistency = _consistency(manifest)
    reuse = []
    if context is None:
        reuse.append(_finding('environment_unknown', 'reuse', 'no current observations supplied', 'unknown'))
    else:
        context = ReuseContext.parse(context.data).data
        candidates = {c['id']: c for c in manifest['candidates']}
        resources = {r['id']: r for r in manifest['resources']}
        expected = candidates.get(context['candidate']['id'])
        if expected is None or expected['sha256'] != context['candidate']['sha256']:
            reuse.append(_finding('candidate_mismatch', 'candidate', 'reuse candidate identity differs'))
        if context['inventory_sha256'] != inventory_digest(manifest['review_inventory']):
            reuse.append(_finding('review_inventory_mismatch', 'review_inventory', 'required inventory changed'))
        observations, errors = _observations(context, manifest)
        reuse.extend(errors)
        checked_at = _time(context['checked_at'])
        candidate_records = {r['id']: r for r in manifest['records'] if r['candidate'] == context['candidate']['id']}
        records = list(candidate_records.values())
        if context['purpose'] != 'navigation':
            obligations = set()
            cases = [c for c in manifest['cases'] if c['candidate'] == context['candidate']['id']]
            if not cases:
                reuse.append(_finding('behavior_unverified', context['candidate']['id'], 'candidate has no behavioral cases', 'unknown'))
            for case in cases:
                behavioral = {r for r in case['records'] if candidate_records[r]['evidence_type'] in {'executed', 'independent_recheck'}}
                obligations.update(behavioral)
                if not behavioral or case['actual']['kind'] == 'unverified':
                    reuse.append(_finding('behavior_unverified', case['id'], 'case lacks measured behavioral evidence', 'unknown'))
                    for ident in case['records']:
                        if candidate_records[ident]['evidence_type'] == 'historical_secondary':
                            reuse.append(_finding('historical_only', ident, 'secondary report cannot discharge a behavior case', 'unknown'))
            for record in records:
                if record['id'] not in obligations:
                    reuse.append(_finding('context_only', record['id'], record['evidence_type'] + ': not a case-linked behavioral obligation', 'info'))
            records = [r for r in records if r['id'] in obligations]
        elif not records:
            reuse.append(_finding('environment_unknown', 'records', 'no matching records', 'unknown'))
        behavioral_observations = [o for o in observations.values() if o['evidence_type'] == 'independent_recheck']
        archived_execution_ids = {r['command']['execution_id'] for r in manifest['records'] if r['command']['execution_id'] is not None}
        archived_captures = [a for a in manifest['artifacts'] if a['kind'] in {'raw', 'trace'}]
        for record in records:
            ident = record['id']
            resource = resources[record['resource']]
            if checked_at < _time(record['observed_at']) or checked_at >= min(_time(record['expires_at']), _time(resource['expires_at'])):
                reuse.append(_finding('expired', ident, 'record or resource is future-dated or expired'))
            observation = observations.get((record['resource'], ident)) or observations.get((record['resource'], None))
            if observation is None:
                reuse.append(_finding('environment_unknown', ident, 'no separately hash-bound current observation for this record/resource', 'unknown'))
                continue
            current = observation['resource']
            reuse.extend(_resource_times(current, ident))
            if observation['candidate'] != context['candidate']:
                reuse.append(_finding('candidate_mismatch', ident, 'current observation candidate differs'))
            if current['owner'] != record['resource_owner']:
                reuse.append(_finding('owner_mismatch', ident, 'current resource owner differs'))
            for field, key in (('resource_generation', 'generation'), ('environment', 'environment')):
                if current[key] != record[field]:
                    reuse.append(_finding('environment_stale', ident, 'current resource ' + key + ' differs'))
            if (_time(observation['observed_at']) <= max(_time(record['observed_at']), _time(resource['observed_at'])) or
                    _time(current['observed_at']) != _time(observation['observed_at'])):
                reuse.append(_finding('environment_unknown', ident, 'current observation must be newer than archived record and resource and agree with current resource time', 'unknown'))
            if checked_at < _time(observation['observed_at']) or checked_at >= _time(current['expires_at']):
                reuse.append(_finding('expired', ident, 'current observation is future-dated or expired'))
            if observation['limitations']:
                reuse.append(_finding('environment_unknown', ident, '; '.join(observation['limitations']), 'unknown'))
            if context['purpose'] != 'navigation':
                capture_alias = any(_alias(observation['raw']['path'], artifact['source']['path']) or
                                    (artifact['state'] == 'preserved' and _alias(observation['raw']['path'], snapshot.path.parents[2] / 'objects' / artifact['sha256']))
                                    for artifact in archived_captures)
                shared_identity = any(other is not observation and
                                      (other['execution_id'] == observation['execution_id'] or
                                       _alias(other['raw']['path'], observation['raw']['path']))
                                      for other in behavioral_observations)
                reused_identity = capture_alias or shared_identity or observation['execution_id'] in archived_execution_ids
                if reused_identity:
                    reuse.append(_finding('independence_unverified', ident, 'execution identity or capture aliases another archived/current execution'))
                independent = (observation['evidence_type'] == 'independent_recheck' and
                               observation['observer'] not in {record['observer'], candidates[record['candidate']]['author']} and
                               next(a for a in manifest['actors'] if a['id'] == observation['observer'])['role'] == 'verifier' and
                               observation['execution_id'] is not None and observation['rechecks'] == ident)
                if not independent:
                    reuse.append(_finding('independence_unverified', ident, 'separate verifier execution and fresh capture required', 'unknown'))
    return {'snapshot_sha256': snapshot.sha256, 'archive_integrity': _status(integrity),
            'archive_consistency': _status(consistency),
            'review_readiness': _status(reviews), 'reuse': _status(consistency + reuse),
            'execution': 'declarations_only', 'findings': integrity + consistency + reviews + reuse}


def _safe(value):
    if not isinstance(value, str):
        value = canonical(value).decode('utf-8')
    return ''.join(ch if ch.isalnum() or ch == ' ' else '&#' + str(ord(ch)) + ';' for ch in value)


def _link_intent(value, artifacts):
    _fields(value, 'schema audience links')
    _require(value['schema'] == 'pstack-links/1', 'schema', 'unsupported link schema')
    _text(value['audience'])
    seen, urls = set(), set()
    for link in _list(value['links']):
        _fields(link, 'item url')
        _id(link['item'])
        _require(link['item'] in set(artifacts) | {'summary', 'cases'}, link['item'], 'unknown publication item')
        _require(link['item'] not in seen, link['item'], 'duplicate publication item')
        seen.add(link['item'])
        _text(link['url'])
        _require(link['url'] not in urls, link['item'], 'URL maps to multiple items')
        urls.add(link['url'])
        _require(len(link['url']) <= 2048 and re.fullmatch(r'[A-Za-z0-9:/._~?#@%+=-]+', link['url']) is not None,
                 link['item'], 'unsafe Markdown URL', 'publication_url_invalid')
        _require(urllib.parse.urlsplit(link['url']).scheme in {'', 'http', 'https', 'file'}, link['item'], 'unsupported URL scheme', 'publication_url_invalid')
        if link['item'] in artifacts:
            _require(artifacts[link['item']]['state'] == 'preserved', link['item'], 'cannot link missing originals', 'missing_original')
    return value


def _documents(snapshot, links):
    manifest = snapshot.data
    records = {r['id']: r for r in manifest['records']}
    review_findings = _reviews(snapshot)
    rows, summaries = [], []
    for case in manifest['cases']:
        actual = case['actual']
        outcome = 'unverified'
        if actual['kind'] == 'artifact':
            raw = snapshot.artifact_bytes(actual['artifact'])
            try:
                observed = _decode(raw) if actual['format'] == 'json' else raw.decode('utf-8')
                matched = canonical(observed) == canonical(case['expected']['value'])
                outcome = 'expectation matched' if matched else 'expectation mismatched'
                actual_text = observed
            except (UnicodeError, EvidenceError):
                actual_text, outcome = 'unreadable result in declared format', 'unverified'
        else:
            actual_text = actual['reason']
        kinds = sorted({records[r]['evidence_type'] for r in case['records']})
        limits = []
        for ident in case['records']:
            record = records[ident]
            limits.append('Declared ' + record['declared_outcome'] + '; exit ' + str(record['command']['exit_code']))
            if record['limitation']:
                limits.append(record['limitation'])
            limits.extend(record['harness']['boundaries'])
            limits.extend(s['component'] + ': ' + s['replacement'] + '; ' + s['impact'] for s in record['harness']['substitutions'])
        data = [case['id'], case['candidate'], case['entry'], case['scenario'], case['expected']['value'],
                actual_text, outcome, ', '.join(kinds), '; '.join(dict.fromkeys(limits)) or 'No limitations declared']
        rows.append('| ' + ' | '.join(_safe(v) for v in data) + ' |')
        summaries.append('- ' + _safe(case['id']) + ': ' + _safe(outcome) + '. Entry: ' + _safe(case['entry']) +
                         '. Expected: ' + _safe(case['expected']['value']) + '. Actual: ' + _safe(actual_text) +
                         '. Evidence: ' + _safe(', '.join(kinds)) + '. Limits: ' + _safe(data[-1]) + '.')
    reviews = []
    by_item = {r['item']: r for r in manifest['reviews']}
    for item in manifest['review_inventory']['items']:
        review = by_item.get(item['id'])
        details = (review['disposition'] + '; ' + review['reason'] +
                   ('; limitation: ' + review['limitation'] if review['limitation'] else '')) if review else 'missing'
        reviews.append('- ' + _safe(item['id']) + ': ' + _safe(item['description']) + '. ' + _safe(details) + '.')
    evidence_links = ['- [' + _safe(link['item']) + '](' + link['url'] + ')' for link in links['links'] if link['item'] not in {'summary', 'cases'}]
    footer = '\n\nArchive consistency: ' + _status(_consistency(manifest)) + '.\n'
    footer += '\nReview readiness: ' + _status(review_findings) + '.\n' + '\n'.join(reviews)
    footer += '\n\nExecution classifications are recorded declarations. Matching bytes do not establish recorder honesty or a new test run.\n'
    footer += '\nEvidence links:\n' + ('\n'.join(evidence_links) if evidence_links else 'Omitted. Anonymous link access has not been checked.') + '\n'
    footer += '\nMissing originals: ' + _safe(', '.join(a['id'] + ': ' + a['missing_reason'] for a in manifest['artifacts'] if a['state'] == 'missing') or 'none declared') + '.\n'
    summary = '# Verification summary\n\n' + '\n'.join(summaries) + footer
    cases = '# Verification cases\n\n| Case | Candidate | Entry | Scenario | Expected | Actual | Result | Evidence | Limits |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n' + '\n'.join(rows) + footer
    return {'summary': summary.encode('utf-8'), 'cases': cases.encode('utf-8')}


def render(snapshot, output, links=None, *, document_state=None, target=None,
           document_owner=None):
    """Create a new directory containing both deterministic views and their binding."""
    output = _path(str(output))
    try:
        str(output).encode('utf-8')
    except UnicodeError as exc:
        raise EvidenceError('retention_invalid', str(output),
                            'render output path must contain valid Unicode characters') from exc
    _require(not any(part.casefold().endswith('.pstack-guard.lock') for part in output.parts), output,
             'the .pstack-guard.lock namespace is reserved for target locks', 'document_options')
    _require(not os.path.lexists(output), output, 'render output must be a fresh directory', 'output_exists')
    try:
        output = _fs.unaliased_path(output.parent) / output.name
    except _fs.UnsupportedFile as exc:
        _fail('retention_invalid', output, str(exc))
    for parent in output.parents:
        _require(not os.path.lexists(parent) or parent.is_dir(), parent, 'render parent must be a directory', 'retention_invalid')
    binding = (document_state, target, document_owner)
    guarded = any(value is not None for value in binding)
    if guarded:
        _require(all(value is not None for value in binding), 'document',
                 'document_state, target and document_owner must be supplied together', 'document_options')
        _text(document_owner, 'document_owner')
        document_state, target = _path(str(document_state)), _path(str(target))
        try:
            document_state, target = (_fs.unaliased_path(path) for path in (document_state, target))
        except _fs.UnsupportedFile as exc:
            _fail('document_options', 'document', str(exc))
        locations = (document_state, target, output)
        _require(all(not _fs.contains_path(a, b) and not _fs.contains_path(b, a)
                     for index, a in enumerate(locations) for b in locations[index + 1:]),
                 'document', 'render output, target and state must be separate locations', 'document_options')
        guard = _document_guard()
        try:
            guard._text(document_owner)
            guard._path(document_state)
            guard._path(target)
        except guard.GuardError as exc:
            _fail('document_guard_error', 'document', str(exc))

    findings = _integrity(snapshot)
    _require(_status(findings) != 'invalid', 'archive', 'cannot render corrupt preserved evidence', 'archive_invalid')
    manifest = snapshot.data
    artifacts = {a['id']: a for a in manifest['artifacts']}
    links = _link_intent(links or {'schema': 'pstack-links/1', 'audience': 'public-anonymous', 'links': []}, artifacts)
    documents = _documents(snapshot, links)
    _require(all(len(data) <= MAX_BYTES for data in documents.values()), 'render', 'rendered file exceeds 16 MiB', 'size_limit')
    metadata = {'schema': 'pstack-render/1', 'snapshot': str(snapshot.path), 'snapshot_sha256': snapshot.sha256,
                'renderer_sha256': digest(_regular(Path(__file__))), 'links': links,
                'files': {item: digest(data) for item, data in documents.items()}}
    identity = digest(canonical(metadata))
    _require(not any(_fs.contains_path(output, p) for p in _fs.excluded_roots() | set(_skill_roots(output))),
             output, 'render must be outside installed skill and ephemeral roots', 'retention_invalid')
    _fs.ensure_directory(output.parent, parents=True)
    staging = _fs.stage_directory(output.parent, '.render-')
    for item, data in documents.items():
        _install(staging / (item + '.md'), data)
    _install(staging / 'render.json', canonical(metadata))
    # A render is complete only after render.json appears. Interrupted directories
    # are retained for diagnosis; callers retry with a fresh output path.
    try:
        _fs.ensure_directory(output, exist_ok=False)
        for name in ('summary.md', 'cases.md'):
            _fs.publish_new(staging / name, output / name)
        _fs.sync_directory(output)
        _fs.publish_new(staging / 'render.json', output / 'render.json')
    except FileExistsError as exc:
        _fail('output_exists', output, str(exc))
    staging.rmdir()
    _fs.sync_directory(output)
    _fs.sync_directory(output.parent)
    result = {'render': str(output / 'render.json'), 'render_sha256': identity,
              'snapshot_sha256': snapshot.sha256, 'links': 'links_declared' if links['links'] else 'checked_no_links'}
    if guarded:
        generated = output / 'summary.md'
        _regular(generated, metadata['files']['summary'])
        source = guard.GeneratedSource('task-evidence-renderer', '1', metadata['renderer_sha256'],
                                       (('snapshot', snapshot.sha256),), identity)
        try:
            proposal = guard.propose(document_state, target, generated, source, owner=document_owner)
        except guard.GuardError as exc:
            _fail('document_guard_error', 'document', str(exc))
        _require(proposal['new_generated'] == metadata['files']['summary'], 'document',
                 'proposal differs from this render', 'render_mismatch')
        result['proposal'] = proposal
    return result


def _public_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
        _require(parts.scheme == 'https' and parts.netloc == 'raw.githubusercontent.com' and
                 parts.hostname == 'raw.githubusercontent.com' and parts.port is None and
                 not parts.username and not parts.password and not parts.query and not parts.fragment,
                 url, 'requires credential-free HTTPS raw GitHub URL without query/fragment', 'publication_url_invalid')
        _require('%' not in parts.path and '\\' not in url and not any(ch.isspace() or ord(ch) < 32 for ch in url), url, 'encoded or ambiguous path is unsupported', 'publication_url_invalid')
        segments = parts.path.split('/')[1:]
        _require(len(segments) >= 4 and re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]*', segments[0]) and
                 re.fullmatch('[A-Za-z0-9_.-]+', segments[1]) and segments[1] not in {'.', '..'} and
                 re.fullmatch('(?:[0-9a-f]{40}|[0-9a-f]{64})', segments[2]) and
                 all(re.fullmatch('[A-Za-z0-9_.-]+', p) and p not in {'.', '..'} for p in segments[3:]),
                 url, 'requires owner/repository/full-commit/regular-path', 'publication_url_invalid')
    except ValueError as exc:
        if isinstance(exc, EvidenceError):
            raise
        _fail('publication_url_invalid', url, str(exc))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def _anonymous_fetch(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'pstack-evidence/1', 'Accept': 'application/octet-stream'})
    deadline = time.monotonic() + 10
    with opener.open(request, timeout=10) as response:
        _require(response.status == 200, url, 'expected HTTP 200', 'publication_inaccessible')
        chunks, size = [], 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('anonymous fetch deadline exceeded')
            chunk = response.read1(min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= MAX_BYTES, url, 'remote response exceeds 16 MiB', 'size_limit')


def publication(render_path, expected_sha256):
    """Verify the exact render and anonymous immutable remote bytes; never upload."""
    _sha(expected_sha256)
    render_path = _path(str(render_path))
    metadata = read_json(render_path, expected_sha256)
    _fields(metadata, 'schema snapshot snapshot_sha256 renderer_sha256 links files')
    _require(metadata['schema'] == 'pstack-render/1', 'schema', 'unsupported render schema')
    _require(metadata['renderer_sha256'] == digest(_regular(Path(__file__))), 'renderer', 'renderer version differs', 'renderer_mismatch')
    snapshot = Snapshot.read(metadata['snapshot'], metadata['snapshot_sha256'])
    findings = _integrity(snapshot)
    artifacts = {a['id']: a for a in snapshot.data['artifacts']}
    links = _link_intent(metadata['links'], artifacts)
    _fields(metadata['files'], 'summary cases')
    documents = _documents(snapshot, links)
    for item, expected in documents.items():
        _sha(metadata['files'][item])
        actual = _regular(render_path.parent / (item + '.md'), metadata['files'][item])
        _require(actual == expected, item, 'render differs from snapshot-derived output', 'render_mismatch')
    for link in links['links']:
        item, url = link['item'], link['url']
        expected = documents[item] if item in documents else snapshot.artifact_bytes(item)
        parts = urllib.parse.urlsplit(url)
        if parts.scheme in {'', 'file'} or parts.hostname in {'localhost', '127.0.0.1', '::1'}:
            findings.append(_finding('publication_url_invalid', item, 'local links are inaccessible to recipients'))
            continue
        if links['audience'] != 'public-anonymous':
            findings.append(_finding('publication_unknown', item, 'unsupported audience', 'unknown'))
            continue
        if parts.hostname != 'raw.githubusercontent.com':
            findings.append(_finding('publication_unknown', item, 'unsupported host', 'unknown'))
            continue
        try:
            _public_url(url)
            remote = _anonymous_fetch(url)
            _require(digest(remote) == digest(expected), item, 'remote bytes differ from preserved/rendered bytes', 'publication_hash_mismatch')
        except EvidenceError as exc:
            findings.append({**exc.finding, 'status': 'invalid'})
        except urllib.error.HTTPError as exc:
            known_failure = exc.code in {301, 302, 303, 307, 308, 401, 403, 404, 410}
            findings.append(_finding('publication_inaccessible' if known_failure else 'publication_unknown', item,
                                     'anonymous HTTP ' + str(exc.code), 'invalid' if known_failure else 'unknown'))
            exc.close()
        except (OSError, urllib.error.URLError, socket.timeout) as exc:
            findings.append(_finding('publication_unknown', item, str(exc), 'unknown'))
    status = _status(findings)
    return {'status': status, 'links': ('checked_no_links' if not links['links'] else
                                      'links_verified' if status == 'valid' else 'links_unverified'),
            'render_sha256': expected_sha256, 'snapshot_sha256': snapshot.sha256,
            'checked_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'scope': 'anonymous access from this environment at this time; no future or universal access guarantee',
            'findings': findings}


def main(argv=None):
    _fs.configure_stdio_utf8()
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest='operation', required=True)
    preserve_parser = operations.add_parser('preserve')
    preserve_parser.add_argument('--input', required=True)
    preserve_parser.add_argument('--store', required=True)
    for name in ('check', 'render'):
        operation = operations.add_parser(name)
        operation.add_argument('--snapshot', required=True, help='absolute pinned manifest.json path')
        operation.add_argument('--sha256', required=True, help='trusted snapshot SHA-256')
        if name == 'check':
            operation.add_argument('--context')
        else:
            operation.add_argument('--out', required=True)
            operation.add_argument('--links')
            operation.add_argument('--document-state')
            operation.add_argument('--target')
            operation.add_argument('--document-owner')
    publish_parser = operations.add_parser('publication')
    publish_parser.add_argument('--render', required=True, help='absolute render.json path')
    publish_parser.add_argument('--sha256', required=True, help='trusted render.json SHA-256')
    args = parser.parse_args(argv)
    if args.operation == 'render':
        document_options = (args.document_state, args.target, args.document_owner)
        if any(value is not None for value in document_options) and not all(value is not None for value in document_options):
            parser.error('--document-state, --target and --document-owner must be supplied together')
    try:
        if args.operation == 'preserve':
            snapshot = preserve(read_json(args.input), args.store)
            result = {'status': 'preserved', 'snapshot': str(snapshot.path), 'snapshot_sha256': snapshot.sha256}
            ok = True
        elif args.operation == 'publication':
            result = publication(args.render, args.sha256)
            ok = result['status'] == 'valid'
        else:
            snapshot = Snapshot.read(args.snapshot, args.sha256)
            if args.operation == 'check':
                context = ReuseContext.parse(read_json(args.context)) if args.context else None
                result = check(snapshot, context)
                ok = result['archive_integrity'] == 'valid' and result['archive_consistency'] == 'valid' and result['review_readiness'] == 'valid' and (not args.context or result['reuse'] == 'valid')
            else:
                result = render(snapshot, args.out, read_json(args.links) if args.links else None,
                                document_state=args.document_state, target=args.target,
                                document_owner=args.document_owner)
                ok = True
        print(json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True))
        return 0 if ok else 1
    except EvidenceError as exc:
        print(json.dumps({'status': 'invalid', 'findings': [exc.finding]}, ensure_ascii=True, sort_keys=True))
        return 1
    except (OSError, ValueError) as exc:
        code = 'unsupported_capability' if isinstance(exc, _fs.CapabilityError) else 'io_error'
        print(json.dumps({'status': 'invalid', 'findings': [{'code': code, 'subject': args.operation, 'reason': str(exc)}]}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
