#!/usr/bin/env python3
"""Retain generated drafts and explicitly promote reviewed local documents."""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys


# Load the installed sibling without creating bytecode or searching sys.path.
def _load_filesystem():
    path = Path(__file__).resolve().with_name('evidence_fs.py')
    spec = importlib.util.spec_from_file_location('_pstack_evidence_fs', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


_fs = _load_filesystem()


__all__ = ['GeneratedSource', 'GuardError', 'propose', 'promote', 'recover']
_LOCK_SUFFIX = '.pstack-guard.lock'
_DEFAULT_MODE = 0o666 if _fs.WINDOWS else 0o644


class GuardError(ValueError):
    """Invalid input, a conflict, or unsupported filesystem state."""


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    try:
        return (json.dumps(data, sort_keys=True, ensure_ascii=False,
                           separators=(',', ':')) + '\n').encode('utf-8')
    except UnicodeError as exc:
        raise GuardError('JSON strings must contain valid Unicode characters') from exc


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise GuardError('Expected a lowercase SHA-256 digest')
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise GuardError('Expected a nonempty identity')
    try:
        value.encode('utf-8')
    except UnicodeError as exc:
        raise GuardError('Identities and paths must contain valid Unicode characters') from exc
    return value


@dataclass(frozen=True)
class GeneratedSource:
    """Identity of the generator and its exact inputs, independent of output."""
    generator_id: str
    generator_version: str
    generator_sha256: str
    inputs: tuple
    render_id: str | None = None

    def __post_init__(self):
        _text(self.generator_id)
        _text(self.generator_version)
        _sha(self.generator_sha256)
        if not isinstance(self.inputs, tuple) or not self.inputs:
            raise GuardError('Source inputs must be a nonempty tuple of (id, sha256)')
        names = set()
        for item in self.inputs:
            if not isinstance(item, tuple) or len(item) != 2:
                raise GuardError('Invalid source input')
            name, digest = item
            _text(name)
            _sha(digest)
            if name in names:
                raise GuardError('Duplicate source input identity')
            names.add(name)
        if self.render_id is not None:
            _sha(self.render_id)

    def as_dict(self):
        return {'schema': 'pstack-generated-source/1',
                'generator': {'id': self.generator_id, 'version': self.generator_version,
                              'sha256': self.generator_sha256},
                'inputs': [{'id': name, 'sha256': digest}
                           for name, digest in sorted(self.inputs)],
                'render_id': self.render_id}

    @classmethod
    def from_dict(cls, value):
        try:
            if set(value) != {'schema', 'generator', 'inputs', 'render_id'}:
                raise GuardError('Invalid source fields')
            if value['schema'] != 'pstack-generated-source/1':
                raise GuardError('Unsupported source schema')
            generator = value['generator']
            if set(generator) != {'id', 'version', 'sha256'}:
                raise GuardError('Invalid generator fields')
            if not isinstance(value['inputs'], list):
                raise GuardError('Invalid source inputs')
            if any(set(item) != {'id', 'sha256'} for item in value['inputs']):
                raise GuardError('Invalid source input fields')
            return cls(generator['id'], generator['version'], generator['sha256'],
                       tuple((item['id'], item['sha256']) for item in value['inputs']),
                       value['render_id'])
        except (KeyError, TypeError) as exc:
            raise GuardError('Invalid generated source') from exc


@dataclass(frozen=True)
class _Target:
    sha256: str = 'absent'
    mode: int | None = None

    def as_dict(self):
        return {'sha256': self.sha256, 'mode': self.mode}


def _lexical_path(value):
    try:
        path = Path(value)
    except TypeError as exc:
        raise GuardError('Expected a filesystem path') from exc
    _text(str(path))
    if not path.is_absolute() or '..' in path.parts:
        raise GuardError('Paths must be absolute and contain no symlink aliases')
    try:
        _fs.validate_path(path)
    except ValueError as exc:
        raise GuardError(str(exc)) from exc
    if any(part.casefold().endswith(_LOCK_SUFFIX) for part in path.parts):
        raise GuardError('The .pstack-guard.lock namespace is reserved for target locks')
    return path


def _path(value):
    path = _lexical_path(value)
    try:
        return _fs.unaliased_path(path)
    except _fs.UnsupportedFile as exc:
        raise GuardError('Paths must be absolute and contain no symlink aliases') from exc


def _target_path(value):
    path = _path(value)
    if path == path.parent:
        raise GuardError('The filesystem root cannot be a document target')
    if (_fs.WINDOWS or _fs.DARWIN) and not path.exists():
        # The sidecar can resolve a case variant while the target is absent.
        lock = path.with_name(path.name + _LOCK_SUFFIX)
        try:
            lock.lstat()
        except FileNotFoundError:
            return path
        try:
            canonical = _fs.unaliased_path(lock)
        except _fs.UnsupportedFile as exc:
            raise GuardError('Lock path has a filesystem alias') from exc
        return path.with_name(canonical.name[:-len(_LOCK_SUFFIX)])
    return path


def _outside_skills(path):
    roots = [_fs.canonical_path(Path(__file__).parents[3])]
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
    if any(_fs.contains_path(path, root) for root in roots):
        raise GuardError('Task output must be outside skill trees')


def _read(path):
    try:
        return _fs.read_regular(path, max_links=1, anchor=path.parent)
    except (_fs.UnsupportedFile, _fs.SourceChanged) as exc:
        raise GuardError(str(exc)) from exc


def _target(path):
    try:
        data, mode = _read(path)
        return _Target(_digest(data), mode), data
    except FileNotFoundError:
        if not path.parent.is_dir():
            raise GuardError('Target parent is missing')
        return _Target(), None


def _read_json(path):
    try:
        value = json.loads(_read(path)[0].decode('utf-8'))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise GuardError('Invalid stored JSON: ' + str(path)) from exc
    if not isinstance(value, dict):
        raise GuardError('Expected a JSON object: ' + str(path))
    return value


def _fsync_dir(path):
    _fs.sync_directory(path)


def _directory(path):
    try:
        _fs.ensure_directory(path)
    except _fs.UnsupportedFile as exc:
        raise GuardError(str(exc)) from exc


def _rename_noreplace(source, destination):
    _fs.publish_new(source, destination)


def _write_once(path, data):
    if path.exists() or path.is_symlink():
        if _read(path)[0] != data:
            raise GuardError('Stored immutable content differs: ' + str(path))
        _fsync_dir(path.parent)
        return
    with _fs.stage(path.parent, data, mode=0o444, prefix='.capture-') as staged:
        try:
            _rename_noreplace(staged, path)
        except FileExistsError:
            if _read(path)[0] != data:
                raise GuardError('Stored immutable content differs: ' + str(path))
    _fsync_dir(path.parent)


def _object(state, data):
    digest = _digest(data)
    _write_once(state / 'objects' / digest, data)
    return digest


def _get_object(state, digest):
    data = _read(state / 'objects' / _sha(digest))[0]
    if _digest(data) != digest:
        raise GuardError('Corrupt retained object: ' + digest)
    return data


@contextmanager
def _locked(state, target, owner=None, timeout=5.0):
    state, target = _path(state), _target_path(target)
    if owner is not None:
        _text(owner)
    excluded = _fs.excluded_roots()
    for path in (state, target):
        _outside_skills(path)
        if any(_fs.contains_path(path, root) for root in excluded):
            raise GuardError('Task output must be outside temporary and system directories')
    if (_fs.contains_path(state, target) or _fs.contains_path(target, state)
            or target.name.endswith(_LOCK_SUFFIX)):
        raise GuardError('Target and state must be separate locations')
    if not target.parent.is_dir() or not state.parent.is_dir():
        raise GuardError('Existing target and state parent directories are required')
    if not isinstance(timeout, (int, float)) or not 0 <= timeout <= 60:
        raise GuardError('Lock timeout must be between zero and 60 seconds')
    _fs.require_same_volume(state.parent, target.parent)
    lock = target.with_name(target.name + _LOCK_SUFFIX)
    with _guard_lock(lock, timeout) as fd:
        if _fs.WINDOWS or _fs.DARWIN:
            state, target = _path(state), _target_path(target)
        binding = _json({'schema': 'pstack-document-lock/1', 'target': str(target),
                         'state': str(state)})
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            saved = stream.read()
        if saved and saved != binding:
            raise GuardError('Target lock is bound to another state directory')
        metadata_path = state / 'owner.json'
        if not saved and owner is not None:
            _target(target)
        if state.exists() and not state.is_dir():
            raise GuardError('Expected an unaliased state directory')
        if state.is_dir():
            _fs.owned_directory(state)
            _fs.require_same_volume(state, target.parent)
        if metadata_path.exists():
            metadata = _read_json(metadata_path)
            _fields(metadata, 'schema owner target')
            _text(metadata['owner'])
            if (metadata.get('schema') != 'pstack-document/1'
                    or metadata.get('target') != str(target)
                    or owner is not None and metadata.get('owner') != owner):
                raise GuardError('State owner or target differs')
        elif owner is None:
            raise GuardError('Propose must initialize the document owner')
        else:
            _directory(state)
            _fs.owned_directory(state)
            _write_once(metadata_path, _json({'schema': 'pstack-document/1',
                                            'owner': _text(owner), 'target': str(target)}))
        for name in ('objects', 'proposals', 'operations'):
            _directory(state / name)
        _operations(state)
        _fsync_dir(state)
        if not saved:
            os.write(fd, binding)
            _fs.sync_file(fd)
            _fsync_dir(target.parent)
        yield state, target


@contextmanager
def _guard_lock(lock, timeout):
    try:
        with _fs.sidecar_lock(lock, timeout) as fd:
            yield fd
    except (_fs.LockBusy, _fs.UnsupportedFile, _fs.SourceChanged) as exc:
        raise GuardError(str(exc)) from exc


def _operation_dir(state, operation_id):
    return state / 'operations' / _digest(_text(operation_id).encode('utf-8'))


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise GuardError('Invalid stored record fields')


def _stored_target(value):
    _fields(value, 'sha256 mode')
    if value['sha256'] == 'absent':
        if value['mode'] is not None:
            raise GuardError('Absent target must not have a mode')
    else:
        _sha(value['sha256'])
        if type(value['mode']) is not int or not 0 <= value['mode'] <= 0o7777:
            raise GuardError('Invalid stored target mode')


def _stored_request(value):
    _fields(value, 'schema target proposal_id operation_id expect_target expect_draft decision merged_path expect_merged')
    if value['schema'] != 'pstack-promotion-request/1':
        raise GuardError('Invalid stored request schema')
    _text(value['target'])
    if not Path(value['target']).is_absolute():
        raise GuardError('Invalid stored target path')
    _sha(value['proposal_id'])
    _text(value['operation_id'])
    if value['expect_target'] != 'absent':
        _sha(value['expect_target'])
    _sha(value['expect_draft'])
    if value['decision'] == 'merge':
        _text(value['merged_path'])
        _sha(value['expect_merged'])
        if not Path(value['merged_path']).is_absolute():
            raise GuardError('Invalid stored merge path')
    elif (value['decision'] != 'replace' or value['merged_path'] is not None
          or value['expect_merged'] is not None):
        raise GuardError('Invalid stored promotion request')


def _stored_intent(value):
    _fields(value, 'schema operation_id request prior_target desired_target desired_mode generated_baseline prior_receipt stage')
    _stored_request(value['request'])
    _stored_target(value['prior_target'])
    _text(value['operation_id'])
    _sha(value['desired_target'])
    _sha(value['generated_baseline'])
    if value['prior_receipt'] is not None:
        _text(value['prior_receipt'])
    if type(value['desired_mode']) is not int or not 0 <= value['desired_mode'] <= 0o7777:
        raise GuardError('Invalid stored desired mode')


def _operations(state):
    result = []
    for directory in sorted((state / 'operations').iterdir()):
        if not directory.is_dir() or _fs.canonical_path(directory) != directory:
            raise GuardError('Invalid operation directory')
        intent_path = directory / 'intent.json'
        receipt_path = directory / 'receipt.json'
        if intent_path.exists():
            intent = _read_json(intent_path)
            request = _read_json(directory / 'request.json')
            _stored_intent(intent)
            _stored_request(request)
            if (intent['schema'] != 'pstack-promotion-intent/1'
                    or intent['stage'] != 'prepared' or intent['request'] != request
                    or intent['generated_baseline'] != request['expect_draft']
                    or intent['prior_target']['sha256'] != request['expect_target']
                    or intent['operation_id'] != request['operation_id']
                    or intent['desired_target'] != (request['expect_merged']
                        if request['decision'] == 'merge' else request['expect_draft'])
                    or intent['desired_mode'] != (intent['prior_target']['mode']
                        if intent['prior_target']['mode'] is not None else _DEFAULT_MODE)):
                raise GuardError('Prepared intent does not match the explicit decision')
            if _operation_dir(state, intent['operation_id']) != directory:
                raise GuardError('Operation identity differs')
            receipt = _read_json(receipt_path) if receipt_path.exists() else None
            if receipt is not None and receipt != _receipt(intent):
                raise GuardError('Receipt does not match prepared intent')
            result.append((intent, receipt))
        elif receipt_path.exists():
            raise GuardError('Receipt has no prepared intent')
    return result


def _history(state):
    operations = _operations(state)
    committed = {intent['operation_id']: (intent, receipt)
                 for intent, receipt in operations if receipt}
    current = None
    while committed:
        following = [(key, pair) for key, pair in committed.items()
                     if pair[0]['prior_receipt'] == current]
        if len(following) != 1:
            raise GuardError('Invalid committed receipt chain')
        current, _ = following[0]
        del committed[current]
    if current is None:
        return None, None
    return next((intent, receipt) for intent, receipt in operations
                if intent['operation_id'] == current)


def _pending(state, except_id=None):
    if any(not receipt and intent['operation_id'] != except_id
           for intent, receipt in _operations(state)):
        raise GuardError('A prepared operation requires recovery before another write')


def _diff(before, after, name):
    def lines(data):
        parts = data.split(b'\n')
        return [part + b'\n' for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])

    patch_lines = difflib.diff_bytes(difflib.unified_diff, lines(before), lines(after),
                                    fromfile=(name + '-before').encode(), tofile=b'draft')
    return b''.join(line if line.endswith(b'\n') else
                    line + b'\n\\ No newline at end of file\n' for line in patch_lines)


def _proposal(state, proposal_id):
    directory = _path(state / 'proposals' / _sha(proposal_id))
    value = _read_json(directory / 'proposal.json')
    _fields(value, 'schema target source previous_generated previous_promotion observed_target new_generated classification files')
    if value['schema'] != 'pstack-proposal/1':
        raise GuardError('Invalid stored proposal schema')
    _text(value['target'])
    _stored_target(value['observed_target'])
    _sha(value['new_generated'])
    if value['previous_generated'] is not None:
        _sha(value['previous_generated'])
    if value['previous_promotion'] is not None:
        _text(value['previous_promotion'])
    if value['classification'] not in ('new', 'unchanged', 'untracked', 'clean_update', 'reviewed_change'):
        raise GuardError('Invalid stored proposal classification')
    files = value['files']
    if (not isinstance(files, dict) or 'target.diff' not in files
            or not set(files) <= {'target.diff', 'target-before.md', 'generated-before.md', 'generated.diff'}):
        raise GuardError('Invalid stored proposal files')
    if _digest(_json(value)) != proposal_id:
        raise GuardError('Corrupt proposal identity')
    files = {'draft.md': value['new_generated'], **value['files']}
    for name, digest in files.items():
        data = _get_object(state, digest)
        if _read(directory / name)[0] != data:
            raise GuardError('Proposal copy differs: ' + name)
    GeneratedSource.from_dict(value['source'])
    return value


def propose(state, target, generated, source, *, owner, lock_timeout=5.0):
    """Retain a deterministic draft and available diffs; never write the target."""
    if not isinstance(source, GeneratedSource):
        raise GuardError('source must be GeneratedSource')
    _json(source.as_dict())
    _text(owner)
    state, target, generated = _path(state), _target_path(target), _path(generated)
    if generated == target or state == generated or state in generated.parents:
        raise GuardError('Generated input must be independent of target and state')
    _read(generated)
    with _locked(state, target, owner, lock_timeout) as (state, target):
        _pending(state)
        current, _ = _history(state)
        observed, old = _target(target)
        new = _read(generated)[0]
        new_hash = _object(state, new)
        previous = current['generated_baseline'] if current else None
        before = _get_object(state, previous) if previous else None
        files = {'target.diff': _object(state, _diff(old or b'', new, 'target'))}
        if old is not None:
            files['target-before.md'] = _object(state, old)
        if before is not None:
            files['generated-before.md'] = previous
            files['generated.diff'] = _object(state, _diff(before, new, 'generated'))
        if observed.sha256 == new_hash:
            classification = 'unchanged'
        elif observed.sha256 == 'absent':
            classification = 'new'
        elif current is None:
            classification = 'untracked'
        elif observed.sha256 == previous:
            classification = 'clean_update'
        else:
            classification = 'reviewed_change'
        value = {'schema': 'pstack-proposal/1', 'target': str(target),
                 'source': source.as_dict(), 'previous_generated': previous,
                 'previous_promotion': current['operation_id'] if current else None,
                 'observed_target': observed.as_dict(), 'new_generated': new_hash,
                 'classification': classification, 'files': files}
        proposal_id = _digest(_json(value))
        directory = state / 'proposals' / proposal_id
        if directory.exists():
            _proposal(state, proposal_id)
        else:
            staging = _fs.stage_directory(state, '.proposal-')
            for name, digest in {'draft.md': new_hash, **files}.items():
                _write_once(staging / name, _get_object(state, digest))
            _write_once(staging / 'proposal.json', _json(value))
            _fsync_dir(staging)
            _rename_noreplace(staging, directory)
            _fsync_dir(directory.parent)
        return {'outcome': 'proposed', 'proposal_id': proposal_id,
                'proposal_dir': str(directory), **value}


def _request(target, proposal_id, operation_id, expect_target, expect_draft,
             decision, merged, expect_merged):
    if expect_target != 'absent':
        _sha(expect_target)
    _sha(expect_draft)
    _sha(proposal_id)
    _text(operation_id)
    if decision not in ('replace', 'merge'):
        raise GuardError('Decision must be replace or merge')
    if decision == 'merge':
        if merged is None:
            raise GuardError('Merge requires an independent file and expected hash')
        merged = str(_lexical_path(merged))
        _sha(expect_merged)
    elif merged is not None or expect_merged is not None:
        raise GuardError('Replace cannot include merged input')
    return {'schema': 'pstack-promotion-request/1', 'target': str(target),
            'proposal_id': proposal_id, 'operation_id': operation_id,
            'expect_target': expect_target, 'expect_draft': expect_draft,
            'decision': decision, 'merged_path': merged, 'expect_merged': expect_merged}


def _current_observation(target):
    try:
        return _target(target)[0].as_dict()
    except (OSError, GuardError):
        return {'sha256': 'unreadable', 'mode': None}


def _replay(target, receipt):
    return {**receipt, 'outcome': 'already_committed',
            'current_target': _current_observation(target)}


def _receipt(intent):
    return {'schema': 'pstack-promotion-receipt/1',
            'operation_id': intent['operation_id'],
            'proposal_id': intent['request']['proposal_id'],
            'intent_sha256': _digest(_json(intent)), 'outcome': 'committed',
            'desired_target': intent['desired_target'],
            'generated_baseline': intent['generated_baseline'],
            'prior_receipt': intent['prior_receipt']}


def _finish(state, intent):
    receipt = _receipt(intent)
    _write_once(_operation_dir(state, intent['operation_id']) / 'receipt.json', _json(receipt))
    return receipt


def _install(state, target, intent):
    _validate_prepared(state, target, intent)
    desired = _get_object(state, intent['desired_target'])
    prior = _Target(**intent['prior_target'])
    with _fs.stage(target.parent, desired, mode=intent['desired_mode'],
                   prefix='.' + target.name + '.pstack-') as staged:
        # The advisory lock excludes other guard writers. Recheck the target
        # after staging to detect edits made during preparation.
        _path(target)
        if _target(target)[0] != prior:
            raise GuardError('Target changed after preparation; recover the retained intent')
        if prior.sha256 == 'absent':
            _rename_noreplace(staged, target)
        elif prior.sha256 != intent['desired_target']:
            _fs.replace_existing(staged, target)
    _fsync_dir(target.parent)
    return _finish(state, intent)


def _validate_prepared(state, target, intent):
    request = intent['request']
    proposal = _proposal(state, request['proposal_id'])
    if (proposal['target'] != str(target) or request['target'] != str(target)
            or proposal['previous_promotion'] != intent['prior_receipt']
            or proposal['observed_target'] != intent['prior_target']
            or proposal['new_generated'] != intent['generated_baseline']):
        raise GuardError('Prepared intent differs from its retained proposal')
    _get_object(state, intent['desired_target'])
    if intent['prior_target']['sha256'] != 'absent':
        _get_object(state, intent['prior_target']['sha256'])
    _fsync_dir(_operation_dir(state, intent['operation_id']))


def promote(state, target, proposal_id, *, operation_id, expect_target,
            expect_draft, decision='replace', merged=None, expect_merged=None,
            single_writer=False, lock_timeout=5.0):
    """Apply an explicit decision once, under a cooperative single-writer lock."""
    if single_writer is not True:
        raise GuardError('Promotion requires one active target writer; acknowledge single_writer')
    state, target = _path(state), _target_path(target)
    request = _request(target, proposal_id, operation_id, expect_target,
                       expect_draft, decision, merged, expect_merged)
    if merged is not None:
        merge_path = Path(request['merged_path'])
        if merge_path == target or state == merge_path or state in merge_path.parents:
            raise GuardError('Merged input must be independent of target and state')
    with _locked(state, target, timeout=lock_timeout) as (state, target):
        directory = _operation_dir(state, operation_id)
        request_path = directory / 'request.json'
        if request_path.exists() and _read_json(request_path) != request:
            raise GuardError('Operation ID was already used with different inputs')
        receipt_path = directory / 'receipt.json'
        if receipt_path.exists():
            _operations(state)
            _fsync_dir(directory)
            return _replay(target, _read_json(receipt_path))
        _pending(state, operation_id)
        intent_path = directory / 'intent.json'
        if intent_path.exists():
            _operations(state)
            intent = _read_json(intent_path)
            if intent['request'] != request:
                raise GuardError('Prepared operation differs')
            if _target(target)[0].as_dict() != intent['prior_target']:
                raise GuardError('Prepared operation requires explicit recovery')
            return _install(state, target, intent)
        proposal = _proposal(state, proposal_id)
        current, _ = _history(state)
        prior_receipt = current['operation_id'] if current else None
        if (proposal['target'] != str(target)
                or proposal['previous_promotion'] != prior_receipt):
            raise GuardError('Proposal target or predecessor differs')
        if proposal['new_generated'] != expect_draft:
            raise GuardError('Draft hash differs')
        prior, old = _target(target)
        if (prior.sha256 != expect_target or prior.as_dict() != proposal['observed_target']):
            raise GuardError('Target differs from the reviewed proposal snapshot')
        desired = _get_object(state, expect_draft)
        if decision == 'merge':
            merge_path = _path(request['merged_path'])
            desired = _read(merge_path)[0]
            if _digest(desired) != expect_merged:
                raise GuardError('Merged hash differs')
        _directory(directory)
        _write_once(request_path, _json(request))
        if old is not None:
            _object(state, old)
        desired_hash = _object(state, desired)
        intent = {'schema': 'pstack-promotion-intent/1', 'operation_id': operation_id,
                  'request': request, 'prior_target': prior.as_dict(),
                  'desired_target': desired_hash,
                  'desired_mode': prior.mode if prior.mode is not None else _DEFAULT_MODE,
                  'generated_baseline': expect_draft, 'prior_receipt': prior_receipt,
                  'stage': 'prepared'}
        _write_once(intent_path, _json(intent))
        return _install(state, target, intent)


def recover(state, target, operation_id, *, lock_timeout=5.0):
    """Inspect a prepared operation; never overwrite unknown or prior bytes."""
    _text(operation_id)
    with _locked(state, target, timeout=lock_timeout) as (state, target):
        directory = _operation_dir(state, operation_id)
        intent = _read_json(directory / 'intent.json')
        _operations(state)
        receipt_path = directory / 'receipt.json'
        if receipt_path.exists():
            _fsync_dir(directory)
            return _replay(target, _read_json(receipt_path))
        _pending(state, operation_id)
        _validate_prepared(state, target, intent)
        current, _ = _history(state)
        if intent['prior_receipt'] != (current['operation_id'] if current else None):
            raise GuardError('Prepared operation predecessor differs')
        observed = _current_observation(target)
        if observed == {'sha256': intent['desired_target'], 'mode': intent['desired_mode']}:
            _get_object(state, intent['desired_target'])
            _get_object(state, intent['generated_baseline'])
            # Equality is consistent with the intent, not proof of who wrote it.
            _fsync_dir(target.parent)
            return _finish(state, intent)
        if observed == intent['prior_target']:
            return {'outcome': 'prepared', 'operation_id': operation_id,
                    'current_target': observed,
                    'reason': 'No commit observed; repeat the original promote decision to resume'}
        return {'outcome': 'uncertain' if observed['sha256'] == 'unreadable' else 'conflict',
                'operation_id': operation_id, 'current_target': observed,
                'reason': 'Target is neither prior nor desired state; all retained data is preserved'}


def _main(argv=None):
    _fs.configure_stdio_utf8()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('propose', 'promote', 'recover'):
        item = sub.add_parser(command)
        item.add_argument('--state', required=True)
        item.add_argument('--target', required=True)
        item.add_argument('--lock-timeout', type=float, default=5.0)
        if command == 'propose':
            item.add_argument('--generated', required=True)
            item.add_argument('--source', required=True)
            item.add_argument('--owner', required=True)
        else:
            item.add_argument('--operation-id', required=True)
        if command == 'promote':
            item.add_argument('--proposal', required=True)
            item.add_argument('--decision', choices=('replace', 'merge'), required=True)
            item.add_argument('--expect-target', required=True)
            item.add_argument('--expect-draft', required=True)
            item.add_argument('--merged')
            item.add_argument('--expect-merged')
            item.add_argument('--single-writer', action='store_true', required=True,
                              help='Acknowledge exclusive target ownership during promotion')
    args = parser.parse_args(argv)
    try:
        common = {'lock_timeout': args.lock_timeout}
        if args.command == 'propose':
            source = GeneratedSource.from_dict(_read_json(_path(args.source)))
            result = propose(args.state, args.target, args.generated, source,
                             owner=args.owner, **common)
        elif args.command == 'promote':
            result = promote(args.state, args.target, args.proposal,
                             operation_id=args.operation_id, expect_target=args.expect_target,
                             expect_draft=args.expect_draft, decision=args.decision,
                             merged=args.merged, expect_merged=args.expect_merged,
                             single_writer=args.single_writer, **common)
        else:
            result = recover(args.state, args.target, args.operation_id, **common)
    except (GuardError, OSError) as exc:
        result = {'outcome': 'error', 'reason': str(exc)}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result['outcome'] in ('proposed', 'committed', 'already_committed', 'prepared') else 1


if __name__ == '__main__':
    sys.exit(_main())
