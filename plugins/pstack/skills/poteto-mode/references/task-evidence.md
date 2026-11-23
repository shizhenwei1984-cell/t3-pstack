# Task evidence reference

[task_evidence.py](../scripts/task_evidence.py) preserves local evidence, checks
reuse, and derives a verification summary and case table from one pinned snapshot.
It treats recorded `command.argv` as data. It requires Python 3.10 or later.
The [validation helper](validation-evidence.md) checks fixture artifacts and visible candidate state.

## Supported storage

Use a local Linux filesystem with hard links, `flock`, `fsync`, and
`renameat2` with `RENAME_NOREPLACE`. Ext4, XFS, and Btrfs provide these operations.
On macOS, use APFS or HFS+ volumes that support `RENAME_EXCL` and `F_FULLFSYNC`.
On Windows, use writable local NTFS with persistent ACLs on Windows 10 version 1607 or
later or Windows Server 2019 or later. Keep the guard state and target on one
volume. For paths beyond MAX_PATH, enable Win32 long paths for Python. Replacing a
read-only target requires NTFS support for `FileRenameInfoEx`.

Writers flush staged file contents before atomic publication. Linux syncs the
containing directory after each namespace update. macOS uses `F_FULLFSYNC` for
files and `fsync` for directories. Windows uses write-through staging files and
flushes file handles. Recovery on NTFS covers process termination. Persistence
of directory-entry changes after power loss depends on NTFS cache commit.

Storage capabilities are checked at use. A volume that cannot provide the
required operation returns a JSON error.
On Windows, `check` and `publication` can read a store without write capability.
The volume must enforce persistent ACLs and provide stable file identities.
The store must still meet the path and ownership requirements below.

## CLI

Set `plugin_root` to the absolute path of the installed plugin directory that
contains `skills/`. Use a task directory outside the plugin and the ephemeral
roots described below. Pass each returned path and SHA-256 to the next command
that reads the artifact.

```sh
plugin_root=/absolute/path/to/installed/plugin
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" preserve \
  --input /home/owner/task/import.json --store /home/owner/task/evidence
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" check \
  --snapshot /home/owner/task/evidence/snapshots/SHA/manifest.json --sha256 SHA
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" check \
  --snapshot /home/owner/task/evidence/snapshots/SHA/manifest.json --sha256 SHA \
  --context /home/owner/task/current.json
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" render \
  --snapshot /home/owner/task/evidence/snapshots/SHA/manifest.json --sha256 SHA \
  --out /home/owner/task/render-1
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" render \
  --snapshot /home/owner/task/evidence/snapshots/SHA/manifest.json --sha256 SHA \
  --out /home/owner/task/render-2 --links /home/owner/task/links.json
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" publication \
  --render /home/owner/task/render-2/render.json --sha256 RENDER_SHA
```

`preserve` returns `snapshot` and `snapshot_sha256`. `render` returns `render` and
`render_sha256`. Every read requires that trusted digest. There is no mutable
latest pointer. The render destination must be new, including when the same
snapshot is rendered again. `publication` checks local files and performs only
the explicitly mapped anonymous fetches. It does not publish them.

Exit 0 means the requested scope completed. Exit 1 means invalid or unverified;
JSON preserves that distinction. Argument errors exit 2. A `check` without a
context exits 0 when archive integrity, archive consistency, and review readiness
are valid, while reporting `reuse: unknown` for consistent archives. A check with
a context also requires `reuse: valid`.
`preserve` and `render` can retain unresolved reviews for inspection. Neither
operation is a readiness gate. Publication verifies content/access separately
from review readiness and from product behavior.

### PowerShell

Use PowerShell 7 on Windows. Write input JSON as UTF-8 without a byte order mark.
Capture `$LASTEXITCODE` immediately after running Python, then parse the response.

```powershell
$script = Join-Path $pluginRoot 'skills/poteto-mode/scripts/task_evidence.py'
Set-Content -LiteralPath $requestPath -Value $requestJson -Encoding utf8NoBOM
$response = & python $script preserve --input $requestPath --store $archivePath
$exitCode = $LASTEXITCODE
$result = ($response -join "`n") | ConvertFrom-Json
```

## Versioned manifest

The import object has exactly these fields. Arrays of entities use unique IDs.
References name entities in the same manifest. These definitions are the schema;
all object fields are required unless a nullable value is explicitly listed.
Unknown fields, duplicate JSON keys/IDs, nonfinite numbers, malformed references,
and booleans in integer fields fail validation. All timestamps are RFC3339 UTC
with `Z`, all paths are absolute, and all hashes are 64 lowercase hex characters.
IDs match `[A-Za-z0-9][A-Za-z0-9._:-]*`. JSON and output files use UTF-8 regardless
of the process locale. Each input, object, outgoing file, and remote body is
limited to 16 MiB.

```text
Manifest = {
  schema: "pstack-evidence/1", task_id: ID, owner: ActorID,
  retention: {owner: ActorID, durable_root: AbsolutePath, cleanup_after: UTC|null},
  actors: Actor[], candidates: Candidate[], resources: Resource[],
  artifacts: Artifact[], records: Record[], cases: Case[],
  review_inventory: Inventory, reviews: Review[], notes: AbsolutePath[]
}
Actor = {id: ID, role: "owner"|"author"|"verifier"|"reviewer"}
Candidate = {id: ID, sha256: SHA, author: ActorID, artifact: ArtifactID}
Resource = {id: ID, owner: ActorID, generation: ID, environment: ID,
            observed_at: UTC, expires_at: UTC}
Artifact = Available | Missing
Available = {id: ID, kind: Kind, state: "available",
             source: {path: AbsolutePath, host: "local"},
             sha256: SHA, media_type: String}
Missing = {id: ID, kind: Kind, state: "missing",
           source: {path: AbsolutePath, host: String},
           sha256: SHA|null, missing_reason: String}
Kind = "raw"|"command"|"environment"|"report"|"trace"|"diff"|"blame"|"recorder"|"source"
```

`actors`, `candidates`, `artifacts`, `cases`, and inventory items are nonempty.
`resources` and `records` must contain every referenced entity. The package owner
has role `owner`; retention and inventory use that owner. Actor IDs validate
stated responsibility, without authenticating people or model families.

A candidate's `sha256` must equal its candidate artifact's expected hash. For a
single-source fixture this can be its source file. A larger candidate can use an
externally prepared source bundle or canonical inventory as that artifact. The
helper preserves its exact bytes; it does not infer a Git tree from a worktree
or attest that code was loaded. Reusing one candidate ID for several entity
entries fails, even if their content matches. Across snapshots, callers compare
the candidate content digest as well as its ID.

Artifact IDs `summary` and `cases` are reserved for rendered reports.
Artifacts in different worker directories are supported. Any non-`local` source
host is `remote_source_unavailable`; transfer it explicitly, verify its hash,
and import the local copy. Missing evidence must be declared as `Missing`.
An undeclared absent file fails with `missing_source`. The helper does not
silently replace absent raw bytes with narrative report bytes.

Preservation checks supplied hashes and stable descriptor/path metadata around
reads, copies bytes into independent store objects, and rechecks existing objects
on retry. Sources that alias a mutable `notes` path by resolution or inode fail.
Symlinks, directories, devices, and FIFOs are not regular-file sources. The
metadata checks detect observed changes; they are not an atomic filesystem
snapshot against a hostile writer.

```text
Record = {
  id: ID, candidate: CandidateID, observer: ActorID,
  observed_at: UTC, expires_at: UTC, evidence_type: EvidenceType,
  resource: ResourceID, resource_owner: ActorID,
  resource_generation: ID, environment: ID,
  command: {argv: String[], cwd: AbsolutePath, exit_code: Integer|null,
            started_at: UTC|null, finished_at: UTC|null, execution_id: ID|null},
  harness: {description: String,
            substitutions: [{component: String, replacement: String, impact: String}],
            boundaries: String[]},
  artifacts: ArtifactID[], declared_outcome: "pass"|"fail"|"unknown",
  rechecks: RecordID|null, limitation: String|null,
  producer: {name: String, artifact: ArtifactID|null}
}
EvidenceType = "executed"|"independent_recheck"|"historical_secondary"|"environment_snapshot"
Case = {
  id: ID, candidate: CandidateID, scenario: ID, scenario_sha256: SHA, entry: String,
  expected: {kind: "json_equal", value: JSONValue}|{kind: "text_equal", value: String},
  actual: {kind: "artifact", artifact: ArtifactID, format: "json"|"utf8"}
          |{kind: "unverified", reason: String},
  records: RecordID[]
}
```

Cases are unique by candidate and scenario. Each referenced record has that
candidate. `scenario_sha256` identifies the caller's request/fixture definition;
the helper preserves it, without establishing equivalence from the label alone.
An actual artifact has kind `raw` or `trace`, belongs to an execution/recheck
record, and has a format matching the expected kind. Source, diff, report, and
environment artifacts cannot supply a measured actual. Rendering compares parsed
canonical JSON or exact UTF-8 text.
A measured match remains separate from declared outcome and command exit status.

Execution requires available candidate content, raw/trace and environment bytes,
nonempty argv, integer exit code, and execution ID. Start/finish/observation
times must be ordered for valid archive consistency. All its attached evidence
must be available. Capture stdout, stderr, and
any command/environment files as separate artifact references. Command metadata,
harness substitutions, limitations, source locators, and the opaque producer
reference are preserved in the snapshot alongside those files. A declared pass
with nonzero exit is retained as a declaration, and the render shows both values.
It cannot establish product success.

An `independent_recheck` names an `executed` original via `rechecks`, uses the same
candidate, has a verifier distinct from both the candidate author and original
observer, and has an execution ID and capture sources distinct from every other
archived execution/recheck. A raw path/inode alias of any such execution is
rejected on import; sealed manifests retain the source paths for comparison.
Independently captured identical
output bytes are allowed. These checks establish declared separation, not that
a trusted observer actually executed the recorded command.

`historical_secondary` requires an available report, an explicitly missing
original artifact, a limitation describing the gap, and a null execution ID.
Known historical command/exit/times can remain recorded; unknown values stay
null, with argv `[]` when unknown. Do not invent them. Available surviving raw
files remain separate originals alongside the report. A historical or environment
record cannot supply a measured actual case result. Its case stays `unverified`.
An environment snapshot requires environment bytes and an unknown behavioral
outcome. It never discharges a behavior obligation.

The producer name and optional copied artifact are a proposed interoperability
reference for a future #4 recorder. No existing recorder schema or RED/GREEN
sequence compatibility is asserted, and no stored argv is run.

## Reviews

```text
Inventory = {owner: ActorID, revision: ID,
             items: [{id: ID, candidate: CandidateID, subject: ArtifactID, description: String}]}
Review = {
  item: InventoryItemID, reviewer: ActorID,
  candidate_sha256: SHA, subject_sha256: SHA, inventory_sha256: SHA,
  disposition: "accept"|"change"|"defer"|"reject", reason: String,
  evidence: ArtifactID[], limitation: String|null
}
```

The reviewed subject is a preserved artifact, such as a diff. Each review binds
its candidate content, subject bytes, and entire owner-authored inventory. The
inventory digest hashes canonical JSON after sorting items by ID. Owner revision
and description changes therefore invalidate prior reviews. Inventory revision
is explicit history, not a mutable merge of reviewer submissions. A consumer
that expects an earlier obligation inventory supplies its digest in the reuse
context; a package alone cannot detect obligations its trusted owner never
listed. Importing reviews does not update the inventory.

Unknown or duplicate review items fail the schema. Missing reviews,
empty/missing citations, missing subject bytes, or subject/digest changes prevent
ready status. Readiness reopens and hash-checks the candidate, subject, and every
supporting artifact, including size and regular-file checks. A declared digest
without available bytes cannot discharge a review. Deleted or corrupt retained
bytes invalidate readiness as well as archive integrity. Every disposition needs
supporting preserved evidence. A limitation or a non-`accept` disposition remains
unresolved, even when all fields exist.
Both rendered views retain the missing/unresolved items.

Reason lint normalizes Unicode NFKC, case, whitespace, punctuation, separators,
and formatting/control characters. It rejects empty and exact bare verdicts,
including `PASS`, `retain`, `ok`, `lgtm`, `通過`, `通过`, `保留`, `好`, `沒問題`,
`合格`, and `承認`. Concise English, Chinese, Japanese, and Korean reasons are
accepted without a length cutoff. This is bounded structural lint. It cannot
judge whether a sentence or citation makes a sound argument.

## Ownership and archive integrity

The resolved store must be inside the explicitly declared `durable_root`, outside
installed plugin and skill trees and actual ephemeral roots. The helper checks
the running plugin root, enclosing Codex, Claude Code, and Antigravity plugin
manifests, and the default and configured skill roots. The Kiro installer copy
includes the Claude Code manifest. `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/`,
`tempfile.gettempdir()`, and configured `TMPDIR`, `TEMP`, `TMP`, and
`XDG_RUNTIME_DIR` roots are excluded after resolution. Symlink escapes in store
object/snapshot directories fail. There is no production allow-temp bypass.
Create the durable root before preserving evidence. On POSIX the directory
owner must be the effective user. On Windows the owner must be the token user
or the default Administrators owner of an elevated token, with a non-null
DACL. The tools create Windows directories with a protected DACL for the
invoking user, SYSTEM, and Administrators. System, Program Files, ProgramData,
Public, the Windows Temp directory, and canonical temporary directories are
excluded. The Darwin per-user temporary directory is also excluded. Windows
paths use absolute drive names. Reparse points at guarded locations, device
names, and alternate data streams are rejected. The manifest's actor ID is a
separate declaration from filesystem ownership.

On case-insensitive APFS and NTFS, the guard uses the stored filename spelling.
For an absent target, its persistent lock records the spelling used at proposal
time. A Windows reader that denies delete sharing blocks replacement and leaves
the prepared intent available for retry.

```text
STORE/owner.json
STORE/objects/SHA
STORE/snapshots/SNAPSHOT_SHA/manifest.json
```

`owner.json` binds the task, owner, root, and retention policy. Conflicting imports
fail without replacing it. `cleanup_after` is the earliest owner-controlled
cleanup eligibility date. Null means retain until explicit owner cleanup. The
helper never automatically deletes evidence, and a passed date does not delete
files. The task owner owns storage and backups. Copies and directory fsyncs do
not guarantee media survival or network-filesystem power-loss behavior.

The sealed manifest uses the same schema with each available artifact changed
to `state: "preserved"` and an integer `size` field. Object paths are derived
from SHA-256, never supplied by JSON. Its exact canonical bytes are the snapshot
identity. Entity arrays and inventory items are sorted by ID, reviews by item;
other arrays retain their semantic order. Canonical JSON sorts keys, uses compact
separators and UTF-8 without Unicode normalization, and permits only finite values.

Write-once object/manifest installation uses flushed private partial files and
no-clobber linking. Source files and rendered views are independent copies, not
user-editable hardlink aliases of objects. A snapshot becomes readable only when
its complete `manifest.json` is installed. Interruptions can retain unpublished
partial files and orphan objects. Retry revalidates them and never repairs a
corrupt existing object by overwriting it. No invocation sweeps another writer's
partial files. Immutability means helper write-once plus integrity verification,
not protection against deliberate filesystem edits.

Every operation reopens the expected manifest and hashes preserved bytes.
`original_removed` is informational when a copied original path disappears.
`missing_original` records declared historical loss with informational status;
it remains visible without failing byte integrity or publication content/access.
`missing_preserved` and
`hash_mismatch` fail archive integrity, including a missing report accompanying
an already missing original. A worker completion report or terminal screen is only a locator; inspected
runtime material does not establish server retention. This helper owns its copies.

`archive_consistency` checks metadata independently from byte integrity, across
all candidates and records even without a reuse context. It reports each owner,
generation, and environment contradiction, resource/record expiry ordering,
records observed at or after resource expiry, out-of-order command timestamps,
and archived rechecks that do not follow the original observation. A resource's
observation can postdate a record from the same generation; it is an archived
observation, not a generation start time. Both bound any new current observation.
Semantic time contradictions are retained by `preserve` and `Snapshot.read` for
inspection, then reported together by `check`; malformed timestamp syntax still
fails parsing. Intact bytes can have invalid metadata. `render` retains a visible
archive-consistency status; publication remains a content/access check.

## Reuse context

```text
ReuseContext = {
  schema: "pstack-reuse/1", candidate: {id: CandidateID, sha256: SHA}, observer: ActorID,
  purpose: "navigation"|"behavior"|"independent_behavior", checked_at: UTC,
  inventory_sha256: SHA, observations: [{path: AbsolutePath, sha256: SHA}]
}
CurrentObservation = {
  schema: "pstack-current-observation/1", candidate: {id: CandidateID, sha256: SHA},
  observer: ActorID, observed_at: UTC, resource: Resource,
  evidence_type: "environment_snapshot"|"independent_recheck",
  execution_id: ID|null, rechecks: RecordID|null,
  raw: {path: AbsolutePath, sha256: SHA}, producer: String, limitations: String[]
}
```

The context resolves separate hash-bound observation JSON files and their own
hash-bound raw captures. Observations are keyed by `(resource.id, rechecks)`;
distinct record rechecks on one resource are supported without changing the
`pstack-current-observation/1` JSON shape. Duplicate bindings are invalid,
including conflicting duplicates. A null `rechecks` is a resource-level navigation
observation; it cannot discharge a behavioral record recheck. Each observation
must use the context observer, be strictly newer than both the archived record
and resource observations, agree with its current resource observation time,
and be unexpired at `checked_at`. Invalid time ordering does not suppress owner,
generation, environment, or expiry findings. Candidate, owner, generation,
environment, and explicit record/resource expiries are compared
per record. All applicable findings are retained. Unknown runtime fields belong
in `limitations`, for example `loaded_candidate unknown; source bytes only`.
A copied old environment declaration or an unresolved file reference is not fresh
observation. No universal TTL or resident-code probe is invented.

For both behavior purposes, the obligation set is every `executed` or
`independent_recheck` record linked by a case for the selected candidate. Every
such record requires its own fresh recheck observation, including an archived
recheck when it is case-linked. Each candidate case must have behavioral records
and a measured actual; an auxiliary-only or explicitly unverified case remains
`behavior_unverified`. A candidate with no cases cannot pass vacuously. Unlinked
records and auxiliary historical/environment records remain visible as
`context_only` informational findings; they do not automatically fail behavior
reuse or discharge a case. Their archive integrity and consistency still apply.
Navigation checks every candidate record and may use a resource-level observation.

Behavior rechecks require a distinct declared verifier, a non-null execution ID,
and `rechecks` binding to the archived record/resource/candidate. Execution IDs
must differ from all archived executions and other current rechecks; raw paths
and inodes must not alias archived captures, stored raw objects, or another
current recheck capture. Identical independently collected bytes are permitted.
These inputs retain observations for independent assessment; the checker neither
runs the command nor authenticates the probe's factual claims.

The result has `archive_integrity`, `archive_consistency`, `review_readiness`,
and `reuse` statuses, plus `execution: "declarations_only"` and findings. Statuses are `valid`, `invalid`,
or `unknown`; invalid takes precedence within a scope. Major finding codes are
`candidate_mismatch`, `owner_mismatch`, `environment_stale`, `expired`,
`environment_unknown`, `historical_only`, `behavior_unverified`,
`independence_unverified`, `time_order_invalid`, `context_only`,
`review_missing`, `review_subject_mismatch`, `review_candidate_missing`,
`review_subject_missing`,
`review_inventory_mismatch`, `review_reason_invalid`, `review_evidence_missing`,
and `review_unresolved`. Intact archive bytes can coexist with stale or unknown
reuse. Archive-consistency errors also invalidate reuse and fail the CLI check
with or without a current context. A valid check is not newly executed product
acceptance.

## Rendering and publication

One pinned in-memory snapshot drives `summary.md` and `cases.md`. Both describe
entry, candidate, scenario, expected/actual values, evidence classification,
declared outcome/exit, harness substitutions, limits, and reviews. Internal
source paths, actor/runtime IDs, commands, and full digests are not copied into
these views. Callers remain responsible for the privacy and meaning of actual
case data and public case/review IDs. Data punctuation becomes numeric entities,
so fields cannot inject Markdown links, table rows, autolinks, or raw HTML.

`render.json` binds the snapshot path/hash, renderer source hash, exact hashes of
both documents, and the explicit link intent. Its own canonical-byte digest is
returned to the caller. Rendered views never alias preserved objects. The output
path is validated before creating any parent or staging directory: it must be
absolute, absent even as a dangling symlink, with canonical directory parents
and no symlink ancestors. Invalid destinations leave no staging files or new
parents. The directory is claimed exclusively, then documents are installed before
`render.json`, which is the completion marker. An interruption may leave an
incomplete directory without that marker; retain it for diagnosis and retry in
a fresh directory. The default render creates only these immutable outputs.

### Propose an update to reviewed text

Supply all three options to retain a summary proposal on a supported local volume.

```sh
python3 "$plugin_root/skills/poteto-mode/scripts/task_evidence.py" render \
  --snapshot /home/owner/task/evidence/snapshots/SHA/manifest.json --sha256 SHA \
  --out /home/owner/task/render-3 \
  --document-state /home/owner/task/summary-state \
  --target /home/owner/task/reviewed-summary.md --document-owner task-owner
```

The options are all-or-none. Partial groups fail before reading the snapshot or
writing output. Empty owners, invalid Unicode identities, aliased paths, and
overlapping output, state, or target locations fail before rendering. Every path
component ending in `.pstack-guard.lock` is reserved for locks. Render outputs
cannot use that namespace or its descendants, even without document options.
Document state and target paths cannot use it either.
Ordinary and guarded renders reject output paths containing invalid Unicode
before creating directories or files. CLI errors escape Unicode characters so
even rejected surrogate paths produce structured JSON under the C locale.
The guard checks storage and existing
owner/target bindings under its lock after the immutable render completes. If
proposal creation fails, the completed render remains available for inspection;
the command exits nonzero. Retry with a fresh output directory.

Successful JSON adds `proposal` without changing `render.json` or publication
checks. The proposal uses this invocation's snapshot digest, renderer digest,
and `render_sha256` as its common `render_id`. Its draft is the hash-checked
`summary.md`. The reviewed target stays available as the proposal's comparison
base. The case table remains in the immutable render.

### Publication links

Optional link intent is exactly:

```json
{
  "schema": "pstack-links/1",
  "audience": "public-anonymous",
  "links": [
    {"item": "raw-capture", "url": "https://raw.githubusercontent.com/owner/repo/FULL_COMMIT/raw.json"},
    {"item": "summary", "url": "https://raw.githubusercontent.com/owner/repo/FULL_COMMIT/summary.md"}
  ]
}
```

Replace `FULL_COMMIT` with 40 or 64 lowercase hex digits. An item is an available
artifact ID or the reserved report name `summary` or `cases`. Report links are
checked against the exact outgoing bytes, but are not inserted into their own
document. Artifact links are emitted in both views. Each item and URL occurs
once. Missing artifacts cannot receive invented links. URL strings are bounded
ASCII without Markdown delimiters. Evidence fields never emit implicit links.
There is no caller-supplied remote expected hash: the checker derives it from
preserved artifact or rendered bytes.

Before network checks, publication reopens the pinned snapshot, verifies every
preserved artifact, rehashes both outgoing documents, and regenerates both from
the same snapshot and link intent. Changed renderer source requires a new render.
Post-render edits or a different pair cannot pass by changing only file hashes.

The only supported fetch is credential-free HTTPS at exactly
`raw.githubusercontent.com/OWNER/REPO/FULL_COMMIT/PATH`. No credentials, cookies,
proxy configuration, redirect following, query, fragment, port, percent encoding,
dot segments, empty path segments, or mutable refs are accepted. The supported
path subset uses ASCII letters, digits, dot, underscore, and hyphen in segments.
The client uses a 10-second socket timeout and body deadline, plus the 16 MiB
body bound. OS resolver and socket behavior remain platform constraints.

HTTP 200 with exact bytes establishes anonymous access from this environment at
the reported time. Redirects, 401, 403, 404, and 410 are invalid. Other HTTP errors,
network/TLS/timeouts, unsupported hosts, and other audiences are unknown.
Local/relative/file links are invalid for every audience, before unsupported
audience classification. None establishes universal future access.
A failed emitted link stays failed. To omit it, generate a new render without it.

With no links, publication returns `links: "checked_no_links"`, never
`links_verified`. Inline scenario/expected/actual/limits remain usable, subject
to [recipient review](engineering-enhancements.md#recipient-review). Historical
missing originals remain explicit, including when their secondary report has a
working link. Their informational status does not turn verified links into
`links_unverified` or fail an otherwise valid no-link publication. Missing or
corrupt retained secondary-report bytes still fail. Publication is a
content/access check, not authorization to publish.

## Python API

Import `task_evidence.py` and call `preserve(request_dict, absolute_store)`;
`Snapshot.read(absolute_manifest_path, expected_sha256)`;
`ReuseContext.parse(context_dict)`; `check(snapshot, context=None)`;
`render(snapshot, absolute_fresh_output, links=None)`; and
`publication(absolute_render_json, expected_sha256)`. These are the same operations
as the CLI. `Snapshot.data` returns an independent parsed copy;
`Snapshot.artifact_bytes(id)` rechecks the preserved object's hash.
`inventory_digest(inventory)` computes the review inventory binding.
`canonical(value)` and `digest(bytes)` expose the documented byte identity rule.
`render` also accepts keyword-only `document_state`, `target`, and
`document_owner`, supplied together, for the summary proposal described above.
The sibling guard is loaded from its local file path and cached without changing
`sys.path`. Loading this module through `importlib` and using Python safe-path
mode both support guarded rendering.
Invalid inputs raise `EvidenceError` with a structured `finding`; filesystem
write failures can raise `OSError`. Guard rejections, including malformed stored
document records, raise `EvidenceError` with code `document_guard_error` and keep
that code in CLI JSON. The CLI serializes errors without running
recorded commands. Supporting private functions are not an integration contract.
