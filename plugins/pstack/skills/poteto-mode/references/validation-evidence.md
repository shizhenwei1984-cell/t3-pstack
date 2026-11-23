# Fixture, candidate and evidence checks

[validation-evidence.py](../scripts/validation-evidence.py) checks fixture
artifacts, observes a candidate's visible source and process, and summarizes
sealed run records. Its results describe those observations. Use
[task evidence](task-evidence.md) to preserve them with their provenance and
render a summary from a pinned snapshot.

Use Python 3.10 or later. Set `plugin_root` to the absolute path of the installed
plugin directory that contains `skills/`. Keep inputs, captures, and redirected
results in a separate task directory. Paths in JSON must be absolute.

```sh
plugin_root=/absolute/path/to/installed/plugin
python3 "$plugin_root/skills/poteto-mode/scripts/validation-evidence.py" fixture-plan "/path/to/run-dir/fixture.json" > "/path/to/run-dir/fixture-plan.json"
python3 "$plugin_root/skills/poteto-mode/scripts/validation-evidence.py" fixture "/path/to/run-dir/fixture.json" > "/path/to/run-dir/fixture-check.json"
python3 "$plugin_root/skills/poteto-mode/scripts/validation-evidence.py" preflight "/path/to/run-dir/candidate.json" > "/path/to/run-dir/preflight.json"
python3 "$plugin_root/skills/poteto-mode/scripts/validation-evidence.py" summary "/path/to/run-dir/index.json" > "/path/to/run-dir/summary.json"
```

Exit 0 means the selected artifact check passed or fixture preparation is `ready`; exit 1 means fail, invalid or
uncovered. Always read `outcome` and the reasons. Preflight currently always
returns `uncovered`/1 because `loaded_candidate` remains `unknown`, even when
source and process observations are verified. Do not hide this with a shell
pipeline or translate it to a product failure/pass. No dependency installation
or runtime fallback is performed.

## Fixture contract: `literal-files-v1`

This adapter supports only a literal route map file whose whole lines have the
form `normal:confirm -> confirm.tpl`. The requested route must be nonblank,
without surrounding whitespace, line breaks or the ` -> ` separator, and have
exactly one map entry; duplicate or conflicting entries are uncovered. The
template must be a physical sibling with the bound filename beside the resolved
map file. A source symlink is allowed; a template symlink escaping that directory
is uncovered.
This is useful for projects with a literal fixture route catalog or an explicit
export from a separately reviewed project adapter. It does **not** parse arbitrary
factory source code, infer supported flows, or certify an unreviewed export.
Choose a project adapter when dispatch is dynamic. A boolean `supported: true`
is insufficient: this helper reads and hashes the actual map and template,
checks the requested route binding, and checks that the template contains the
requested slot. Unknown routes/adapters are `uncovered`, never Green.

Minimal input (replace all example paths, values and hashes):

```json
{
  "adapter": "literal-files-v1",
  "candidate": "revision-or-run-candidate-id",
  "route": "normal:confirm",
  "supported_routes": {"normal:confirm": "/run/confirm.tpl"},
  "source": {
    "path": "/run/routes.txt",
    "sha256": "<64 lowercase hex digits>",
    "binding": "normal:confirm -> confirm.tpl"
  },
  "template": "/run/confirm.tpl",
  "template_sha256": "<64 lowercase hex digits>",
  "slot_literal": "{{field}}",
  "extract": {"start": "<slot>", "end": "</slot>"},
  "canary": "independently-seeded-private-value",
  "benign_expected": "ordinary output",
  "outputs": {
    "target": "/run/target.raw",
    "positive": "/run/positive.raw",
    "benign": "/run/benign.raw"
  }
}
```

Before live fixture creation, run `fixture-plan` to check the route map, template
and intended slot without requiring captured outputs or control settings. It
returns `ready`, never `pass`, and cannot establish runtime reachability. Confirm
the map against the project's real dispatcher/template loader; this adapter only
checks its literal artifact representation. For a full `fixture` result, supply
three separately captured outputs in distinct physical files. Same-path, symlink
and hardlink aliases are uncovered; distinct files alone do not establish capture
independence. `outputs` and `extract` must be objects. Each output must have
exactly one start delimiter,
exactly one end delimiter after it and non-whitespace content between them.
The positive slot must contain the seeded canary; benign content must equal
`benign_expected` and omit the canary. With valid controls, canary present in the
target means `fail`; absent means this artifact check `pass`. Missing/ambiguous
extraction, missing files or failed controls mean `uncovered`. This is a literal
UTF-8 extraction adapter, independent of the host locale. Canary tokens must
match `[A-Za-z0-9_.-]+`; escapable or non-ASCII tokens are uncovered rather than
silently comparing differently encoded values. This restriction does not prove
detection of arbitrary application transformations. It is not an HTML parser;
use unique capture delimiters and
a project adapter for structured/encoded output. Do not include the intentional
positive slot in the target capture. The helper reports lengths, not canary text.
The input producer is responsible for independent canary provenance and binding
all captures to the named candidate/request. Merely providing these files cannot
prove live route reachability, HTTP status, request identity or test execution.

## Read-only candidate preflight

```json
{
  "candidate": "revision-or-run-candidate-id",
  "source_mode": "local",
  "files": [
    {"host": "/repo/module.py", "visible": "/repo/module.py", "sha256": "<64 lowercase hex digits>"}
  ],
  "process": {
    "pid": 1234,
    "start_ticks": 123456,
    "boot_id": "<Linux boot id from baseline observation>",
    "argv": ["python3", "/repo/server.py"]
  }
}
```

Capture the expected identity and command independently for each relevant PID.
A prefork pool requires one observation for each relevant process. Local
preflight accepts these process profiles.

| `profile` | Required fields besides positive integer `pid` | Native observation |
| --- | --- | --- |
| `linux` or omitted | Nonnegative integer `start_ticks`, string `boot_id`, exact nonempty string array `argv` | Linux reads field 22 of `/proc/PID/stat` and checks the identity around the command-line read. Empty arguments are retained. |
| `darwin` | String `boot_session_uuid`, nonnegative integers `start_sec` and `start_usec`, exact nonempty string array `argv` | macOS checks the boot session and process start around the `KERN_PROCARGS2` read. It preserves empty arguments and discards environment bytes. |
| `windows` | Unsigned 64-bit decimal string `creation_filetime`, nonempty raw string `command_line` | Windows reads creation time from a waitable process handle and checks liveness before and after collecting the command line. For another PID it queries the Windows PowerShell CIM provider. |

On Windows, preserve the command line's exact quoting and spaces. Use a string
for FILETIME to preserve all digits in JSON readers. PowerShell can read the
creation time with `(Get-Process -Id $processId).StartTime.ToFileTimeUtc()`. Convert
that value to a decimal string before writing JSON. Read the command line from
`Get-CimInstance Win32_Process -Filter "ProcessId = $processId"`. Use the UTF-8
invocation from the [task evidence reference](task-evidence.md#powershell).

Malformed or differing identity yields `process_status: mismatch`. Missing,
denied, dead, or changing process data yields `process_status: unknown`.
This includes truncated Darwin argument records and Windows processes for which
the caller lacks permission to wait on the process handle.
Preflight keeps `loaded_candidate: unknown` and exits 1 even when source and
process both verify.

Supported explicit source modes:

- `local`: host and visible paths must resolve to the same physical file. Hashes
  are read locally; no claim about a container is made.
- `docker-bind`: also supply `container`. Docker inspect must show a running
  container and the longest covering mount must be a bind whose host mapping
  matches each host path. Both host and container-visible bytes must match the
  declared hash. Docker Desktop bind sources that cannot be resolved to a native
  Windows file leave the source check unknown.
- `docker-image`: supply `container` and exact `image_id` from Docker inspect
  (`sha256:…`, not a mutable tag). The running container image ID must match and
  no mount may shadow a tested path. Both host reference bytes and container
  bytes must match the declared hash. This does not prove absence of unrelated
  writable-layer changes.

Docker modes use the Linux process profile and absolute POSIX paths inside the
guest regardless of the host OS. Docker modes require an available CLI, daemon,
and container `cat`;
only fixed `docker inspect` and `docker exec CONTAINER cat -- ABSOLUTE_PATH`
argument arrays run, with timeouts. There is no shell and no manifest command
field. Inspect uses `--type container --` before the caller identifier, and all
subsequent file/proc reads use the inspected container ID. A failed running/image
identity check leaves process status unknown and skips process reads. Visible
paths and mount destinations are lexically normalized as absolute POSIX paths
before longest-mount selection and file reads, including `.` and `..` segments.
A bind mapping must remain within the resolved host mount source. This cannot
resolve symlinks inside the container rootfs; project-owned runtime probes remain
necessary. Proc paths are read in the selected container. Missing runtime is
`unknown`; unrecognized source mode/platform capability is unsupported/unknown,
never a local fallback. Results include observed file hashes, process identity
and container ID when available. These are point-in-time observations, not
atomic snapshots. Source/PID success does not prove loaded interpreted modules,
shared libraries, caches or reload completion: `loaded_candidate: unknown`
remains explicit until a separate project-specific runtime probe establishes it.
No reload, stop, database or template mutation is authorized by this helper.

## Sealed evidence versus mutable notes

```json
{
  "candidate": "revision-or-run-candidate-id",
  "notes": ["/run/plan.md", "/run/coordination.md"],
  "records": [
    {
      "candidate": "revision-or-run-candidate-id",
      "outcome": "pass",
      "exit": 0,
      "evidence": [{"path": "/run/both-green.raw", "sha256": "<64 lowercase hex digits>"}]
    }
  ]
}
```

Capture command exit status and adapter outcome in records at execution time;
retain the command/environment in the sealed evidence. Hash raw files once
sealed (e.g. `sha256sum /run/both-green.raw`) and store the index separately.
`summary` hashes bytes, including binary files, without renaming, rewriting or
creating raw evidence. Every record must name the index candidate, have explicit
`outcome: pass`, integer `exit: 0` and nonempty, present, hash-matching sealed
evidence to produce a passing summary; every sealed file must contain at least
one byte. `notes` must be an array of absolute paths, `records` a nonempty array
of objects, and `evidence` a nonempty array of objects. Malformed types fail
with structured errors. A filename containing `green` cannot
override nonzero exit, wrong candidate, uncovered outcome or missing evidence.
Unknown/failed historical results stay so in the index. The summary retains each
record's declared outcome, exit and candidate with validation errors.

Mutable note paths are excluded from sealing; changing them does not invalidate
sealed evidence. Listing the same resolved path or physical file (including a
hardlink) as a note and sealed evidence is rejected. Notes may not yet exist;
other path errors, including symlink loops, fail with errors. This is logical sealing through hashes, not filesystem immutability or
a cryptographic attestation of the record author: keep the trusted original index
and compare it in review. Do not regenerate hashes to conceal changed raw data.
A passing summary verifies the supplied index and bytes, not the truth of an
untrusted recorder or a new product test. Keep raw historical filenames intact.
