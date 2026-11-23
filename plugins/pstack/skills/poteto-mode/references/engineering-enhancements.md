# Engineering evidence and recipient review

## Record evidence and decisions

For each verification result, record the candidate identity, executor, command or action, environment, expected and actual results, artifact path and SHA-256, and execution ID when available. Use these provenance labels.

- `executed` identifies a fresh observation.
- `independent_recheck` identifies a fresh observation by another executor. Link it to the run it checks.
- `historical_secondary` identifies a result recovered from a prior report or history. Preserve gaps in the original evidence and the recorded test boundaries. A recovered report cannot establish a fresh run.

Record any replacement for a real dependency and the behavior that remains unverified. Bind findings to the candidate that produced them. Verification in separate worktrees covers those worktrees. Check the integrated candidate when the claim covers the integrated result.

Use [task evidence](task-evidence.md) to preserve artifacts before cleanup, check a pinned snapshot, and render its summary and cases. Use [validation evidence](validation-evidence.md) for literal fixture checks, source and process observations, and sealed run summaries.

Before rewriting a deliverable, cross-check confirmed facts, decisions, owners, and deadlines. Retain those details unless a user instruction or new evidence supersedes them. Record the basis for each change.

## Test regressions across stages

In a multi-stage transform, drive the first affected entry point through preprocessing, fast paths, and the final interpretation. For each downstream call, identify which inputs are plain values, replacements, or arguments that the receiver interprets again.

Vary entry conditions independently. Cover the trigger present, the trigger absent, and an earlier stage consuming the last trigger when those cases are reachable. Seed a positive control that exercises the expected behavior without opening the tested entry gate. Record before-change behavior for syntax variants that callers rely on.

If the root cause spans a known finite set of entry points and input sources or states, record reachability, expected behavior, and the observed failure or coverage gap for each combination during Red. Rerun the affected cases after the fix.

## Recipient review

Before an authorized PR write, read the exact title, body, and comments as a first-time recipient. Replace private workstream labels and agent roles with concrete behavior and public references. Preserve real symbols, repository-relative source paths, routes, public case IDs, and the purpose of each PR dependency.

Keep local evidence paths, digests, internal execution IDs, and dispatch context in the internal record. Link evidence the recipient can access. When evidence is private, describe the executed scenario, expected and actual results, and coverage limits.

Preserve confirmed decisions, responsibilities, and the next action. Name owners only where established. Read each amended paragraph in full against the confirmed facts. After creation or amendment, fetch the published text and repeat the review on what the recipient sees.
