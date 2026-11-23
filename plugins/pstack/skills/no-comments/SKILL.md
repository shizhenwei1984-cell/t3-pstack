---
name: no-comments
description: "Spawn Comment Sicko, fix accepted findings, and offer encodings for claimed constraints."
disable-model-invocation: true
---

# No comments

Ask Comment Sicko to screen the scoped comments. The parent decides which findings to accept and makes any edits.

## Scope

Use the caller's files or diff. Otherwise use the current diff against the base branch, default `main`, including the working tree.

## Steps

1. If the operator explicitly chose a target for this run, use it. Otherwise locate the existing sheet as described in [poteto-mode](../poteto-mode/SKILL.md#models). Run `node <plugin root>/skills/setup-pstack/scripts/t3-sheet.mjs --resolve-fixed-role comment-review <sheet path>`. Omit the path if neither sheet exists. Use `bun` if Node is unavailable. Here, `<plugin root>` is the directory that holds this plugin's `skills/`. Pass the resolver's JSON output unchanged as `target`.

   Dispatch one `delegate_task` child with `mode: "async"` and `role: "review"`. Start the brief with the worker.md pointer from poteto-mode, then "Read `<plugin root>/agents/comment-sicko.md` in full and act as it says". Give the child the scope and instruct it to review read-only, with no worktree so it can read uncommitted changes.

   If resolution fails, the target is unavailable, or dispatch or the child fails, report the specific error and leave the review open. Use only the resolved or operator-selected target with its exact options.
2. Review the proposed dispositions against the scoped code. Audit missed lint and TypeScript suppressions. Verify safety, correctness, concurrency, and external or platform constraints before acting. Trace the relevant code when the claim is unclear. Keep the comment while a consequential constraint is unresolved. If the child edited files or the report escaped scope, reject its report and leave the screening open.
3. Delete the comments the parent accepts for removal. Fix trivial accepted code findings directly by deleting a dead path, dropping a parameter, or using the real API. If an accepted, authorized fix needs a design, the parent runs `/architect` before implementation.
4. Implement the smallest accepted root-cause fix in scope. If the root cause is out of scope, report it open.
5. For a confirmed constraint, offer the cheapest in-scope type, runtime check, test, or CI lint. Wait for interactive approval before encoding it. Unattended and eval runs require caller pre-approval. Keep the constraint comment until the agreed check covers it.
6. Report the deletions, fixes, proposed or implemented checks, and unresolved findings.

## Models

Role defaults on T3, stamped from `plugins/pstack/models.json`. Each role below uses its listed target. A missing model-sheet row uses that binding. An explicit row must match it exactly.

- comment-review: `antigravity/gemini-4-hydrogen thought_level=medium`
