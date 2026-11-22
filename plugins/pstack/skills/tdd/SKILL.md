---
name: tdd
description: "Apply before each implementation change, including features, fixes, refactors, performance work and one-line edits. Applies to coordinators and code-writing workers."
disable-model-invocation: true
---

# Test-driven development

Read-only investigation, documentation-only edits and test authoring can proceed directly. Apply this workflow before editing any implementation, including executable scripts, behavior-changing configuration and code in candidate worktrees.

1. **Choose the contract.** State the observable result and select the smallest repeatable check that exercises the real path. Reuse a suitable existing regression, integration or browser test. Add a focused check when needed.
2. **Red.** Save the test in the project test suite before the first implementation edit, or identify an existing committed test that already fails for this contract. Keep it for future runs. A throwaway command or manual reproduction alone does not satisfy Red. For projects without a runner, keep a runnable regression script alongside the project. Run the check against the unchanged implementation in the checkout where the change will be made. Record the command and its actual failure. Confirm that it detects the requested behavior or constraint. Fix unrelated setup failures first. An existing failure qualifies when it meets these criteria.
3. **Green.** Make the smallest implementation change that satisfies the contract. Rerun the same check, with the same assertion, and record its passing result.
4. **Refactor and verify.** Clean up while the tests stay green. Run relevant surrounding tests. Repeat from Red for the next independent change.
5. **Hand back the evidence.** Include the test path, commands, observed Red and Green, and the surrounding checks run. The coordinator checks this evidence before accepting a delegated change.

For a behavior-preserving refactor, run a characterization test on the original code and keep it green throughout. For the initial Red, use a meaningful additional requirement of the requested refactor, such as a migrated public interface or removal of a prohibited dependency. Performance work can use a repeatable measured budget. Never manufacture Red by damaging working code, weakening assertions, or asserting arbitrary source text.

Stop before editing implementation code if a meaningful Red cannot be demonstrated. Report the missing prerequisite or contract. The user can explicitly make an exception for that task.
