---
name: how
description: "Use for \"how does X work\", code walkthroughs before changing something, and placement / ownership / layering questions (\"where should this live\", \"which package owns this\", \"is this the right layer\"). Explains subsystem architecture, runtime flow, onboarding mental models. Use why for motivation."
disable-model-invocation: true
---

# How

Explore the codebase to answer "how does X work?" questions.

If the scope is ambiguous, state your interpretation and explore. The user can redirect.

## 1. Collect evidence

Dispatch one read-only `delegate_task` child with `role: "research"` using the model sheet’s `explore` target and all its options. Give it the user's question and this brief:

> Trace the relevant code path. Return observed behavior, file and line references, and any unresolved questions. The caller will write the explanation.

## 2. Present

Use the returned evidence to write your own explanation for the user. Label uncertainties and request further evidence from the explorer when needed.
