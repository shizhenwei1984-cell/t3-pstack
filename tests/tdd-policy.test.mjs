import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL("../plugins/pstack/" + path, import.meta.url), "utf8");

test("the session, coordinator and delegated writers all route code changes through TDD", () => {
  for (const file of ["hooks/session-start-context.md", "skills/poteto-mode/SKILL.md", "skills/poteto-mode/worker.md"]) {
    expect(read(file)).toContain("Before changing implementation code");
    expect(read(file)).toContain("tdd/SKILL.md");
  }
});

test("TDD requires observed evidence and gives a blocked path when Red is unavailable", () => {
  const skill = read("skills/tdd/SKILL.md");
  expect(skill).toContain("Run the check against the unchanged implementation");
  expect(skill).toContain("Stop before editing implementation code");
  expect(skill).toContain("characterization");
  expect(read("skills/poteto-mode/playbooks/bug-fix.md")).not.toContain("Skip it when the test would be expensive");
});
