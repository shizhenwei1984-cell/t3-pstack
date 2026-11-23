import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

test("CI exercises evidence commands and recovery on each native platform", () => {
  const workflow = Bun.YAML.parse(readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8"));
  const job = workflow.jobs["python-evidence"];
  expect(job["runs-on"]).toBe("${{ matrix.os }}");
  expect(job.strategy["fail-fast"]).toBe(false);
  expect(job.strategy.matrix.os).toEqual(["ubuntu-latest", "macos-latest", "windows-latest"]);
  expect(job.steps.some(({ uses }) => /^actions\/setup-python@[0-9a-f]{40}$/.test(uses))).toBe(true);
  for (const suite of ["test_*_evidence.py", "test_evidence_fs.py", "test_guarded_document.py"]) {
    expect(job.steps.some(({ run }) => run?.includes(`python -B -m unittest discover -s tests -p '${suite}' -v`))).toBe(true);
  }
  expect(job.steps.some(({ run }) => run === "python -B tests/evidence_cli_smoke.py")).toBe(true);
  expect(job.steps).toContainEqual({
    name: "Exercise evidence commands in PowerShell",
    if: "runner.os == 'Windows'",
    shell: "pwsh",
    run: "./tests/evidence-powershell-smoke.ps1",
  });
});
