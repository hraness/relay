import { test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

test("Required remains a Bash-only status gate on slim", () => {
  const block = readFileSync(new URL(".github/workflows/ci.yml", import.meta.url), "utf8").split("  required:\n")[1]!;
  expect(block).toBe(`    name: Required
    if: always()
    needs: check
    runs-on: ubuntu-slim
    timeout-minutes: 5
    steps:
      - name: Require every blocking job
        env:
          CHECK: \${{ needs.check.result }}
        run: |
          set -euo pipefail
          [[ "$CHECK" == success ]]
`);
  const script = block.split("        run: |\n")[1]!.replace(/^          /gm, "");
  for (const CHECK of ["success", "failure", "cancelled", "skipped", ""]) {
    const result = spawnSync("/bin/bash", ["--noprofile", "--norc", "-eo", "pipefail", "-c", script], { env: { PATH: "/nonexistent", CHECK }, timeout: 1000 });
    expect(result.error).toBeUndefined();
    expect(result.status === 0).toBe(CHECK === "success");
  }
});
