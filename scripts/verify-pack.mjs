import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const scratch = mkdtempSync(join(tmpdir(), "api-access-kit-pack-"));
try {
  execFileSync("npm", ["run", "build"], { stdio: "inherit" });
  const tarball = execFileSync("npm", ["pack", "--json"], { encoding: "utf8" });
  const [{ filename }] = JSON.parse(tarball);
  execFileSync("npm", ["init", "-y"], { cwd: scratch, stdio: "ignore" });
  execFileSync("npm", ["install", join(process.cwd(), filename)], { cwd: scratch, stdio: "inherit" });
  // Smoke-test this package's own packed surface via a native ESM import. This is
  // deliberately hermetic: it installs only this tarball (zero runtime deps) and
  // does not reach for sibling kits, so a sibling's tags or network can't red this gate.
  execFileSync("node", ["--input-type=module", "-e", `
    import * as access from '@andrewpopov/api-access-kit';
    const required = [
      'issueApiAccessCredential',
      'issueReplacementApiAccessCredential',
      'authenticateApiAccessCredential',
      'authorizeApiAccess',
      'defineApiScopes',
      'defineApiAccessPepperRing',
      'defineApiCommands',
      'DEFAULT_API_ACCESS_HASH_VERSION',
    ];
    const missing = required.filter((name) => access[name] === undefined);
    if (missing.length > 0) {
      console.error('[verify:pack] missing exports: ' + missing.join(', '));
      process.exit(2);
    }
  `], { cwd: scratch, stdio: "inherit" });
  console.log("[verify:pack] PASS: the packed package installs and exposes its public surface (ESM import).");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
