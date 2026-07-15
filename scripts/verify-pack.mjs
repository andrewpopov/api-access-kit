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
  execFileSync("npm", ["install", join(process.cwd(), filename), "github:andrewpopov/alert-kit#v0.4.0", "github:andrewpopov/release-kit#v0.1.2", "github:andrewpopov/express-security-kit#v1.6.0"], { cwd: scratch, stdio: "inherit" });
  execFileSync("node", ["--input-type=module", "-e", `
    import * as access from '@andrewpopov/api-access-kit';
    import { AlertDeliveryError } from '@andrewpopov/alert-kit';
    import { createReleaseArtifactV1 } from '@andrewpopov/release-kit';
    import { verifyApiKey } from '@andrewpopov/express-security-kit';
    if (!access.authenticateApiAccessCredential || !AlertDeliveryError || !createReleaseArtifactV1 || !verifyApiKey) process.exit(2);
  `], { cwd: scratch, stdio: "inherit" });
  console.log("[verify:pack] PASS: immutable packed shared-kit contracts install and expose their conformance surface.");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
