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
  execFileSync("node", ["--input-type=module", "-e", "import('@andrewpopov/api-access-kit')"], { cwd: scratch, stdio: "inherit" });
  console.log("[verify:pack] PASS: tarball installs and exports its public surface.");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
