import fs from "node:fs/promises";
import path from "node:path";

function compilePatterns(input) {
  return input.map((pattern) => new RegExp(pattern, "m"));
}

async function listFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(fullPath)));
      continue;
    }
    if (entry.isFile() && /\.(ts|tsx|js|mjs|cjs)$/.test(entry.name)) {
      files.push(fullPath);
    }
  }
  return files;
}

const [, , packageDirArg, labelArg, ...patterns] = process.argv;
if (!packageDirArg || !labelArg || patterns.length === 0) {
  console.error(
    "Usage: node tools/check-package-boundaries.mjs <packageDir> <label> <regex> [<regex>...]",
  );
  process.exit(1);
}

const packageDir = path.resolve(packageDirArg);
const scanDirs = [path.join(packageDir, "src"), path.join(packageDir, "test")];
const forbiddenPatterns = compilePatterns(patterns);
const files = (await Promise.all(scanDirs.map((dir) => listFiles(dir)))).flat();
const violations = [];

for (const file of files) {
  const content = await fs.readFile(file, "utf8");
  if (forbiddenPatterns.some((pattern) => pattern.test(content))) {
    violations.push(path.relative(packageDir, file));
  }
}

if (violations.length > 0) {
  console.error(`Boundary check failed for ${labelArg}.`);
  for (const violation of violations) {
    console.error(` - ${violation}`);
  }
  process.exit(1);
}

console.log(`Boundary check passed for ${labelArg}.`);
