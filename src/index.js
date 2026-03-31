#!/usr/bin/env node

import { execSync } from "child_process";
import { readFileSync, createReadStream } from "fs";
import { resolve, basename, extname, dirname } from "path";
import { fileURLToPath } from "url";
import pc from "picocolors";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Rules ────────────────────────────────────────────────────────────────────

const RULES = [
  {
    id: "source-maps",
    description: "Source map files (.map) expose your full source code",
    severity: "error",
    match: (file) => file.endsWith(".map"),
    hint: "Add '*.map' to .npmignore, or set sourceMap: false in your bundler config.",
  },
  {
    id: "env-files",
    description: "Environment files may contain secrets",
    severity: "error",
    match: (file) => /^\.env(\.|$)/.test(basename(file)),
    hint: "Add '.env*' to .npmignore.",
  },
  {
    id: "source-directory",
    description: "Raw source directory is being published",
    severity: "warn",
    match: (file) => /^(src|source|lib\/src)\//.test(file),
    hint: "Use the 'files' field in package.json to whitelist only your dist output.",
  },
  {
    id: "large-file",
    description: "Suspiciously large file (>5MB) — likely an unintended artifact",
    severity: "warn",
    // Only warn for 5-20MB range; >20MB is an error handled separately
    match: (_file, meta) => meta?.size > 5 * 1024 * 1024 && meta?.size <= 20 * 1024 * 1024,
    hint: "Verify this file is intentional. Large files are often debug artifacts.",
  },
  {
    id: "large-file-extreme",
    description: "Extremely large file (>20MB) — almost certainly an accident",
    severity: "error",
    match: (_file, meta) => meta?.size > 20 * 1024 * 1024,
    hint: "A 59.8MB source map is how Anthropic leaked their codebase. Remove this file.",
  },
  {
    id: "secrets-filename",
    description: "Potential secrets file detected",
    severity: "error",
    match: (file) => {
      const base = basename(file).toLowerCase();
      // Match exact names or names that start with these words (not contain, to avoid false positives)
      return (
        /^(secrets?|credentials?|private-key|api-key|auth-key)(\.|$)/.test(base) ||
        base === ".npmrc" ||
        base === "auth.json" ||
        base === "service-account.json" ||
        base === "firebase-adminsdk.json" ||
        base === "gcloud-service-key.json"
      );
    },
    hint: "Add this file to .npmignore immediately.",
  },
  {
    id: "private-keys",
    description: "Private key or certificate file detected",
    severity: "error",
    match: (file) => {
      const ext = extname(file).toLowerCase();
      return [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"].includes(ext);
    },
    hint: "Private keys must NEVER be published to npm. Remove immediately.",
  },
  {
    id: "config-files",
    description: "Internal config/tooling file included",
    severity: "warn",
    match: (file) => {
      const base = basename(file);
      return [
        ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.cjs",
        ".prettierrc", ".prettierrc.js", ".prettierrc.json",
        "jest.config.js", "jest.config.ts", "jest.config.mjs",
        "tsconfig.json", ".babelrc", ".babelrc.js",
        "vitest.config.ts", "vitest.config.js",
        "rollup.config.js", "rollup.config.mjs",
        "webpack.config.js", "webpack.config.mjs",
        ".editorconfig", ".browserslistrc",
      ].includes(base);
    },
    hint: "Consider removing internal tooling configs from your published package.",
  },
  {
    id: "test-files",
    description: "Test files are being published",
    severity: "warn",
    match: (file) =>
      /\.(test|spec)\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file) ||
      /^(test|tests|__tests__|__mocks__|__snapshots__|coverage|\.nyc_output)\//.test(file),
    hint: "Use the 'files' field in package.json or .npmignore to exclude tests.",
  },
  {
    id: "git-directory",
    description: "Version control directory included",
    severity: "error",
    match: (file) => /^(\.git|\.svn|\.hg)\//.test(file),
    hint: "This should never be in an npm package. Check your .npmignore.",
  },
  {
    id: "ide-files",
    description: "IDE configuration files included",
    severity: "warn",
    match: (file) => /^(\.vscode|\.idea|\.vs)\//.test(file),
    hint: "Add IDE directories to .npmignore.",
  },
];

// ─── Secret Content Scanning ─────────────────────────────────────────────────

const SECRET_PATTERNS = [
  { pattern: /(?:['"`\s=:])(?:sk-[a-zA-Z0-9]{20,})/, name: "OpenAI API key" },
  { pattern: /(?:['"`\s=:])(?:sk-ant-[a-zA-Z0-9-]{20,})/, name: "Anthropic API key" },
  { pattern: /(?:['"`\s=:])(?:ghp_[a-zA-Z0-9]{36,})/, name: "GitHub token" },
  { pattern: /(?:['"`\s=:])(?:gho_[a-zA-Z0-9]{36,})/, name: "GitHub OAuth token" },
  { pattern: /(?:['"`\s=:])(?:glpat-[a-zA-Z0-9\-_]{20,})/, name: "GitLab token" },
  { pattern: /(?:['"`\s=:])(?:xoxb-[a-zA-Z0-9\-]+)/, name: "Slack bot token" },
  { pattern: /(?:['"`\s=:])(?:xoxp-[a-zA-Z0-9\-]+)/, name: "Slack user token" },
  { pattern: /AKIA[A-Z0-9]{16}/, name: "AWS access key" },
  { pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, name: "Private key" },
  { pattern: /(?:['"`\s=:])(?:npm_[a-zA-Z0-9]{36,})/, name: "npm token" },
  { pattern: /(?:['"`\s=:])(?:sk_live_[a-zA-Z0-9]{24,})/, name: "Stripe secret key" },
  { pattern: /(?:['"`\s=:])(?:SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,})/, name: "SendGrid key" },
  { pattern: /(?:['"`\s=:])(?:AIza[a-zA-Z0-9_-]{35})/, name: "Google API key" },
];

const TEXT_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  ".json", ".yaml", ".yml", ".toml", ".xml",
  ".md", ".txt", ".csv", ".html", ".css", ".scss",
  ".env", ".cfg", ".conf", ".ini", ".sh",
  ".py", ".rb", ".go", ".rs", ".java", ".php",
]);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getVersion() {
  try {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf-8"));
    return pkg.version ?? "1.0.0";
  } catch {
    return "1.0.0";
  }
}

function getPackedFiles(cwd) {
  const output = execSync("npm pack --dry-run --json 2>/dev/null", {
    encoding: "utf8",
    cwd,
    maxBuffer: 50 * 1024 * 1024,
  });
  const parsed = JSON.parse(output);
  const entry = Array.isArray(parsed) ? parsed[0] : parsed;
  return {
    files: entry?.files ?? [],
    totalSize: entry?.unpackedSize ?? 0,
    name: entry?.name ?? "unknown",
    version: entry?.version ?? "0.0.0",
  };
}

function formatSize(bytes) {
  if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${bytes}B`;
}

function isTextFile(filePath) {
  return TEXT_EXTENSIONS.has(extname(filePath).toLowerCase());
}

function scanFileForSecrets(filePath, cwd) {
  try {
    const fullPath = resolve(cwd, filePath);
    const content = readFileSync(fullPath, "utf-8");
    const found = [];
    for (const { pattern, name } of SECRET_PATTERNS) {
      if (pattern.test(content)) {
        found.push(name);
      }
    }
    return found;
  } catch {
    return [];
  }
}

// ─── Parse CLI args ───────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = { cwd: process.cwd(), json: false, allowSrc: false };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    if (arg === "--version" || arg === "-v") {
      console.log(getVersion());
      process.exit(0);
    }
    if (arg === "--json") { opts.json = true; continue; }
    if (arg === "--allow-src") { opts.allowSrc = true; continue; }
    if (!arg.startsWith("-")) { opts.cwd = resolve(arg); }
  }
  return opts;
}

function printHelp() {
  console.log(`
  ${pc.bold("publish-guard")} — Pre-publish safety linter for npm packages

  Built because Anthropic leaked their Claude Code source to npm. Twice.

  ${pc.bold("USAGE")}
    npx publish-guard           Scan current directory
    npx publish-guard ./path    Scan specific directory

  ${pc.bold("OPTIONS")}
    --json         Output as JSON (for CI parsing)
    --allow-src    Don't warn about src/ directory
    -h, --help     Show this help
    -v, --version  Show version

  ${pc.bold("CI INTEGRATION")}
    Add to package.json:
    {
      "scripts": {
        "prepublishOnly": "npx publish-guard"
      }
    }
`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function run() {
  const opts = parseArgs(process.argv);

  console.log();
  console.log(pc.bold("publish-guard") + pc.dim(" — pre-publish safety check"));
  console.log(pc.dim("─".repeat(50)));

  // 1. Get packed files
  let packInfo;
  try {
    packInfo = getPackedFiles(opts.cwd);
  } catch {
    console.error(pc.red("✖ Failed to run `npm pack --dry-run`. Are you in an npm package directory?"));
    process.exit(1);
  }

  const { files, totalSize, name, version } = packInfo;

  console.log(pc.dim(`Package:  ${name}@${version}`));
  console.log(pc.dim(`Size:     ${formatSize(totalSize)}`));
  console.log(pc.dim(`Scanning ${files.length} files...\n`));

  // 2. Run rules
  const errors = [];
  const warnings = [];

  // Package-level size check
  if (totalSize > 20 * 1024 * 1024) {
    errors.push({
      file: "(package total)",
      size: totalSize,
      rule: {
        id: "package-too-large",
        description: `Package is ${formatSize(totalSize)} — this is suspiciously large`,
        hint: "Anthropic's leaked package was 59.8MB. Check what you're shipping.",
      },
    });
  }

  for (const fileEntry of files) {
    const filePath = fileEntry.path;
    const meta = { size: fileEntry.size };

    // Skip src/ warnings if --allow-src
    if (opts.allowSrc && /^(src|source)\//.test(filePath)) continue;

    for (const rule of RULES) {
      if (rule.match(filePath, meta)) {
        const finding = { file: filePath, size: meta.size, rule };
        if (rule.severity === "error") errors.push(finding);
        else warnings.push(finding);
      }
    }

    // Secret content scanning (only text files under 2MB)
    if (meta.size < 2 * 1024 * 1024 && isTextFile(filePath)) {
      const secrets = scanFileForSecrets(filePath, opts.cwd);
      for (const secretName of secrets) {
        errors.push({
          file: filePath,
          size: meta.size,
          rule: {
            id: "secret-in-content",
            description: `Possible ${secretName} found in file contents`,
            severity: "error",
            hint: "Never publish secrets to npm. Remove the secret and rotate it immediately.",
          },
        });
      }
    }
  }

  // 3. JSON output
  if (opts.json) {
    process.stdout.write(JSON.stringify({
      package: { name, version, size: totalSize, fileCount: files.length },
      errors: errors.map(e => ({ file: e.file, rule: e.rule.id, description: e.rule.description })),
      warnings: warnings.map(w => ({ file: w.file, rule: w.rule.id, description: w.rule.description })),
      passed: errors.length === 0,
    }, null, 2) + "\n");
    process.exit(errors.length > 0 ? 1 : 0);
  }

  // 4. Print warnings
  if (warnings.length > 0) {
    console.log(pc.yellow(pc.bold(`⚠  ${warnings.length} warning${warnings.length > 1 ? "s" : ""}`)));
    for (const w of warnings) {
      console.log(`   ${pc.yellow("▸")} ${pc.bold(w.file)} ${pc.dim(`(${formatSize(w.size)})`)}`);
      console.log(`     ${pc.dim(w.rule.description)}`);
      console.log(`     ${pc.cyan("→")} ${pc.dim(w.rule.hint)}`);
    }
    console.log();
  }

  // 5. Print errors
  if (errors.length > 0) {
    console.log(pc.red(pc.bold(`✖  ${errors.length} error${errors.length > 1 ? "s" : ""} — publish blocked`)));
    for (const e of errors) {
      console.log(`   ${pc.red("▸")} ${pc.bold(e.file)} ${pc.dim(`(${formatSize(e.size)})`)}`);
      console.log(`     ${pc.dim(e.rule.description)}`);
      console.log(`     ${pc.cyan("→")} ${pc.dim(e.rule.hint)}`);
    }
    console.log();
    console.log(pc.dim("─".repeat(50)));
    console.log(pc.red("Publish aborted. Fix the errors above before publishing."));
    console.log(pc.dim("Run `npm pack --dry-run` to see all files that would be included.\n"));
    process.exit(1);
  }

  // 6. All clear
  if (warnings.length === 0) {
    console.log(pc.green(pc.bold("✔  All clear!")));
  } else {
    console.log(pc.green(pc.bold("✔  No errors.")));
  }
  console.log(pc.dim(`   ${files.length} files checked, ready to publish.\n`));
}

run();
