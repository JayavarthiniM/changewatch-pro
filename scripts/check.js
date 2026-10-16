#!/usr/bin/env node
'use strict';

// Repeatable local preflight: syntax-check every project JavaScript file, then run unit tests.
// Does not install dependencies or claim live API/browser acceptance.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const ignoredDirs = new Set(['node_modules', '.git', 'coverage']);
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!ignoredDirs.has(entry.name)) walk(path.join(dir, entry.name));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      files.push(path.join(dir, entry.name));
    }
  }
}
walk(root);
files.sort();
let failed = false;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) {
    failed = true;
    process.stderr.write(`FAIL syntax ${path.relative(root, file)}\n${result.stderr || result.stdout}`);
  } else {
    process.stdout.write(`PASS syntax ${path.relative(root, file)}\n`);
  }
}
if (failed) {
  process.stderr.write('\nPreflight stopped: syntax errors found. Unit tests were not run.\n');
  process.exit(1);
}
process.stdout.write(`\nJavaScript syntax: ${files.length}/${files.length} files passed.\n\n`);
const tests = spawnSync(process.execPath, ['--test'], { cwd: root, stdio: 'inherit' });
process.exit(typeof tests.status === 'number' ? tests.status : 1);
