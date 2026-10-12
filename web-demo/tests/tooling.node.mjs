import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'package.json'));
const compiler = path.join(root, 'node_modules/.bin/tsc');

function compile(source) {
  const directory = mkdtempSync(path.join(tmpdir(), 'quantum-vault-ts7-'));
  try {
    const input = path.join(directory, 'control.ts');
    writeFileSync(input, source);
    return spawnSync(compiler, [
      '--ignoreConfig', '--noEmit', '--strict', '--skipLibCheck', '--target', 'ES2020', input,
    ], { cwd: root, encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '0' } });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('the build uses native TypeScript 7 while tooling receives the supported API', () => {
  const native = require('@typescript/native/package.json');
  const api = require('typescript/package.json');
  assert.equal(native.name, 'typescript');
  assert.equal(native.version, '7.0.2');
  assert.equal(api.name, '@typescript/typescript6');
  assert.equal(api.version, '6.0.2');
  assert.match(realpathSync(compiler), /[\\/]@typescript[\\/]native[\\/]bin[\\/]tsc$/);
  assert.match(execFileSync(compiler, ['--version'], { encoding: 'utf8' }), /^Version 7\.0\.2\s*$/);
  assert.match(ts.version, /^6\.0\./);
  assert.equal(typeof ts.createProgram, 'function');
});

test('the native compiler accepts valid strict TypeScript', () => {
  const result = compile('export const identity = (input: number): number => input;\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('the native compiler rejects implicit any and invalid null assignment', () => {
  const result = compile('export function identity(input) { return input; }\nexport const invalid: string = null;\n');
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /TS7006/);
  assert.match(result.stdout + result.stderr, /TS2322/);
});
