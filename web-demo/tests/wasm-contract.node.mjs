import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function exportsFor(relativePath) {
  const path = fileURLToPath(new URL(relativePath, import.meta.url));
  const module = new WebAssembly.Module(readFileSync(path));
  return new Set(WebAssembly.Module.exports(module).map(entry => entry.name));
}

test('the shipped HAETAE binary contract is recorded accurately', () => {
  const exports = exportsFor('../public/haetae.wasm');
  for (const required of [
    'haetae_keypair',
    'haetae_sign',
    'haetae_verify',
    'haetae_publickeybytes',
    'haetae_secretkeybytes',
    'haetae_sigbytes',
  ]) {
    assert.ok(exports.has(required), `missing required HAETAE export: ${required}`);
  }

  // The active historical artifact predates the current C zeroization wrapper.
  // If a future artifact adds this export, revisit the fallback and evidence
  // docs instead of silently leaving the deployed contract stale.
  assert.equal(exports.has('haetae_secure_zeroize'), false);
});

test('the shipped SMAUG binary retains its C zeroization export', () => {
  const exports = exportsFor('../public/smaug.wasm');
  assert.ok(exports.has('smaug_secure_zeroize'));
});
