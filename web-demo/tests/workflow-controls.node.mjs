import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const workflowPath = fileURLToPath(
  new URL('../../.github/workflows/deploy-pages.yml', import.meta.url),
);
const workflow = readFileSync(workflowPath, 'utf8');

test('publishing authority is isolated from repository build jobs', () => {
  assert.match(workflow, /permissions:\n  contents: read\n/);
  assert.match(
    workflow,
    /pages-artifact:[\s\S]*permissions:\n      actions: read\n      pages: write\n      id-token: write[\s\S]*does not check out or execute repository code/,
  );
  assert.match(
    workflow,
    /deploy:[\s\S]*permissions:\n      pages: write\n      id-token: write/,
  );

  const artifactJob = workflow.slice(
    workflow.indexOf('\n  pages-artifact:'),
    workflow.indexOf('\n  deploy:'),
  );
  const deployJob = workflow.slice(
    workflow.indexOf('\n  deploy:'),
    workflow.indexOf('\n  dependabot-auto-merge:'),
  );
  assert.doesNotMatch(artifactJob, /actions\/checkout/);
  assert.doesNotMatch(deployJob, /actions\/checkout/);
});

test('pull requests test but do not retain or publish a Pages artifact', () => {
  assert.match(
    workflow,
    /Retain the tested site for a main publish only\n        if: github\.event_name != 'pull_request'/,
  );
  assert.match(
    workflow,
    /pages-artifact:\n    name: Prepare Pages artifact\n    if: github\.event_name != 'pull_request'/,
  );
});

test('main deploys cannot be cancelled by a newer run', () => {
  assert.match(
    workflow,
    /cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}/,
  );
});

test('all declared Node release lines run the web gate', () => {
  assert.match(workflow, /node: \[22, 24, 26\]/);
});

test('feature-off tests and warning-free clippy block the Rust gate', () => {
  assert.match(workflow, /cargo test -p qv-core --no-default-features/);
  assert.match(workflow, /cargo check -p qv-cli --release --no-default-features\n/);
  assert.doesNotMatch(workflow, /qv-cli[^\n]*kpqc-wasm/);
  assert.match(workflow, /cargo clippy --workspace --all-targets -- -D warnings/);
  assert.match(
    workflow,
    /cargo test -p qv-core --no-default-features --features kpqc-native \\\n+              --test differential_tests/,
  );
});

test('downloaded native source is authenticated before it is compiled', () => {
  const sourceJob = workflow.slice(
    workflow.indexOf('\n  source:'),
    workflow.indexOf('\n  pages-artifact:'),
  );
  const authenticateAt = sourceJob.indexOf(
    'Capture and authenticate immutable public source archives',
  );
  const compileAt = sourceJob.indexOf(
    'Compile and exercise the fixed Level 3 / Mode 3 native FFI',
  );
  assert.ok(authenticateAt >= 0);
  assert.ok(compileAt > authenticateAt);
  assert.match(sourceJob.slice(authenticateAt, compileAt), /hashlib\.sha256/);
  assert.match(sourceJob.slice(authenticateAt, compileAt), /wasm\/reproduction\.json/);
});

test('only gated patch and minor dependency updates can auto-merge', () => {
  assert.match(workflow, /update-type == 'version-update:semver-major'/);
  assert.match(workflow, /update-type == 'version-update:semver-patch'/);
  assert.match(workflow, /update-type == 'version-update:semver-minor'/);
  assert.match(workflow, /gate passed but the dependency PR did not merge[\s\S]*exit 1/);
  assert.doesNotMatch(workflow, /Merge any bump/);
});
