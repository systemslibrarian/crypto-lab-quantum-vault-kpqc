"""Build input controls; fixture compiler outputs are not reproduced WASM."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build.sh"


class BuildPreflight(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qv-preflight-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.wasm = self.root / "wasm"
        self.wasm.mkdir()
        self.script = self.wasm / "build.sh"
        shutil.copyfile(SCRIPT, self.script)
        self.smaug = self.wasm / "vendor/smaug-t/reference_implementation"
        self.haetae = self.wasm / "vendor/haetae/HAETAE-1.1.2/reference_implementation"
        for tree in (self.smaug, self.haetae):
            (tree / "include").mkdir(parents=True)
            (tree / "src").mkdir()
        (self.wasm / "src").mkdir()
        # Placeholders satisfy existence only. No upstream code is invented.
        text = SCRIPT.read_text()
        roots = {"SMAUG_SRC": self.smaug, "HAETAE_SRC": self.haetae,
                 "SCRIPT_DIR": self.wasm}
        for variable, suffix in re.findall(r'"\$(SMAUG_SRC|HAETAE_SRC|SCRIPT_DIR)(/[^"\n]+\.c)"', text):
            (roots[variable] / suffix.lstrip("/")).write_text("/* fixture */\n")
        (self.smaug / "include/kem.h").write_text("/* fixture */\n")
        (self.haetae / "include/api.h").write_text("/* fixture */\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "compiler-calls"
        compiler = self.bin / "emcc"
        compiler.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$PREFLIGHT_CALLS"
count=$(wc -l < "$PREFLIGHT_CALLS" | tr -d ' ')
if [ "$count" = "${PREFLIGHT_FAIL_CALL:-0}" ]; then exit 17; fi
if [ "$count" = "${PREFLIGHT_SKIP_OUTPUT_CALL:-0}" ]; then exit 0; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    shift
    if [ "${PREFLIGHT_EMPTY_OUTPUTS:-0}" = 1 ]; then
      : > "$1"
      : > "${1%.js}.wasm"
      break
    fi
    if [ "${PREFLIGHT_LINK_OUTPUTS:-0}" = 1 ]; then
      ln -s "$PREFLIGHT_CALLS" "$1"
      ln -s "$PREFLIGHT_CALLS" "${1%.js}.wasm"
      break
    fi
    printf 'fixture loader\\n' > "$1"
    if [ "${PREFLIGHT_LOADER_ONLY:-0}" = 1 ]; then break; fi
    printf 'fixture binary\\n' > "${1%.js}.wasm"
    break
  fi
  shift
done
""")
        compiler.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(self.bin) + ":/usr/bin:/bin",
                                PREFLIGHT_CALLS=str(self.calls))

    def run_build(self, **environment):
        return subprocess.run(["/bin/bash", str(self.script)], cwd=self.root,
                              env=dict(self.environment, **environment),
                              capture_output=True, text=True, timeout=15)

    def assert_unread_before_outputs(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("UNREAD", result.stderr)
        self.assertFalse(self.calls.exists(), "compiler ran with incomplete inputs")
        self.assertFalse((self.wasm / "dist").exists(), "incomplete inputs created outputs")

    def test_missing_vendor_directories(self):
        shutil.rmtree(self.wasm / "vendor")
        self.assert_unread_before_outputs(self.run_build())

    def test_missing_declared_source_prevents_partial_build(self):
        for path in (self.smaug / "src/io.c", self.haetae / "src/sign.c",
                     self.wasm / "src/randombytes_wasm.c"):
            with self.subTest(path=str(path)):
                contents = path.read_bytes()
                path.unlink()
                self.assert_unread_before_outputs(self.run_build())
                path.write_bytes(contents)

    def test_missing_wrapper_header_prevents_compiler(self):
        for path in (self.smaug / "include/kem.h", self.haetae / "include/api.h"):
            with self.subTest(path=str(path)):
                contents = path.read_bytes()
                path.unlink()
                self.assert_unread_before_outputs(self.run_build())
                path.write_bytes(contents)

    def test_missing_compiler_is_unread(self):
        (self.bin / "emcc").unlink()
        self.assert_unread_before_outputs(self.run_build())

    def test_unreadable_source_is_unread(self):
        path = self.smaug / "src/io.c"
        path.chmod(0)
        try:
            if os.access(path, os.R_OK):
                self.skipTest("current user bypasses fixture file permissions")
            self.assert_unread_before_outputs(self.run_build())
        finally:
            path.chmod(0o600)

    def test_complete_fixture_inputs_reach_both_compiler_calls(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn(str(self.smaug / "src/io.c"), calls[0])
        self.assertIn(str(self.haetae / "src/sign.c"), calls[1])
        self.assertEqual(len(list((self.wasm / "dist").glob("*.wasm"))), 2)

    def test_successful_compiler_with_missing_outputs_is_incomplete(self):
        for call in ("1", "2"):
            with self.subTest(call=call):
                result = self.run_build(PREFLIGHT_SKIP_OUTPUT_CALL=call)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("UNREAD", result.stderr)
                self.assertNotIn("Build complete", result.stdout)
                self.assertEqual(len(self.calls.read_text().splitlines()), int(call))
                shutil.rmtree(self.wasm / "dist")
                self.calls.unlink()

    def test_loader_without_binary_is_incomplete(self):
        result = self.run_build(PREFLIGHT_LOADER_ONLY="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("UNREAD", result.stderr)
        self.assertNotIn("Build complete", result.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)

    def test_empty_outputs_are_incomplete(self):
        result = self.run_build(PREFLIGHT_EMPTY_OUTPUTS="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("UNREAD", result.stderr)
        self.assertNotIn("Build complete", result.stdout)

    def test_symlink_outputs_are_incomplete(self):
        result = self.run_build(PREFLIGHT_LINK_OUTPUTS="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("UNREAD", result.stderr)
        self.assertNotIn("Build complete", result.stdout)

    def test_preexisting_output_evidence_is_preserved_before_compilation(self):
        dist = self.wasm / "dist"
        dist.mkdir()
        before = {name: ("historical:" + name).encode()
                  for name in ("smaug.js", "smaug.wasm", "haetae.js", "haetae.wasm")}
        for name, content in before.items():
            (dist / name).write_bytes(content)
        result = self.run_build()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("UNREAD", result.stderr)
        self.assertNotIn("Build complete", result.stdout)
        self.assertFalse(self.calls.exists())
        self.assertEqual({path.name: path.read_bytes() for path in dist.iterdir()}, before)

    def test_first_compiler_failure_is_not_success(self):
        result = self.run_build(PREFLIGHT_FAIL_CALL="1")
        self.assertEqual(result.returncode, 17)
        self.assertNotIn("Build complete", result.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)

    def test_second_compiler_failure_is_not_global_success(self):
        result = self.run_build(PREFLIGHT_FAIL_CALL="2")
        self.assertEqual(result.returncode, 17)
        self.assertNotIn("Build complete", result.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
