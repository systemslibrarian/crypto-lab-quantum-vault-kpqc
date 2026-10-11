"""Offline controls for evidence completeness; fixtures are not crypto builds."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

WASM = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reproduction", WASM / "reproduce.py")
rep = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rep)
MANIFEST = json.loads((WASM / "reproduction.json").read_text())


class ReproductionControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qv-reproduction-control-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, kind="zip", names=("ref/a.c", "ref/b.h")):
        buffer = io.BytesIO()
        if kind == "zip":
            with zipfile.ZipFile(buffer, "w") as z:
                for name in names:
                    z.writestr(name, b"fixture source")
        else:
            with tarfile.open(fileobj=buffer, mode="w:gz") as z:
                for name in names:
                    t = tarfile.TarInfo(name); t.size = len(b"fixture source")
                    z.addfile(t, io.BytesIO(b"fixture source"))
        data = buffer.getvalue()
        blob = b"fixture source"
        spec = {"kind": kind, "sha256": rep.digest(data), "expectedFiles": 2,
                "files": [{"archivePath": name, "path": "captured/" + Path(name).name,
                           "sha256": rep.digest(blob), "gitBlob": hashlib.sha1(b"blob 14\0" + blob).hexdigest()} for name in names]}
        return data, spec

    def test_exact_tar_and_zip_inputs(self):
        for kind in ("tar", "zip"):
            with self.subTest(kind=kind):
                dest = self.root / kind; dest.mkdir()
                data, spec = self.archive(kind)
                rep.extract_archive(data, spec, dest)
                self.assertEqual((dest / "captured/a.c").read_bytes(), b"fixture source")
                self.assertEqual(len(list(dest.rglob("*.*"))), 2)

    def test_changed_archive_and_file_hashes_never_write_partial_inputs(self):
        data, spec = self.archive()
        for field in ("archive", "sha256", "gitBlob", "missing", "omitted"):
            bad = copy.deepcopy(spec)
            if field == "archive": bad["sha256"] = "0" * 64
            elif field == "missing": bad["files"][1]["archivePath"] = "absent.c"
            elif field == "omitted": bad["files"].pop()
            else: bad["files"][1][field] = "0" * (40 if field == "gitBlob" else 64)
            with self.subTest(field=field), self.assertRaises(ValueError):
                rep.extract_archive(data, bad, self.root)
            self.assertFalse(list(self.root.iterdir()))

    def test_traversal_and_duplicate_archive_members_are_refused(self):
        for kind in ("zip", "tar"):
            for names in (("../escaped.c", "ref/b.h"), ("ref/a.c", "ref/a.c")):
                data, spec = self.archive(kind, names)
                with self.subTest(kind=kind, names=names), self.assertRaises(ValueError):
                    rep.extract_archive(data, spec, self.root)
                self.assertFalse(list(self.root.iterdir()))

    def test_archive_symlink_is_refused(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as z:
            t = tarfile.TarInfo("ref/link"); t.type = tarfile.SYMTYPE; t.linkname = "/tmp/other"
            z.addfile(t)
        data, spec = self.archive("tar"); spec["sha256"] = rep.digest(buf.getvalue())
        with self.assertRaises(ValueError): rep.extract_archive(buf.getvalue(), spec, self.root)
        self.assertFalse(list(self.root.iterdir()))

    def test_existing_source_and_symlink_destinations_are_preserved(self):
        data, spec = self.archive()
        (self.root / "captured").mkdir(); target = self.root / "captured/b.h"
        target.write_bytes(b"user evidence")
        with self.assertRaises(ValueError): rep.extract_archive(data, spec, self.root)
        self.assertEqual(target.read_bytes(), b"user evidence")
        self.assertFalse((target.parent / "a.c").exists())
        elsewhere = self.root / "elsewhere"; elsewhere.mkdir()
        (self.root / "linked").symlink_to(elsewhere, target_is_directory=True)
        spec["files"][0]["path"] = "linked/a.c"
        with self.assertRaises(ValueError): rep.extract_archive(data, spec, self.root)
        self.assertFalse(list(elsewhere.iterdir()))

    def artifact_fixture(self):
        manifest = {"artifacts": []}; tracked = {}
        for role in sorted(rep.ROLES):
            blob = ("fixture " + role).encode(); path = "dist/" + role
            p = self.root / path; p.parent.mkdir(exist_ok=True); p.write_bytes(blob)
            manifest["artifacts"].append(dict(role=role, path=role, rebuiltPath=path, sha256=rep.digest(blob), bytes=len(blob)))
            tracked[role] = blob
        return manifest, tracked

    def test_all_four_byte_matches_and_changed_bytes(self):
        m, tracked = self.artifact_fixture()
        self.assertTrue(all(x["byteIdentical"] for x in rep.compare_artifacts(self.root, m, tracked)))
        (self.root / m["artifacts"][0]["rebuiltPath"]).write_bytes(b"changed compiler output")
        rows = rep.compare_artifacts(self.root, m, tracked)
        self.assertEqual(sum(not x["byteIdentical"] for x in rows), 1)

    def test_missing_empty_symlink_and_duplicate_artifacts_refuse_success(self):
        m, tracked = self.artifact_fixture(); entry = m["artifacts"][0]; p = self.root / entry["rebuiltPath"]
        original = p.read_bytes()
        for mode in ("missing", "empty", "symlink"):
            p.unlink()
            if mode == "empty": p.write_bytes(b"")
            if mode == "symlink": p.symlink_to(self.root / m["artifacts"][1]["rebuiltPath"])
            with self.subTest(mode=mode), self.assertRaises(ValueError): rep.compare_artifacts(self.root, m, tracked)
            if p.is_symlink() or p.exists(): p.unlink()
            p.write_bytes(original)
        m["artifacts"][0] = copy.deepcopy(m["artifacts"][1])
        with self.assertRaises(ValueError): rep.compare_artifacts(self.root, m, tracked)

    def test_changed_tracked_identity_is_not_reported_as_reproduction(self):
        m, tracked = self.artifact_fixture(); tracked[m["artifacts"][0]["path"]] = b"new source bytes"
        with self.assertRaises(ValueError): rep.compare_artifacts(self.root, m, tracked)

    def test_adapter_accepts_only_exact_recorded_loader(self):
        raw = b"generated();return moduleRtn}})();legacy tail\n"
        adapter = dict(originalSha256=rep.digest(raw), marker=";return moduleRtn}})();", tail="legacy tail\n", replacement="\nexport default fixture;\n")
        self.assertEqual(rep.adapt_loader(raw, adapter), b"generated();return moduleRtn}})();\nexport default fixture;\n")
        with self.assertRaises(ValueError): rep.adapt_loader(raw + b"changed", adapter)
        for field in ("tail", "marker"):
            bad = dict(adapter); bad[field] = "wrong"
            with self.assertRaises(ValueError): rep.adapt_loader(raw, bad)

    def stages(self):
        m = MANIFEST; result = []
        for cmd, output in ((["emcc", "--version"], "emcc " + m["compiler"]["version"] + " (" + m["compiler"]["commit"] + ")"), (["node", "--version"], m["compiler"]["nodeVersion"])):
            result.append(dict(command=cmd, exit=0, stdout=output, stderr=""))
        for name in ("smaug", "haetae"):
            cmd = ["emcc", *m["commands"][name]]
            stderr = "\n".join("emcc:DEBUG: compiling source file: " + p + "\nutils:DEBUG: successfully executed /emsdk/upstream/bin/clang -c " + p + " -o /tmp/fresh.o" for p in cmd if p.endswith(".c"))
            result.append(dict(command=cmd, exit=0, stdout="", stderr=stderr))
        result.append(dict(stage="input-integrity", sourceInputsUnchanged=True, compilerInputsUnchanged=True, compilerInputFiles=1913, compilerInputInventorySha256=m["compiler"]["systemLibraryInventorySha256"]))
        return result

    def test_full_fresh_compilation_report(self):
        rep.validate_manifest(MANIFEST)
        self.assertEqual(len(rep.validate_stages("\n".join(map(json.dumps, self.stages())), MANIFEST)), 5)

    def test_partial_failed_timeout_and_malformed_reports(self):
        for mode in ("partial", "failed", "bool", "timeout", "compiler", "node", "cache", "source", "inventory", "compilation", "unfinished"):
            rows = self.stages()
            if mode == "partial": rows.pop()
            elif mode == "failed": rows[2]["exit"] = 17
            elif mode == "bool": rows[2]["exit"] = False
            elif mode == "timeout": rows[2].update(exit=None, timedOut=True)
            elif mode == "compiler": rows[0]["stdout"] = "emcc 6.0.10 unknown"
            elif mode == "node": rows[1]["stdout"] = "v24.0.0"
            elif mode == "cache": rows[-1]["compilerInputsUnchanged"] = False
            elif mode == "source": rows[-1]["sourceInputsUnchanged"] = False
            elif mode == "inventory": rows[-1]["compilerInputFiles"] = 1
            elif mode == "compilation": rows[2]["stderr"] = ""
            elif mode == "unfinished": rows[2]["stderr"] = "\n".join(x for x in rows[2]["stderr"].splitlines() if "successfully executed" not in x)
            with self.subTest(mode=mode), self.assertRaises(ValueError): rep.validate_stages("\n".join(map(json.dumps, rows)), MANIFEST)
        with self.assertRaises(ValueError): rep.validate_stages("unreadable provider output", MANIFEST)

    def test_omitted_sources_wrappers_artifacts_and_unpinned_compiler(self):
        for mode in ("source", "wrapper", "artifact", "compiler", "original", "command"):
            m = copy.deepcopy(MANIFEST)
            if mode == "source": m["sources"]["smaug"]["files"].pop()
            elif mode == "wrapper": m["wrappers"].pop()
            elif mode == "artifact": m["artifacts"].pop()
            elif mode == "compiler": m["compiler"]["image"] = "emscripten/emsdk:latest"
            elif mode == "original": m["originalCompiler"] = "guessed"
            else: m["commands"]["smaug"].append("/work/uncaptured.c")
            with self.subTest(mode=mode), self.assertRaises(ValueError): rep.validate_manifest(m)

    def test_dirty_checkout_fails_before_any_compiler_or_dependency_command(self):
        repo = self.root / "repo"; (repo / "wasm").mkdir(parents=True)
        (repo / "wasm/reproduce.py").write_bytes((WASM / "reproduce.py").read_bytes())
        def git(*args):
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
        git("init"); git("add", "wasm/reproduce.py")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
        (repo / "user-work").write_bytes(b"preserve this")
        r = subprocess.run(["python3", "-B", str(repo / "wasm/reproduce.py"), "--smaug-archive", "absent", "--haetae-archive", "absent"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2); report = json.loads(r.stdout)
        self.assertIn("clean source checkout", report["error"])
        self.assertEqual([x["command"] for x in report["commands"]], [["git", "status", "--porcelain"]])
        self.assertEqual((repo / "user-work").read_bytes(), b"preserve this")


if __name__ == "__main__":
    unittest.main()
