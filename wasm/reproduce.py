"""Clean, bounded reproduction of the four shipped browser artifacts.

Inputs are immutable public archives and historical tracked wrappers. This
command neither installs lab dependencies nor replaces application artifacts.
The original publisher's compiler remains unknown, even after a byte match.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROLES = {"smaug-loader", "smaug-wasm", "haetae-loader", "haetae-wasm"}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def relative(name):
    p = PurePosixPath(name)
    if not name or str(p) == "." or p.is_absolute() or ".." in p.parts or "\\" in name:
        raise ValueError("Unsafe archive or output path")
    return p


def extract_archive(data, spec, destination):
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Source archive exceeds collection bound")
    if digest(data) != spec["sha256"]:
        raise ValueError("Archive digest differs from the pinned source")
    entries = {}
    selected = {x["archivePath"] for x in spec["files"]}
    if spec["kind"] == "tar":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                relative(member.name)
                if member.name in entries or (member.name in selected and not member.isfile()):
                    raise ValueError("Duplicate or unsupported archive entry")
                # Official archives also contain links in unrelated optimized
                # benchmark trees. Never extract or follow them. A selected
                # source must itself be a regular file, not a link target.
                if not (member.isfile() or member.isdir()):
                    entries[member.name] = None
                    continue
                if member.size > 100 * 1024 * 1024 or sum(len(x) for x in entries.values() if x) + member.size > 512 * 1024 * 1024:
                    raise ValueError("Unpacked archive exceeds collection bound")
                entries[member.name] = archive.extractfile(member).read() if member.isfile() else None
    elif spec["kind"] == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                relative(member.filename)
                if member.filename in entries or ((member.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError("Duplicate or symlink archive entry")
                if member.file_size > 100 * 1024 * 1024 or sum(len(x) for x in entries.values() if x) + member.file_size > 512 * 1024 * 1024:
                    raise ValueError("Unpacked archive exceeds collection bound")
                entries[member.filename] = None if member.is_dir() else archive.read(member)
    else:
        raise ValueError("Unsupported source archive")
    pending = []
    destinations = set()
    if not spec["files"] or len(spec["files"]) != spec["expectedFiles"]:
        raise ValueError("Missing source inventory")
    for entry in spec["files"]:
        path = destination / relative(entry["path"])
        parents = []
        for parent in path.parents:
            if parent == destination:
                break
            parents.append(parent)
        if not path.resolve().is_relative_to(destination.resolve()) or any(p.is_symlink() for p in parents):
            raise ValueError("Source destination follows a symlink")
        blob = entries.get(entry["archivePath"])
        if path in destinations or path.exists() or path.is_symlink():
            raise ValueError("Duplicate destination or existing source refused")
        if not isinstance(blob, bytes) or digest(blob) != entry["sha256"]:
            raise ValueError("Missing or changed pinned source file")
        if entry.get("gitBlob"):
            git_blob = hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest()
            if git_blob != entry["gitBlob"]:
                raise ValueError("Source differs from its immutable Git blob")
        destinations.add(path)
        pending.append((path, blob))
    # Validate the whole inventory before writing anything.
    for path, blob in pending:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)


def adapt_loader(raw, adapter):
    marker = adapter["marker"].encode()
    if digest(raw) != adapter["originalSha256"] or raw.count(marker) != 1:
        raise ValueError("Original generated loader identity is wrong")
    head, tail = raw.split(marker)
    if tail != adapter["tail"].encode():
        raise ValueError("Unrecognized module adapter input")
    return head + marker + adapter["replacement"].encode()


def compare_artifacts(scratch, manifest, tracked):
    if len(manifest["artifacts"]) != 4 or {x["role"] for x in manifest["artifacts"]} != ROLES:
        raise ValueError("All four distinct active artifacts are required")
    rows = []
    for entry in manifest["artifacts"]:
        p = scratch / relative(entry["rebuiltPath"])
        if not p.is_file() or p.is_symlink() or not p.stat().st_size:
            raise ValueError("Missing, empty or nonregular rebuilt artifact")
        original = tracked[entry["path"]]
        if digest(original) != entry["sha256"] or len(original) != entry["bytes"]:
            raise ValueError("Tracked artifact differs from the reviewed inventory")
        rebuilt = p.read_bytes()
        rows.append({"role": entry["role"], "path": entry["path"],
                     "rebuiltSha256": digest(rebuilt), "trackedSha256": digest(original),
                     "bytes": len(rebuilt), "byteIdentical": rebuilt == original})
    return rows


def validate_manifest(manifest):
    if manifest.get("schemaVersion") != 1 or "originalCompiler" not in manifest or manifest["originalCompiler"] is not None:
        raise ValueError("Invalid schema or invented original compiler")
    if set(manifest["sources"]) != {"smaug", "haetae"} or set(manifest["commands"]) != {"smaug", "haetae"}:
        raise ValueError("Both source and compiler recipes are required")
    artifacts = manifest["artifacts"]
    if len(artifacts) != 4 or {x["role"] for x in artifacts} != ROLES or len({x["path"] for x in artifacts}) != 4 or len({x["rebuiltPath"] for x in artifacts}) != 4:
        raise ValueError("Four distinct artifact identities are required")
    for x in artifacts:
        relative(x["path"]); relative(x["rebuiltPath"])
        if type(x["bytes"]) is not int or x["bytes"] <= 0 or not re.fullmatch(r"[a-f0-9]{64}", x["sha256"]):
            raise ValueError("Invalid artifact inventory")
    compiler = manifest["compiler"]
    if not re.fullmatch(r"emscripten/emsdk@sha256:[a-f0-9]{64}", compiler["image"]) or not re.fullmatch(r"[a-f0-9]{40}", compiler["commit"]):
        raise ValueError("Compiler must have immutable image and source identities")
    wrappers = manifest["wrappers"]
    if len(wrappers) != 4 or len({x["destination"] for x in wrappers}) != 4:
        raise ValueError("Both historical wrapper pairs are required")
    for name, spec in manifest["sources"].items():
        if not re.fullmatch(r"[a-f0-9]{40}", spec["pin"]) or not re.fullmatch(r"[a-f0-9]{64}", spec["sha256"]):
            raise ValueError("Source must have immutable identities")
        files = spec["files"]
        if type(spec["expectedFiles"]) is not int or not files or len(files) != spec["expectedFiles"] or len({x["path"] for x in files}) != len(files):
            raise ValueError("Incomplete source inventory")
        pair = [x for x in wrappers if x["component"] == name]
        if len(pair) != 2:
            raise ValueError("Missing historical wrapper")
        paths = {"/work/" + str(relative(x["path"])) for x in files}
        paths.update("/work/" + str(relative(x["destination"])) for x in pair)
        inputs = [x for x in manifest["commands"][name] if x.endswith(".c")]
        if not inputs or len(inputs) != manifest["expectedCompiledSources"][name] or len(set(inputs)) != len(inputs) or not set(inputs).issubset(paths):
            raise ValueError("Incomplete or unexplained compiler input")


# Runs inside the digest-pinned compiler image, as an unprivileged user. Every
# object is fresh; only compiler-image system libraries are reused unchanged.
CONTAINER = r'''
import pathlib,subprocess,json,time,hashlib,shutil,os,sys
root=pathlib.Path('/work'); spec=json.loads((root/'recipe.json').read_text())
def inventory(p): return {str(x.relative_to(p)):hashlib.sha256(x.read_bytes()).hexdigest() for x in p.rglob('*') if x.is_file()}
def run(argv,env=None):
 t=time.time()
 try:
  r=subprocess.run(argv,cwd=root,env=env,text=True,capture_output=True,timeout=180)
  row=dict(command=argv,exit=r.returncode,seconds=time.time()-t,stdout=r.stdout,stderr=r.stderr)
 except subprocess.TimeoutExpired as e:
  row=dict(command=argv,exit=None,timedOut=True,seconds=time.time()-t,stdout=(e.stdout or b'').decode(errors='replace') if isinstance(e.stdout,bytes) else e.stdout or '',stderr=(e.stderr or b'').decode(errors='replace') if isinstance(e.stderr,bytes) else e.stderr or '')
 print(json.dumps(row),flush=True)
 if row['exit']!=0: sys.exit(2 if row['exit'] is None else 1)
inputs=inventory(root); cache=pathlib.Path('/emsdk/upstream/emscripten/cache'); imageInputs=inventory(cache)
shutil.copytree(cache,root/'compiler-cache'); assert inventory(root/'compiler-cache')==imageInputs
run(['emcc','--version']); run(['node','--version'])
(root/'dist').mkdir()
env=dict(os.environ,EM_CACHE='/work/compiler-cache',EMCC_CORES='1',EMCC_DEBUG='1')
for name in ['smaug','haetae']: run(['emcc',*spec['commands'][name]],env)
print(json.dumps(dict(stage='input-integrity',sourceInputsUnchanged=all((root/p).is_file() and hashlib.sha256((root/p).read_bytes()).hexdigest()==h for p,h in inputs.items()),compilerInputFiles=len(imageInputs),compilerInputInventorySha256=hashlib.sha256(json.dumps(imageInputs,sort_keys=True).encode()).hexdigest(),compilerInputsUnchanged=inventory(cache)==imageInputs and inventory(root/'compiler-cache')==imageInputs)),flush=True)
'''


def validate_stages(stdout, manifest):
    stages = [json.loads(line) for line in stdout.splitlines()]
    if len(stages) != 5:
        raise ValueError("Partial or malformed build report")
    commands = [["emcc", "--version"], ["node", "--version"],
                ["emcc", *manifest["commands"]["smaug"]], ["emcc", *manifest["commands"]["haetae"]]]
    for stage, argv in zip(stages[:4], commands):
        if stage.get("command") != argv or type(stage.get("exit")) is not int or stage["exit"] != 0:
            raise ValueError("Wrong, missing or failed compiler stage")
    compiler = manifest["compiler"]
    if compiler["version"] not in stages[0].get("stdout", "") or compiler["commit"] not in stages[0]["stdout"]:
        raise ValueError("Wrong compiler identity")
    if stages[1].get("stdout", "").strip() != compiler["nodeVersion"]:
        raise ValueError("Wrong compiler runtime")
    for name, stage in zip(["smaug", "haetae"], stages[2:4]):
        paths = [a for a in stage["command"] if a.endswith(".c")]
        compiled = re.findall(r"^emcc:DEBUG: compiling source file: (.+)$", stage.get("stderr", ""), re.M)
        if len(paths) != manifest["expectedCompiledSources"][name] or compiled != paths:
            raise ValueError("Missing fresh C object compilation")
        for path in paths:
            if not any(line.startswith("utils:DEBUG: successfully executed ") and " -c " + path + " -o " in line for line in stage.get("stderr", "").splitlines()):
                raise ValueError("Fresh C compilation did not finish")
    integrity = stages[-1]
    if integrity.get("stage") != "input-integrity" or integrity.get("sourceInputsUnchanged") is not True or integrity.get("compilerInputsUnchanged") is not True:
        raise ValueError("Source or compiler inputs changed")
    if type(integrity.get("compilerInputFiles")) is not int or integrity["compilerInputFiles"] != compiler["systemLibraryFiles"] or integrity.get("compilerInputInventorySha256") != compiler["systemLibraryInventorySha256"]:
        raise ValueError("Incomplete compiler input inventory")
    return stages


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smaug-archive", type=Path, required=True)
    parser.add_argument("--haetae-archive", type=Path, required=True)
    parser.add_argument("--docker-context")
    parser.add_argument("--scratch-root", type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    report = {"state": "source-incomplete", "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "originalCompiler": None, "scope": "Four browser artifacts only; no constant-time proof", "commands": []}

    def run(argv, timeout=60):
        try:
            r = subprocess.run(argv, cwd=repo, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            report["commands"].append({"command": argv, "exit": None, "timedOut": True, "stdout": decoded(error.stdout), "stderr": decoded(error.stderr)})
            raise
        report["commands"].append({"command": argv, "exit": r.returncode, "stdout": r.stdout, "stderr": r.stderr})
        if r.returncode:
            if "run" in argv and r.returncode == 1:
                report["state"] = "source-build-failed"
            raise ValueError("Command failed: " + " ".join(argv))
        return r.stdout

    def git_blob(identity):
        argv = ["git", "show", identity]
        result = subprocess.run(argv, cwd=repo, capture_output=True, timeout=60)
        report["commands"].append({"command": argv, "exit": result.returncode,
                                   "stdoutBytes": len(result.stdout), "stdoutSha256": digest(result.stdout),
                                   "stderr": result.stderr.decode(errors="replace")})
        if result.returncode:
            raise ValueError("Immutable Git source unreadable: " + identity)
        return result.stdout

    try:
        if run(["git", "status", "--porcelain"]).strip():
            raise ValueError("Preserve local work: clean source checkout required")
        sha = run(["git", "rev-parse", "HEAD"]).strip()
        report["inspectedLabSha"] = sha
        origin = run(["git", "remote", "get-url", "origin"]).strip().removesuffix(".git")
        if origin not in {"https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc", "git@github.com:systemslibrarian/crypto-lab-quantum-vault-kpqc"}:
            raise ValueError("Unexpected repository identity")
        recipe_bytes = git_blob(sha + ":wasm/reproduction.json")
        manifest = json.loads(recipe_bytes)
        validate_manifest(manifest)
        docker = ["docker"] + (["--context", args.docker_context] if args.docker_context else [])
        image = json.loads(run([*docker, "image", "inspect", "--platform", "linux/amd64", manifest["compiler"]["image"]]))
        if len(image) != 1 or image[0].get("Architecture") != "amd64" or image[0].get("Os") != "linux" or image[0].get("Id") != manifest["compiler"]["platformImageId"]:
            raise ValueError("Wrong compiler platform image")
        scratch = Path(tempfile.mkdtemp(prefix="kpqc-source-rebuild-", dir=args.scratch_root.resolve()))
        report["scratch"] = str(scratch)
        for name, archive in [("smaug", args.smaug_archive), ("haetae", args.haetae_archive)]:
            extract_archive(archive.read_bytes(), manifest["sources"][name], scratch)
        for entry in manifest["wrappers"]:
            blob = git_blob(entry["pin"] + ":" + entry["path"])
            if digest(blob) != entry["sha256"] or hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest() != entry["gitBlob"]:
                raise ValueError("Historical wrapper identity changed")
            p = scratch / relative(entry["destination"])
            if p.exists():
                raise ValueError("Wrapper would overwrite captured source")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(blob)
        (scratch / "recipe.json").write_bytes(recipe_bytes)
        for p in scratch.rglob("*"):
            if p.is_file():
                os.utime(p, (946684800, 946684800))
        cid = scratch / "container-id"
        try:
            output = run([*docker, "run", "--rm", "--cidfile", str(cid), "--network=none", "--platform", "linux/amd64", "--user", str(os.getuid()) + ":" + str(os.getgid()), "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256", "--cpus=2", "--memory=2g", "--mount", "type=bind,src=" + str(scratch) + ",dst=/work", manifest["compiler"]["image"], "python3", "-u", "-c", CONTAINER], timeout=600)
        except subprocess.TimeoutExpired:
            if cid.is_file() and re.fullmatch(r"[a-f0-9]{64}", cid.read_text().strip()):
                try:
                    run([*docker, "stop", "--time", "5", cid.read_text().strip()], timeout=30)
                except (ValueError, subprocess.SubprocessError):
                    pass
            raise
        report["stages"] = validate_stages(output, manifest)
        (scratch / "dist/haetae.active-esm.js").write_bytes(adapt_loader((scratch / "dist/haetae.js").read_bytes(), manifest["haetaeModuleAdapter"]))
        tracked = {e["path"]: git_blob(sha + ":" + e["path"]) for e in manifest["artifacts"]}
        report["artifacts"] = compare_artifacts(scratch, manifest, tracked)
        if run(["git", "rev-parse", "HEAD"]).strip() != sha or run(["git", "status", "--porcelain"]).strip():
            raise ValueError("Repository source moved during reproduction")
        report["recipeSha256"] = digest(recipe_bytes)
        report["sources"] = {k: {field: spec[field] for field in ["repository", "pin", "sha256"]} for k, spec in manifest["sources"].items()}
        report["state"] = "source-reproduced" if all(x["byteIdentical"] for x in report["artifacts"]) else "source-mismatch"
        code = 0 if report["state"] == "source-reproduced" else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            report["timedOut"] = True
        code = 1 if report["state"] == "source-build-failed" else 2
    report["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
