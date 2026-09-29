"""Measure native Sigma and paired standalone Windows triage collectors.

Downloads happen before measurement. Collection outputs are inspected, reduced
to logs/metadata, and deleted between runs to avoid filling the runner's disk.
"""

import argparse
import base64
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import statistics
import subprocess
import time
import urllib.parse
import urllib.request
import zipfile

import psutil
import yaml


REPO = Path(__file__).resolve().parents[1]
PROFILES = {
    "high": ("Critical and High", "Stable"),
    "medium": ("Critical, High, and Medium", "Stable and Test"),
    "all": ("All", "All Rules"),
}


def download(url, dest, expected=None):
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if expected and digest != expected:
        raise RuntimeError(f"SHA256 mismatch for {url}: {digest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return digest


def execute(cmd, stdout, timeout=660):
    start = time.perf_counter()
    peak = 0
    cpu = 0
    with stdout.open("wb") as stream:
        proc = subprocess.Popen([str(x) for x in cmd], stdout=stream, stderr=subprocess.STDOUT)
        tracked = psutil.Process(proc.pid)
        while proc.poll() is None:
            try:
                peak = max(peak, tracked.memory_info().rss)
                usage = tracked.cpu_times()
                cpu = max(cpu, usage.user + usage.system)
            except psutil.Error:
                pass
            if time.perf_counter() - start > timeout:
                proc.kill()
                proc.wait()
                raise RuntimeError(f"Benchmark exceeded {timeout}s: {cmd}")
            time.sleep(0.05)
    elapsed = time.perf_counter() - start
    if proc.returncode:
        raise RuntimeError(f"Exit {proc.returncode}: {cmd}; see {stdout}")
    return {"wall_seconds": elapsed, "sampled_peak_rss_bytes": peak, "sampled_cpu_seconds": cpu}


def inspect_collection(path, output):
    with zipfile.ZipFile(path) as archive:
        for name in ("log.json", "collection_context.json"):
            (output / name).write_bytes(archive.read(name))
        logs = [json.loads(line) for line in archive.read("log.json").splitlines()]
        context = json.loads(archive.read("collection_context.json"))
        messages = [row.get("message", "") for row in logs]
        errors = [row for row in logs if str(row.get("level", "")).upper() == "ERROR"]
        hits = sum(len(archive.read(name).splitlines()) for name in archive.namelist()
                   if name.startswith("results/Windows.Hayabusa.Rules") and name.endswith(".json"))
        result = {
            "zip_bytes": path.stat().st_size,
            "sigma_hits": hits,
            "sigma_loaded": [m.strip() for m in messages if "sigma: Loaded" in m],
            "sigma_completed": [m.strip() for m in messages if "sigma: Completed" in m],
            "errors": errors,
            "context": context,
        }
    path.unlink()
    # State 2 is FINISHED; never treat timed-out or failed scans as fast results.
    if context.get("state") not in (2, "FINISHED") or errors:
        raise RuntimeError(f"Collection incomplete or logged errors: {output}")
    if result["sigma_loaded"] and not result["sigma_completed"]:
        raise RuntimeError(f"Sigma did not finish: {output}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=("all", "engine", "triage"), default="all")
    args = parser.parse_args()
    work, output = args.work.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((REPO / "benchmarks/sigma/inputs.json").read_text())
    windows = platform.system() == "Windows"
    binary = work / ("velociraptor.exe" if windows else "velociraptor")
    suffix = "windows-amd64.exe" if windows else "linux-amd64"
    download(f"https://github.com/Velocidex/velociraptor/releases/download/v{manifest['version']}/velociraptor-v{manifest['version']}-{suffix}",
             binary, manifest["windows_binary_sha256"] if windows else None)
    if not windows:
        binary.chmod(0o755)
    pack = work / "sigma.zip"
    download("https://sigma.velocidex.com/artifacts/Velociraptor-Hayabusa-Rules.zip", pack, manifest["sigma_sha256"])
    definitions = work / "datastore/artifact_definitions/Benchmark"
    definitions.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pack) as archive:
        for name in ("Windows.Hayabusa.Rules.yaml", "Windows.Sigma.Base.yaml"):
            (definitions / name).write_bytes(archive.read(name))
    logs = work / "logs"
    for item in manifest["files"]:
        url = f"https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/{manifest['commit']}/{urllib.parse.quote(item['path'])}"
        download(url, logs / item["name"], item["sha256"])
    count_query = f"SELECT OSPath, count() AS Events FROM foreach(row={{SELECT OSPath FROM glob(globs='{logs.as_posix()}/*.evtx')}}, query={{SELECT OSPath FROM parse_evtx(filename=OSPath)}}) GROUP BY OSPath"
    counts = json.loads(subprocess.check_output([str(binary), "query", count_query]))
    host = {"platform": platform.platform(), "cpu_count": psutil.cpu_count(),
            "memory_bytes": psutil.virtual_memory().total, "python": platform.python_version(),
            "runner_image": os.environ.get("ImageVersion"), "inputs": manifest,
            "events_by_file": counts, "dataset_bytes": sum(p.stat().st_size for p in logs.glob("*.evtx"))}
    (output / "environment.json").write_text(json.dumps(host, indent=2))
    rows = []

    def record(label, cmd, zip_path, rep):
        dest = output / f"{label}-{rep}"
        dest.mkdir(exist_ok=True)
        measured = execute(cmd, dest / "stdout.log")
        measured.update(inspect_collection(zip_path, dest))
        if "baseline" not in label and (not measured["sigma_loaded"] or not measured["sigma_completed"]):
            raise RuntimeError(f"Missing Sigma execution: {dest}")
        measured.update(label=label, repetition=rep)
        rows.append(measured)
        (output / "measurements.json").write_text(json.dumps(rows, indent=2))
        print(f"{label} repetition {rep}: {measured['wall_seconds']:.2f}s, {measured['sigma_hits']} Sigma hits", flush=True)

    # Same native engine/corpus on Linux and Windows, three repetitions/profile.
    for label, (level, status) in (PROFILES.items() if args.phase != "triage" else []):
        for rep in range(3):
            dest = work / f"engine-{label}-{rep}.zip"
            record(f"engine-{label}", [binary, "--definitions", definitions, "artifacts", "collect",
                   "Windows.Hayabusa.Rules", "--args", f"ROOT={logs.as_posix()}",
                   "--args", f"RuleLevel={level}", "--args", f"RuleStatus={status}",
                   "--timeout", "600", "--output", dest], dest, rep)

    if windows and args.phase != "engine":
        # The standard executable reserves about 80 KiB for compressed config.
        # Bundle the unchanged compressed rules as a resource, rather than
        # embedding their ~1 MiB base64 string in the artifact definition.
        rules_path = definitions / "Windows.Hayabusa.Rules.yaml"
        rule_artifact = yaml.safe_load(rules_path.read_text())
        original_query = rule_artifact["sources"][0]["query"]
        rule_pattern = r'LET Rules <= gunzip\(string=base64decode\(string="([^"]+)"\)\)'
        match = re.search(rule_pattern, original_query)
        if not match:
            raise RuntimeError("Unexpected curated rule artifact format")
        payload = work / "sigma-rules.yaml.gz"
        payload.write_bytes(base64.b64decode(match.group(1)))
        rule_artifact["tools"] = [{"name": "HayabusaSigmaRules"}]
        rule_artifact["sources"][0]["query"] = re.sub(
            rule_pattern,
            'LET RuleFile <= SELECT * FROM Artifact.Generic.Utils.FetchBinary(\n'
            '    ToolName="HayabusaSigmaRules", IsExecutable=FALSE)\n'
            'LET Rules <= gunzip(string=read_file(filename=RuleFile[0].OSPath))',
            original_query, count=1)
        rules_path.write_text(json.dumps(rule_artifact, indent=2))
        host["bundled_rules_sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()
        # Build actual self-contained EXEs with the project's complete Windows spec.
        target_pack = work / "triage.zip"
        target_digest = download("https://triage.velocidex.com/artifacts/Windows.Triage.Targets.zip", target_pack)
        host["triage_targets_sha256"] = target_digest
        (output / "environment.json").write_text(json.dumps(host, indent=2))
        with zipfile.ZipFile(target_pack) as archive:
            for name in archive.namelist():
                if name.endswith(".yaml"):
                    (definitions / Path(name).name).write_bytes(archive.read(name))
        base = yaml.safe_load((REPO / "config/spec.yaml").read_text())
        collectors = {}
        for label in ("baseline", "medium"):
            if label == "medium":
                execute([binary, "--config", work / "datastore/server.config.yaml", "tools", "upload",
                         "--name", "HayabusaSigmaRules", "--filename", payload.name, payload],
                        output / "register-rules.log", timeout=120)
            spec = json.loads(json.dumps(base))
            spec.update(OptCollectorTemplate=f"benchmark-{label}.exe", OptPrompt=False, OptAdmin=True,
                        OptOutputDirectory=work.as_posix(), OptFilenameTemplate=f"benchmark-{label}",
                        OptTimeout=600)
            for option in ("OptVerbose", "OptBanner"):
                spec[option] = str(spec[option]).lower() in ("y", "yes", "true")
            if label == "medium":
                spec["Artifacts"]["Windows.Hayabusa.Rules"] = dict(zip(("RuleLevel", "RuleStatus"), PROFILES["medium"]))
            spec_path = work / f"spec-{label}.yaml"
            # JSON is valid YAML and keeps Y/N parameter values as strings.
            # PyYAML emits unquoted Y, which Velociraptor reads as boolean true
            # and rejects because artifact parameter values must be strings.
            spec_path.write_text(json.dumps(spec, indent=2))
            execute([binary, "collector", "--datastore", work / "datastore", spec_path], output / f"build-{label}.log", timeout=300)
            matches = list((work / "datastore").rglob(f"benchmark-{label}.exe"))
            if len(matches) != 1 or matches[0].stat().st_size < 10_000_000:
                raise RuntimeError(f"Expected a self-contained collector: {matches}")
            collectors[label] = matches[0]
        # Alternate order to reduce bias from cache warming and runner drift.
        for rep, order in enumerate((("baseline", "medium"), ("medium", "baseline"))):
            for label in order:
                record(f"triage-{label}", [collectors[label]], work / f"benchmark-{label}.zip", rep)

    summary = ["# Native Sigma benchmark", "", "| Workload | Median seconds | Range seconds |", "|---|---:|---:|"]
    for label in dict.fromkeys(row["label"] for row in rows):
        times = [row["wall_seconds"] for row in rows if row["label"] == label]
        summary.append(f"| {label} | {statistics.median(times):.2f} | {min(times):.2f}–{max(times):.2f} |")
    if windows and args.phase != "engine":
        deltas = [next(r["wall_seconds"] for r in rows if r["label"] == "triage-medium" and r["repetition"] == rep)
                  - next(r["wall_seconds"] for r in rows if r["label"] == "triage-baseline" and r["repetition"] == rep) for rep in range(2)]
        summary.extend(["", f"Paired full-triage added seconds: {deltas}"])
    summary.extend(["", "Corpus results use cached public attack samples; live triage uses the runner's own logs.",
                    "The Windows runner is a fresh server VM, not a typical user workstation.",
                    "Memory/CPU measurements are sampled for the collector process; child tool usage is excluded."])
    text = "\n".join(summary) + "\n"
    (output / "summary.md").write_text(text, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(text)


if __name__ == "__main__":
    main()
