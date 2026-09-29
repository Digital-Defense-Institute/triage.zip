# Native Sigma collection benchmark

The `Sigma benchmark` workflow runs on a disposable GitHub-hosted Windows
Server 2022 VM. It measures two different workloads:

* **Native engine:** Velociraptor 0.77.2 evaluates a pinned public five-channel
  EVTX corpus, three times per rule profile. Downloads are outside the timer.
* **Full standalone triage:** build two self-contained Windows collectors from
  `config/spec.yaml`, one unchanged and one with `Windows.Hayabusa.Rules`
  (medium and above, stable and test). Run two pairs in opposite orders to
  reduce cache/order bias. Both scan the runner's live system; the native-engine
  corpus is a separate workload.

The profiles are high/critical + stable, medium and above + stable/test, and all
levels/statuses, retaining the curated artifact's default noisy-rule exclusions.

The workflow publishes `environment.json`, `measurements.json`, `summary.md`,
build/stdout logs, and each collection's `log.json` and
`collection_context.json`. Collection ZIPs are inspected and then removed to
conserve disk. Input hashes and the public corpus commit are recorded in
`inputs.json`; the live KAPE package's downloaded hash is recorded at runtime.
No release is published by this workflow.

Manual dispatch defaults to both phases. Branch pushes run the paired triage
phase only; select `engine` or `all` in manual dispatch to measure the corpus.
The CLI also accepts `--phase engine` or `--phase triage` for targeted reruns.

The full curated rules artifact exceeds the standard executable's embedded
configuration capacity. For standalone builds, the script moves its unchanged
compressed rule payload into a bundled `HayabusaSigmaRules` resource and replaces
the large inline constant with a local `Generic.Utils.FetchBinary` / `read_file`
call. The collector builder overrides `FetchBinary` to read resources from its
own executable. The Sigma base model and all matching rules remain unchanged;
there is no runtime rule download or external detection executable.

To run locally, install Python 3.12, `PyYAML==6.0.2` and `psutil==7.0.0`, then:

```powershell
python scripts/benchmark_sigma.py --work C:/Temp/sigma-benchmark --output benchmark-results
```

Use an elevated shell on Windows. On Linux the same script runs only the
native-engine benchmarks (use an appropriate Linux temporary path). The Windows
binary and rules/corpus are checksum checked before execution.

Collections have a 600-second timeout; incomplete collections, missing Sigma
execution, and error-level collection logs fail the benchmark rather than
counting as fast scans. Peak RSS and CPU time are sampled for the parent
collector process only, so external Autoruns resource use is excluded.

Interpretation matters: this is a fresh server VM with little operational
history, and the public attack corpus is intentionally detection-heavy.
Neither alone represents an established workstation. Compare paired triage
times to quantify the added wall time on this runner; use corpus engine times
to compare rule profiles. Extrapolating per-event throughput to larger real
logs is approximate because channel mix, rule matches, caching, and CPU/disk
contention change the cost. A 600-second cap also cannot establish timings for
workloads that need longer to finish.
