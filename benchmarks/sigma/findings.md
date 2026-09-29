# Initial measurements

Measured on September 29, 2026 using Velociraptor 0.77.2 and the pinned inputs
in `inputs.json`. These measurements are an initial estimate, not a production
latency guarantee.

## Added time in the actual standalone Windows collector

[Successful Windows run](https://github.com/Digital-Defense-Institute/triage.zip/actions/runs/36631318440)
on a disposable Windows Server 2022 runner with 4 vCPUs and 16 GiB RAM:

| Pair | Run order | Existing triage | Triage + medium Sigma | Added wall time |
|---|---|---:|---:|---:|
| 1 | Baseline, Sigma | 85.23 s | 110.91 s | 25.68 s |
| 2 | Sigma, baseline | 38.77 s | 111.02 s | 72.25 s |

The baseline uses the repository's complete Windows spec, including all four
high-level KAPE selections and Autoruns. The Sigma version adds medium and
above, stable/test, with the default noisy-rule exclusions. Both retain ZIP
compression level 5, artifact concurrency 2, and no CPU throttling. Both are
actual self-contained Windows executables. Build/download time is excluded.
For this benchmark both collectors have a 600-second completion limit.

Each Sigma run finished with 1,715 detections. All four collections finished
without error-level logs. They collected roughly 379 MiB of raw evidence each;
that includes other forensic files and is **not** the amount of EVTX scanned.
Result ZIPs were about 332 MiB baseline and 335 MiB with Sigma. Sampled parent
process peak RSS was 261–309 MiB baseline and 485–538 MiB with Sigma; child
Autoruns resource use is excluded.

For a host resembling this runner, the observed additional cost was about
**26–72 seconds**. The arithmetic midpoint is about 49 seconds, but two pairs
do not establish a reliable population mean or confidence interval. The first
baseline was much slower than the later baseline, consistent with cache/first
run effects. The more stable warmed comparison was approximately 39 seconds
baseline versus 111 seconds with Sigma, or 72 seconds added.

The runner's own live logs were scanned, not the public corpus below. A fresh
server VM has a different history and channel mix from an established endpoint.
Elapsed time can increase substantially with more events, different rules,
CPU throttling, slower storage, or concurrent acquisition. Total ZIP size is
not a useful denominator for predicting Sigma scan time.

## Controlled public corpus

Five standard-named channels: Security, System, Application, PowerShell
Operational and Sysmon Operational. Total: 24,720 events / 20.33 MiB. Three
runs per profile, default curated rule exclusions retained:

| Profile | Loaded rule instances | Linux median | Windows median | Windows range |
|---|---:|---:|---:|---:|
| High/critical, stable | 116 | 2.80 s | 4.52 s | 4.50–4.62 s |
| Medium and above, stable/test | 3,892 | 53.03 s | 78.84 s | 78.54–80.47 s |
| All levels/statuses | 4,850 | 69.75 s | 98.16 s | 96.86–102.54 s |

Each profile returned the same hit counts on Linux and Windows: 22, 665 and
2,681 respectively. These are native engine runs using `artifacts collect`,
including JSON result ZIP writing. Linux used a 3-vCPU x86_64 VM; Windows used
the hosted 4-vCPU / 16-GiB runner. Linux empty-log controls took 1.23–1.31 s,
showing that rule-loading/startup alone does not explain the medium profile's
runtime. The corpus is detection-heavy public attack data, and does not
establish typical per-event throughput for normal endpoint logs.

The [Windows engine run](https://github.com/Digital-Defense-Institute/triage.zip/actions/runs/36629447370)
completed all nine engine measurements, then failed at standalone spec
serialization. Those completed measurements are preserved separately from the
later successful standalone run.

## Packaging finding

Adding the entire curated rule artifact inline exceeds the standard binary's
embedded configuration capacity. The working collector instead bundles the
unchanged 865,390-byte compressed rule payload as a local resource and uses
VQL to extract/read it before invoking `Windows.Sigma.Base`. No rules are
downloaded at collection time and no external detection program runs.

The Linux standalone resource check returned the same 22 high/critical hits
as the inline artifact. Inspection of the built Windows EXE's appended archive
confirmed that the rules resource hash matched the original payload. The
successful Windows standalone run then verified this packaging in the full
triage workload.

Raw timing records are in `linux-measurements.json`,
`windows-engine-measurements.json` and `windows-triage-measurements.json`.
The GitHub run artifacts additionally retain collection logs and contexts.
