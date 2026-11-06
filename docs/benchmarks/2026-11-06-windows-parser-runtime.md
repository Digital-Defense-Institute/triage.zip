# Windows parser runtime benchmark — 2026-11-06

## Scope and reproducibility

The experiment uses the Windows collection validator from commit
`eebda5037e7c91f8408cc10470da404ab44e3a64` of the parallel
`ecapuano/collector-validator` worktree. That checkout was left unchanged.
The benchmark implementation is isolated on `ecapuano/parser-runtime-benchmark`.
No PR, release, or production configuration was published by this experiment.

Both variants use Velociraptor 0.77.3, the same Windows triage bundle, embedded
production configuration, Autoruns, three-day VSS policy, and concurrency of two.
The candidate appends SRUM, BAM, UserAssist, AppCompatCache, and Amcache in the
proposed production order. It deliberately excludes the proposed MOTW search and
all upstream acquisition/exclusion changes, isolating the five parsers.

Collectors execute without command-line overrides as Administrator on disposable
GitHub-hosted Windows 2022 runners. The original timeout, executable hash checks,
ZIP integrity/completion checks, meaningful Autoruns and triage-evidence checks,
and evidence cleanup are retained. Benchmark checks additionally verify the exact
requested artifact selection and count each parser's JSONL rows and bytes.
Only executable inputs/public metadata and sanitized numeric reports are retained;
raw evidence ZIPs, logs, datastores and private configuration are never uploaded.

Reported execution times measure collector process wall time. ZIP validation and
cleanup are timed separately. Builds, runner startup, downloads and test setup
are excluded. See [numeric reports](2026-11-06-windows-parser-runtime.json) for
exact input hashes, runner image, revisions, durations and counts.

## Experiments

- [Paired experiment](https://github.com/Digital-Defense-Institute/triage.zip/actions/runs/42249025144):
  three pairs on one runner, ordered baseline/parsers, parsers/baseline,
  baseline/parsers. Its initial baseline is reported separately because the
  first collection was substantially slower than all later collections.
- [Fresh-runner experiment](https://github.com/Digital-Defense-Institute/triage.zip/actions/runs/42251038897):
  three independent runners per variant, each executing one first collection.
  These comparisons include normal differences between hosted VMs; they are not
  paired measurements of the same machine.

## Results

All 12 collections passed validation. Every parser-enabled collection produced
nonempty results from all five parsers. Fresh-runner candidate collections each
returned 7,182 parser rows (SRUM 857, BAM 11, UserAssist 4, AppCompatCache 662,
Amcache 5,648), totaling approximately 2.74 MB of raw parser JSONL.

| Experiment | Baseline process time | With five parsers | Interpretation |
| --- | --- | --- | --- |
| Fresh runners, three per variant | 90.09–122.53 s; median 104.45 s | 87.82–123.32 s; median 110.79 s | Median difference +6.34 s (+6.1%); wide overlapping ranges prevent a precise overhead estimate. |
| Warm paired trials, pairs 2 and 3 | 50.33 s / 52.10 s | 52.57 s / 52.90 s | Paired increases +2.24 s (+4.4%) and +0.79 s (+1.5%). |
| Initial pair, baseline first | 105.53 s | 53.08 s | Strong first-collection effect; this is not evidence that parsers make collection faster. |

Fresh-runner means were 105.69 s baseline and 107.31 s candidate (+1.62 s,
+1.5%). The difference between mean and median comparisons illustrates the
uncertainty from this small, variable sample. The repeated same-runner trials
suggest modest incremental cost on this image; they do not establish the cost
of a first collection on a real workstation. Do not compare the faster warm
runs directly with the existing CI's first-collection step timings.

ZIP validation and cleanup added 7.89–7.97 s for fresh baseline trials and
9.17–11.87 s for fresh candidate trials. That CI-only work is excluded from the
process times above and does not run as part of an end user's collector.

## Limits

This small experiment measures a hosted Windows server image with relatively
small forensic databases, not a representative fleet of user workstations.
SRUM, Amcache, user activity, profile count, storage speed and other endpoint
conditions can change parser cost. A percentage measured here is not a bound or
SLA. MOTW traversal and future staging-file acquisition need separate measurement.
