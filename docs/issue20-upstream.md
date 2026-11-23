# Issue 20 implementation and upstream follow-up

This work follows [issue 20](https://github.com/Digital-Defense-Institute/triage.zip/issues/20).
The collector changes are proposed in [PR #23](https://github.com/Digital-Defense-Institute/triage.zip/pull/23) and have not been published in a collector release.

## Changes in triage.zip

- Enable the existing SRUM, BAM, UserAssist, AppCompatCache, and Amcache parsers.
- Preserve raw MOTW streams with the existing `Generic.Collectors.File` artifact.
  Its profile scope and 64 KiB enumeration-size filter are in `config/spec.yaml`.
- Test the MOTW configuration against temporary copies of the SHA256-pinned
  upstream NTFS image. CI runs the test after building and before release changes.

Prefetch already has parsed results through `_Live`. No custom artifact or
rewritten copy of the upstream triage artifact is packaged.

## Upstream capabilities and downstream policy

| Project | Change | Compatibility |
| --- | --- | --- |
| [Triage Artifact PR #41](https://github.com/Velocidex/velociraptor-triage-collector/pull/41) | Add `ExcludePathRegex` and `ExcludeDirectoryRegex` to `Windows.Triage.Targets` | Empty defaults preserve selection. Nonempty filters need separate coverage and cost qualification before downstream use. |
| [Velociraptor PR #5129](https://github.com/Velocidex/velociraptor/pull/5129) | Add `MaxFileSize` and `ModifiedWithinDays` to the existing `Windows.Search.FileFinder` | Zero defaults disable the new filters. Negative limits stop before searching. Relative age intersects existing absolute timestamp filters. |

Both upstream PRs merged on November 7, 2026. FileFinder's parameters are
available in Velociraptor 0.77.4, now used by the published collector. Availability
does not select or qualify a downstream acquisition policy: this PR enables no
Search/ListSync exclusions and no broad staging-file pass.

Retain Windows Search databases and OneDrive ListSync data by default. Search
indexes can preserve metadata and indexed content absent from current files;
ListSync can retain offline business-list content. Their absence from one case's
analysis does not establish that they are disposable. Any reduced collection
profile needs an explicit account of sacrificed evidence and measured cost.

Broad staging collection remains a separate opt-in proposal. The suggested
seven-day modification window and 50 MiB per-file selection threshold are not
qualified defaults. They may omit old, timestamp-preserved or larger payloads.
Such a pass also needs aggregate-volume and runtime evaluation and consistent
handling of related database files. Staging may preserve sensitive credentials.

FileFinder's size filter examines listed metadata; it does not guarantee a strict
byte cap if a file grows afterward, or impose an aggregate quota. Path exclusions
prevent uploads but adaptive targets may already have inspected or hashed the
referenced file. These controls are acquisition policy, not filesystem access
boundaries. Directory pruning alone does not suppress explicit adaptive references.

## Validation scope

The parser benchmark ran six baseline and six parser-enabled hosted collections;
all five parsers emitted rows in each of the six candidate collections. See
[runtime results and limits](benchmarks/2026-11-06-windows-parser-runtime.md).
That experiment isolates the parsers and does not measure MOTW traversal.
The full configuration has subsequently executed in Windows CI; the original
validator did not qualify its new evidence paths. The updated Windows check
requires each parser's meaningful results, reports SRUM sources separately, and
reconciles MOTW metadata, upload records, archive members, sizes and hashes.

Seeded packaged-collector checks exercise discovery, empty/binary streams, the
actual 64 KiB size boundary, depth 20/21 and an out-of-scope redirected-profile
location. The latter confirms an omission, not redirected-profile support. The
same executable runs against 1,000/10,000/10,000/1,000 synthetic files to report
full-collector scaling. These checks require a successful run at the reviewed
revision; preparing them locally is not evidence that Windows qualification
passed. Synthetic workload timings do not establish workstation runtime bounds.
