# Issue 20 implementation and upstream follow-up

This work follows [issue 20](https://github.com/Digital-Defense-Institute/triage.zip/issues/20).
The changes described here are local and unpublished.

## Changes in triage.zip

- Enable the existing SRUM, BAM, UserAssist, AppCompatCache, and Amcache parsers.
- Preserve raw MOTW streams with the existing `Generic.Collectors.File` artifact.
  Its profile scope and 64 KiB enumeration-size filter are in `config/spec.yaml`.
- Test the MOTW configuration against temporary copies of the SHA256-pinned
  upstream NTFS image. CI runs the test after building and before release changes.

Prefetch already has parsed results through `_Live`. No custom artifact or
rewritten copy of the upstream triage artifact is packaged.

## Prepared upstream contributions

| Project | Change | Compatibility |
| --- | --- | --- |
| [Triage Artifact project](https://github.com/Velocidex/velociraptor-triage-collector) | Add `ExcludePathRegex` and `ExcludeDirectoryRegex` to `Windows.Triage.Targets` | Empty defaults preserve current acquisition. Path filtering covers static and adaptive upload routes; directory filtering prunes glob recursion. |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Add `MaxFileSize` and `ModifiedWithinDays` to the existing `Windows.Search.FileFinder` | Zero defaults disable the new filters. Negative limits stop before searching. Relative age intersects existing absolute timestamp filters. |

The exclusion contribution starts from upstream commit `78968d0`. The FileFinder
contribution starts from `6d45bf88b3a6253f78cc7af6ac6737fbf1b355a8`.
Both include upstream-format golden tests. The tests use disposable trees or
mocked filesystem/content operations, not a collection against a live host.

These parameters are not yet available in the published triage.zip inputs.
Do not add them to the production spec until the upstream changes are accepted,
published, and their exact downloaded definitions have been verified.

## Policy to apply after upstream publication

Exclude the OneDrive `AppData/Local/Microsoft/OneDrive/ListSync` cache subtree
while retaining `OneDrive/logs/ListSync` and other sync logs. Exclude only the
Windows Search `Windows.edb` and `Windows.db` databases and SQLite sidecars in
the machine and per-user Search database directories. Match whole path components
and support drive and VSS prefixes; do not exclude arbitrary similarly named files.

Keep broad staging collection opt-in. Configure FileFinder for user AppData
Local/Roaming, ProgramData, and Public, with uploads enabled, no extension filter,
a proposed seven-day modification window, and a proposed 50 MiB file-size filter.
Local already includes Temp and INetCache. Confirm coverage and cost on Windows
before choosing published defaults. Staging may preserve sensitive credentials.

FileFinder's size filter examines listed metadata; it does not guarantee a strict
byte cap if a file grows afterward, or impose an aggregate quota. Path exclusions
prevent uploads but adaptive targets may already have inspected or hashed the
referenced file. These controls are acquisition policy, not filesystem access
boundaries. Directory pruning alone does not suppress explicit adaptive references.

## Validation and remaining gates

The local parser/MOTW spec built all four collector formats, and both macOS
signatures verified. The 31-test regression suite passed with the real NTFS image
tests enabled; shell syntax, actionlint, and whitespace checks passed.

The exclusion artifact compiled and passed binary verification plus the complete
upstream golden suite. Its end-to-end fixture checks static and adaptive uploads
with exclusions enabled and disabled. The FileFinder artifact passed binary
verification, its existing golden test, and the new limits golden test, including
mocked call counts for filtering before content reads.

Independent Astra review found no actionable issues. The five parsers also passed
12 hosted Windows benchmark collections against the parallel CI validator;
see [runtime results and limits](benchmarks/2026-11-06-windows-parser-runtime.md).
That experiment isolates the parsers: full parser-plus-MOTW offline collection
and representative workstation qualification remain outstanding. Linux PR CI and
upstream maintainer review remain required. No release publication or upstream
submission has been performed.
