# Collector changelog

Changes to triage.zip evidence coverage, platform support, and delivery. Dates track project changes; Velociraptor versions identify the upstream engine.

Read the [hosted changelog](https://triage.zip/changelog.html).

> Historical dates through October 6, 2026 are the UTC dates changes reached the main branch, reconstructed from the linked source changes. Collector publication may have followed later. Routine upstream engine and target-definition refreshes are not individually listed.

<!-- Generated from data/changelog.json by site/render_changelog.py. -->

## Not yet released

These proposals are under review and are not included in the current downloads.

### Parsed Windows evidence and download attribution

**Proposed** · Windows

- Add parsed SRUM, BAM, UserAssist, AppCompatCache, and Amcache results alongside the raw evidence already collected.
- Preserve raw Zone.Identifier streams under user profiles, with a 20-directory recursion limit and a 64 KiB per-stream size selection limit. The stream's parent file is not acquired by this pass.
- Hosted Windows tests found small warm-run parser overhead; first-collection timings varied substantially between runners. Workstation impact remains workload-dependent. Broader staging-file acquisition and ListSync/Search exclusions are separate follow-ups awaiting upstream support.

Sources: [Issue #20](https://github.com/Digital-Defense-Institute/triage.zip/issues/20)

### Check collection results before publication

**Proposed** · Windows, Linux

- Run the production Windows and Linux collectors on disposable CI runners and validate their resulting evidence archives before publishing a release.
- Require the published executables to match the tested binaries. Collection errors and incomplete evidence can block publication even when the collector exits successfully.

Sources: [PR #21 (open)](https://github.com/Digital-Defense-Institute/triage.zip/pull/21)

## 2026-10-06 — Windows x86 retired; builds support Velociraptor 0.77.3

**Breaking change** · Windows, Linux, macOS

- Remove the 32-bit Windows collector because Velociraptor 0.77.3 removed the Windows_x86 build target. Windows downloads now require x64; Linux x64 and both macOS architectures remain available.
- Support compressed upstream binaries and keep macOS binaries on the same engine version as the build host. Invalid downloads and fatal artifact errors stop the build; upstream advisory warnings remain nonfatal.
- Rebuild collectors when their inputs change. Site-only changes no longer replace the download, and release metadata is committed after publication succeeds.

Sources: [PR #19](https://github.com/Digital-Defense-Institute/triage.zip/pull/19)

## 2026-06-04 — macOS launch fix and more reliable downloads

**Fixed** · Windows, Linux, macOS

- Ad-hoc sign both macOS collectors after embedding their configuration, fixing launch failures caused by invalidated signatures on modern macOS. This is not Apple notarization; trusted browser downloads can still need their quarantine flag cleared.
- Tolerate harmless CDN timestamp differences while retaining checks for changed download content, reducing interrupted builds caused by inconsistent CDN metadata.

Sources: [PR #18: macOS signing](https://github.com/Digital-Defense-Institute/triage.zip/pull/18); [PR #16: CDN handling](https://github.com/Digital-Defense-Institute/triage.zip/pull/16)

## 2026-06-03 — Linux and macOS collectors added

**Added** · Windows, Linux, macOS

- Add Linux x64, macOS Intel, and macOS Apple Silicon downloads using Linux.Triage.UAC with all applicable targets selected.
- Embed the matching macOS executable so each macOS download is a standalone collector instead of a shell stub that requires another binary.
- Check every output's format and minimum size before publication to reject collector stubs.

Sources: [PR #14: platform support](https://github.com/Digital-Defense-Institute/triage.zip/pull/14); [PR #15: standalone binaries](https://github.com/Digital-Defense-Institute/triage.zip/pull/15)

## 2026-02-15 — 32-bit Windows support added

**Added** · Windows

- Add a Windows x86 collector alongside the existing x64 download, using the same collection targets. A failed x86 build blocks publication of a partial release.
- This historical download was later retired on October 6, 2026.

Sources: [PR #12](https://github.com/Digital-Defense-Institute/triage.zip/pull/12)

## 2026-01-07 — Target changes trigger fresh collector builds

**Changed** · Windows

- Detect updates to Windows.Triage.Targets and rebuild even when the Velociraptor engine version is unchanged. Evidence coverage can therefore evolve between builds that share an engine version.
- Display the last build time on the site and record the target bundle's hash alongside the engine version. Validate artifact definitions before building.

Sources: [PR #11](https://github.com/Digital-Defense-Institute/triage.zip/pull/11)

## 2025-11-24 — Collector configuration compatibility and engine visibility

**Fixed** · Windows

- Correct parameter types and ZIP output arguments for compatibility with Velociraptor 0.75.5. The configured target groups and three-day shadow-copy window stay the same.
- Record the Velociraptor version used for the collector and show it on the download page. Scheduled builds begin checking for engine-version changes.

Sources: [Configuration compatibility](https://github.com/Digital-Defense-Institute/triage.zip/commit/87ef627); [Version tracking](https://github.com/Digital-Defense-Institute/triage.zip/commit/8bf50c9)

## 2025-10-28 — Fix serialization of Windows target selection

**Fixed** · Windows

- Encode the selected KAPE Triage, Basic Collection, Live, and SANS Triage groups in the JSON-array format expected by the artifact. This corrects the configuration errors following the target-selection update.

Sources: [PR #7](https://github.com/Digital-Defense-Institute/triage.zip/pull/7); [PR #9](https://github.com/Digital-Defense-Institute/triage.zip/pull/9)

## 2025-10-20 — Update Windows collection groups and include Live

**Changed** · Windows

- Replace the legacy individual target switches, including ServerTriage, with HighLevelTargets selecting KAPE Triage, Basic Collection, Live, and SANS Triage.
- The new selection includes live system and adaptive evidence collection. Its configuration serialization was corrected on October 28.

Sources: [PR #6](https://github.com/Digital-Defense-Institute/triage.zip/pull/6)

## 2025-09-17 — Restore the three-day shadow-copy setting

**Fixed** · Windows

- Use the renamed VSS_MAX_AGE_DAYS parameter after migrating to Windows.Triage.Targets, restoring the intended acquisition of available Volume Shadow Copies up to three days old.

Sources: [PR #4](https://github.com/Digital-Defense-Institute/triage.zip/pull/4)

## 2025-09-15 — Move to the separately maintained triage artifact

**Changed** · Windows

- Switch from Windows.KapeFiles.Targets to Windows.Triage.Targets and download its definitions from the upstream Triage Artifact project during builds. The collection definitions can now change independently of the engine binary.

Sources: [PR #2](https://github.com/Digital-Defense-Institute/triage.zip/pull/2)

## 2025-07-16 — More resilient collector builds

**Fixed** · Windows

- Retry upstream API requests and binary downloads, clean up partial downloads, and reject empty or invalid release responses. Transient network failures are less likely to interrupt collector updates.

Sources: [Source change](https://github.com/Digital-Defense-Institute/triage.zip/commit/dd1fe32)

## 2025-03-17 — Weekly collector refreshes scheduled

**Changed** · Windows

- Schedule automatic builds on Mondays at 18:00 UTC so the latest collector can pick up upstream updates without waiting for a project code change.

Sources: [Source change](https://github.com/Digital-Defense-Institute/triage.zip/commit/b34e7cb)

## 2025-03-14 — Initial Windows triage collector

**Added** · Windows

- Introduce the Windows x64 offline collector with KAPE/SANS triage targets, Basic Collection, ServerTriage, and Sysinternals Autoruns, with a three-day shadow-copy acquisition setting.
- Run with administrative privileges and write a local Triage-<host>-<timestamp> ZIP containing JSONL results and acquired evidence. ZIP output is unencrypted.

Sources: [Initial commit](https://github.com/Digital-Defense-Institute/triage.zip/commit/fdd9457)
