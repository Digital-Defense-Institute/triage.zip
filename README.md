# triage.zip

[![Build Status](https://github.com/Digital-Defense-Institute/triage.zip/actions/workflows/ci.yml/badge.svg)](https://github.com/Digital-Defense-Institute/triage.zip/actions/workflows/ci.yml)

## Overview

**triage.zip** provides ready-to-run Velociraptor offline triage collectors for Windows x64, Linux x64, and macOS (Intel and Apple Silicon). Responders can collect evidence without building their own collector. 32-bit Windows is no longer supported.

## Automated Builds

Follow dated changes to collector behavior in the [collector changelog](https://triage.zip/changelog.html)
or [CHANGELOG.md](CHANGELOG.md). Proposals under review are shown separately from
the historical changes.

The [CI workflow](.github/workflows/ci.yml) builds all four collectors on pushes to `main`, pull requests targeting `main`, and manual workflow dispatches. A scheduled run every Monday at 18:00 UTC checks the upstream Velociraptor version and the ETags of both `Windows.Triage.Targets` and `Linux.Triage.UAC`; scheduled builds are skipped when all three are unchanged.

The build downloads the upstream Velociraptor binaries and triage artifact bundles, validates artifact definitions (errors are fatal; upstream warnings are advisory), generates collectors from the platform configurations, and records version, artifact hashes/ETags, and build time in [data/velociraptor-version.json](data/velociraptor-version.json). Successful builds on `main` publish the four binaries to the `latest` GitHub release only when the upstream version or artifact ETags change, collector inputs change across the push, or a manual run is requested. Docs/site-only pushes still validate the build but do not republish unchanged inputs. Pull request builds never publish. Version metadata is committed only after release creation succeeds.

Before publication, CI runs the newly built Windows and Linux executables with their embedded production configurations on separate disposable runners: `windows-2022` as Administrator and `ubuntu-24.04` as root. Each collection has a 45-minute execution limit, and both must pass. Shared checks cover ZIP integrity, completed collection metadata, structured results and collection errors. Windows validation requires meaningful Autoruns output and verified triage file uploads. Linux validation requires the production `Linux.Triage.UAC` `_All` request, target rules, file metadata, verified uploads, and recognizable passwd or OS-release baseline content. The publish job downloads the same immutable build artifact and checks that both executable SHA256 hashes match the binaries tested on their respective platforms.

Collection evidence and raw process logs stay on the disposable runners and are deleted after validation. CI retains only redacted validation summaries for three days. These smoke tests cover the tested runner images; they do not establish compatibility with every Windows version or Linux distribution, exercise VSS when no shadow copies exist, validate macOS execution, or test importing the container into a server.

Artifact target selection can include directories. Validators report these as directory skips only when the ZIP member is explicitly a directory, its stored content is empty, and the read reports Windows `ERROR_INVALID_FUNCTION` (`Incorrect function`) or Linux `EISDIR` (`is a directory`), respectively. These entries never count as collected file evidence. Regular-file read failures, partial uploads, unknown errors, and mismatched sizes still fail validation.

For failed Linux sources, the guarded runner also records filesystem metadata on the same VM and binds these temporary facts to the collection SHA256. With matching recorded link sizes, the Linux validator can report links to directories, dangling `/etc` links, and configuration links under `/etc` or systemd unit directories pointing to `/dev/null`, devices, pipes or sockets as separate non-file skips. Error signatures, target types and source scope must match; copied bytes and existing regular-file read failures remain fatal. A target that disappeared from `/tmp` or `/var/tmp` can be reported separately only when its original glob metadata matches, the same VM confirms ENOENT, and upload failed before storing anything. Other missing files remain fatal.

These post-collection observations establish current state, not that a link never changed during collection or that every enumerated temporary file was acquired. Facts containing source paths are deleted with the evidence. Standalone archive validation never inspects the current host and remains strict without an explicit matching facts file. Cached UAC `Details.Stat` can describe a different source, so it is not used as proof for these exceptions; the smoke test does not qualify every artifact enrichment field.

Windows can likewise report vanished temporary targets only with explicit same-runner facts, the exact file/path-not-found error before any stored output, and matching original positive-size file metadata. Eligible sources are ordinary local paths under `C:\Windows\Temp`, a user's `AppData\Local\Temp`, or the hosted runner's `a\_temp`. Device/UNC paths, DOS device aliases, traversal, alternate data streams and missing files elsewhere are excluded. The helper probes only eligible temporary paths; its private facts are bound to the archive hash and deleted with the collection.

## Key Features

- **Offline collection:** Pre-packaged artifacts let responders collect evidence without a Velociraptor server connection.
- **Windows triage:** KAPE and SANS triage targets, basic collection, live system data, and Sysinternals Autoruns, including Volume Shadow Copies up to three days old. Parsed SRUM, BAM, UserAssist, AppCompatCache, and Amcache supplement the raw evidence.
- **Linux and macOS triage:** `Linux.Triage.UAC` collects the applicable Unix-like Artifacts Collector targets for each platform.
- **ZIP output:** Each collector writes an evidence archive for later analysis.

## Usage Instructions

1. **Download and Run:**
   Download the latest release of the collector (permalinks):
   - [Windows x64](https://github.com/Digital-Defense-Institute/triage.zip/releases/download/latest/Velociraptor_Triage_Collector.exe)
   - [Linux x64](https://github.com/Digital-Defense-Institute/triage.zip/releases/download/latest/Velociraptor_Triage_Collector_Linux)
   - [macOS Intel x64](https://github.com/Digital-Defense-Institute/triage.zip/releases/download/latest/Velociraptor_Triage_Collector_macOS)
   - [macOS Apple Silicon](https://github.com/Digital-Defense-Institute/triage.zip/releases/download/latest/Velociraptor_Triage_Collector_macOS_ARM)

   On Windows, **run the executable as Administrator** on the target system.

   On Linux, make the collector executable and run it with `sudo`:
   ```sh
   chmod +x Velociraptor_Triage_Collector_Linux
   sudo ./Velociraptor_Triage_Collector_Linux
   ```

   On macOS, use the binary matching the target's processor. For a trusted browser download, clear the quarantine flag, make it executable, and run it with `sudo` (replace the filename with `Velociraptor_Triage_Collector_macOS` for Intel):
   ```sh
   xattr -d com.apple.quarantine Velociraptor_Triage_Collector_macOS_ARM
   chmod +x Velociraptor_Triage_Collector_macOS_ARM
   sudo ./Velociraptor_Triage_Collector_macOS_ARM
   ```

   **Integrity metadata:** The hashes in `data/velociraptor-version.json` describe the downloaded triage artifact bundles, not the collector executables. Direct Velociraptor downloads are checked against the GitHub release asset size and SHA256 digest when supplied, then decompressed and checked for the expected executable type. Collector SHA256 hashes are not published in the release notes.

2. **Triage Operation:**  
   Upon execution, the collector gathers artifacts and zips them using a naming template (`Triage-%FQDN%-%TIMESTAMP%.zip`), making it easy to correlate with the system it was collected from.  
   1. **NOTE:** we intentionally chose not to [encrypt](https://docs.velociraptor.app/docs/offline_triage/#encrypting-the-offline-collection) or password protect the collection ZIP to make subsequent automated processing easier. Be mindful of this and never leave a triage collection behind on a compromised system or any other unsecured location.

3. **Analyze Triage Collection:**  
   Upon completion, you can either import the collection into a Velociraptor server or use a tool such as [Plaso](https://github.com/log2timeline/plaso) or [OpenRelik](https://openrelik.org/) to process the evidence.

## Building Your Own Collector

Fork this repository and adjust the configuration for the target platform:

| Collector | Configuration |
| --- | --- |
| Windows x64 | [config/spec.yaml](config/spec.yaml) |
| Linux x64 | [config/spec_linux.yaml](config/spec_linux.yaml) |
| macOS Intel x64 | [config/spec_macos.yaml](config/spec_macos.yaml) |
| macOS Apple Silicon | [config/spec_macos_arm.yaml](config/spec_macos_arm.yaml) |

[build_collector.sh](build_collector.sh) builds all four collectors on Linux and is the script used by CI. [build_collector_macos.sh](build_collector_macos.sh) provides a macOS build path. Both use shared helpers in [lib/collector_common.sh](lib/collector_common.sh).

CI builds PR and `main` changes even when the upstream version and artifact ETags are unchanged, so configuration and build-script changes are exercised. See [Automated Builds](#automated-builds) for the schedule and release behavior.

## Parsed Windows evidence

The Windows spec enables the built-in `Windows.Forensics.SRUM`,
`Windows.Forensics.Bam`, `Windows.Registry.UserAssist`,
`Windows.Registry.AppCompatCache`, and `Windows.Forensics.Amcache` artifacts.
Their JSONL results supplement the raw files acquired by `Windows.Triage.Targets`.
Parsed Prefetch is already provided by `_Live`, under
`Windows.Triage.Targets/PrefetchBinaries_Executables`; downstream tools must read
that result source rather than assuming a separate Prefetch artifact was run.

Parser output depends on the available evidence and Windows version. Inspect
collection logs and retain raw files for independent parsing when needed. SRUM
network byte counts do not establish the volume of stolen data, and BAM's
recorded last execution is not a process termination time.

## Mark-of-the-Web preservation

The Windows spec uses the built-in `Generic.Collectors.File` artifact to collect
raw `Zone.Identifier` alternate data streams under `C:\Users`, to a maximum
recursion depth of 20 directories below each profile. The NTFS accessor reads
the streams directly; the parent files are not uploaded or hashed by this pass.
Streams reported larger than 64 KiB during enumeration are skipped. This is a
per-stream selection limit, not an aggregate archive limit or a guarantee against
files changing during collection.

Look for stream paths ending in `:Zone.Identifier` in
`Generic.Collectors.File/All Matches Metadata` and
`Generic.Collectors.File/Uploads`. The uploaded bytes retain fields such as
`ZoneId`, `HostUrl`, and `ReferrerUrl` when present; this pass does not parse
them into separate columns. All zones are preserved. A missing stream does not
establish that a file was created locally, since download and extraction tools
do not always create or preserve MOTW.

CI tests this configuration against a disposable copy of upstream's NTFS fixture,
including exact bytes, metadata, size boundaries, unrelated streams, and paths
outside user profiles. This does not substitute for Windows endpoint validation.

The remaining staging-file and collection-exclusion work is tracked in
[the issue 20 upstream follow-up](docs/issue20-upstream.md). It requires upstream
features before those policies can be enabled in the published collector.

## Maintaining the changelog

Edit [data/changelog.json](data/changelog.json), then run
`python3 site/render_changelog.py` to regenerate both `CHANGELOG.md` and
`changelog.html`. The regression suite checks that these views match their source.
No additional build tool or Markdown package is needed on GitHub Pages.

Use an undated `Proposed` entry while a change is under review. After collector
publication is verified, give it the UTC publication date, update its kind and
source links, and regenerate both views. Explain changes to evidence coverage,
platform support, archive format, invocation, or release behavior, including
defaults and any action users need to take. Keep engine versions explicitly
identified as Velociraptor versions; triage.zip uses dates rather than a second
version number.

The retroactive history uses verified main-branch commit/merge dates where exact
publication dates could not be recovered. Routine upstream refreshes are not
individually reconstructed. Keep that distinction visible in both views.

## Further Information

- **Velociraptor Documentation:**  
  More detailed information about offline collectors can be found on the [Velociraptor docs](https://docs.velociraptor.app/docs/offline_triage/).

- **Processing Triage Acquisitions:**  
  For inspiration on how to process triage acquisitions generated by this tool, check out [OpenRelik](https://openrelik.org/).

- **Understanding KAPE Targets:**  
  The original KAPE Targets can be found [here](https://github.com/EricZimmerman/KapeFiles/tree/master/Targets).
  The project uses Windows.Triage.Targets artifact. The underlying KAPE targets can be found [here](https://raw.githubusercontent.com/Velocidex/velociraptor/master/artifacts/definitions/Windows/KapeFiles/Targets.yaml). The Windows.Triage.Targets artifact documentation is available at [triage.velocidex.com](https://triage.velocidex.com).

- **License:**  
  This project is licensed under the [MIT License](LICENSE).

## Support

If you encounter issues or have suggestions for enhancement, feel free to open a GitHub issue on the repository.

Happy triaging!
