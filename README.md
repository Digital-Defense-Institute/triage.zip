# triage.zip

[![Build Status](https://github.com/Digital-Defense-Institute/triage.zip/actions/workflows/ci.yml/badge.svg)](https://github.com/Digital-Defense-Institute/triage.zip/actions/workflows/ci.yml)

## Overview

**triage.zip** provides ready-to-run Velociraptor offline triage collectors for Windows x64, Linux x64, and macOS (Intel and Apple Silicon). Responders can collect evidence without building their own collector. 32-bit Windows is no longer supported.

## Automated Builds

The [CI workflow](.github/workflows/ci.yml) builds all four collectors on pushes to `main`, pull requests targeting `main`, and manual workflow dispatches. A scheduled run every Monday at 18:00 UTC checks the upstream Velociraptor version and the ETags of both `Windows.Triage.Targets` and `Linux.Triage.UAC`; scheduled builds are skipped when all three are unchanged.

The build downloads the upstream Velociraptor binaries and triage artifact bundles, validates artifact definitions (errors are fatal; upstream warnings are advisory), generates collectors from the platform configurations, and records version, artifact hashes/ETags, and build time in [data/velociraptor-version.json](data/velociraptor-version.json). Successful builds on `main` publish the four binaries to the `latest` GitHub release; pull request builds do not publish a release.

## Key Features

- **Offline collection:** Pre-packaged artifacts let responders collect evidence without a Velociraptor server connection.
- **Windows triage:** KAPE and SANS triage targets, basic collection, live system data, and Sysinternals Autoruns, including Volume Shadow Copies up to three days old.
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
