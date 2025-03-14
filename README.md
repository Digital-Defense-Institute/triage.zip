# triage.zip

[![Build Status](https://github.com/Digital-Defense-Institute/triage.zip/actions/workflows/ci.yml/badge.svg)](https://github.com/Digital-Defense-Institute/triage.zip/actions/workflows/ci.yml)

## Overview

**triage.zip** provides an out-of-the-box Velociraptor triage collector for Windows, pre-configured for rapid and effective incident response. The project is intended for responders who need a reliable offline collector without the hassle of building from scratch.

## Repo Contents and Workflow

- **Automated Build and Deployment:**  
  Every commit to the `main` branch triggers a CI workflow (see [ci.yml](.github/workflows/ci.yml)) which:
  1. Fetches the latest Velociraptor Linux binary from its official release using a shell script.
  2. Generates an offline collector using the provided configuration ([spec.yaml](config/spec.yaml)).
  3. Deploys the collector as a GitHub release for easy download.

- **Configuration:**  
  The collector behavior is defined in [spec.yaml](config/spec.yaml), detailing operating system, artifacts, collection parameters, and output settings.

## Key Features

- **Automated Builds:**  
  CI workflows ensure that every update is built automatically and the latest version is available as a GitHub release.

- **Offline Collector:**  
  Designed to run without network dependencies, the executable facilitates rapid triage on target systems.

- **Pre-configured Response Options:**  
  Tailored for Windows environments, the spec includes options for valuable artifacts (e.g., Kape Files and Sysinternals Autoruns) to cover a wide range of triage scenarios.

## Usage Instructions

1. **Download and Run:**  
   Download the latest release of the collector [here](https://github.com/Digital-Defense-Institute/triage.zip/releases/download/latest/Velociraptor_Triage_Collector.exe) (permalink).  
   **Run the executable as an Administrator** on the target system.

2. **Triage Operation:**  
   Upon execution, the collector gathers artifacts and zips them using a naming template (`Triage-%FQDN%-%TIMESTAMP%.zip`), making it easy to correlate with the system it was collected from.  
   1. **NOTE:** we intentionally chose not to [encrypt](https://docs.velociraptor.app/docs/offline_triage/#encrypting-the-offline-collection) or password protect the collection ZIP to make subsequent automated processing easier. Be mindful of this and never leave a triage collection behind on a compromised system or any other unsecured location.

3. **Analyze Triage Collection:**  
   Upon completion, you can either import the collection into a Velociraptor server or use a tool such as [Plaso](https://github.com/log2timeline/plaso) or [OpenRelik](https://openrelik.org/) to process the evidence.

## Building Your Own Collector

If you wish to customize or build your own version, you can easily fork this repo:
  
- **Build Script:**  
  Modify and examine the [build_collector.sh](build_collector.sh) script to understand how the collector is generated.
  
- **Configuration:**  
  Adjust collection specifics in [spec.yaml](config/spec.yaml) to suit your needs.
  
- **Continuous Integration:**  
  The CI pipeline in [.github/workflows/ci.yml](.github/workflows/ci.yml) orchestrates the build and release process. Commit to `main` to trigger a new build.

## Further Information

- **Velociraptor Documentation:**  
  More detailed information about offline collectors can be found on the [Velociraptor docs](https://docs.velociraptor.app/docs/offline_triage/).

- **Processing Triage Acquisitions:**  
  For inspiration on how to process triage acquisitions generated by this tool, check out [OpenRelik](https://openrelik.org/).

- **Understanding KAPE Targets:**  
  The original KAPE Targets can be found [here](https://github.com/EricZimmerman/KapeFiles/tree/master/Targets).
  The version of the targets used by Velociraptor can be found [here](https://raw.githubusercontent.com/Velocidex/velociraptor/master/artifacts/definitions/Windows/KapeFiles/Targets.yaml).

- **License:**  
  This project is licensed under the [MIT License](LICENSE).

## Support

If you encounter issues or have suggestions for enhancement, feel free to open a GitHub issue on the repository.

Happy triaging!